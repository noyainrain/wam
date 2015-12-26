#!/usr/bin/env python3

"""wam!"""

import sys
import os
import signal
import json
import subprocess
import logging
import shlex
import argparse
from time import sleep
from collections.abc import Mapping
from subprocess import Popen, CalledProcessError, check_call, check_output
from shutil import copyfile, copytree, make_archive
from random import choice
from string import ascii_lowercase
from urllib.parse import urldefrag
from re import sub
from os import path, mkdir
from errno import ENOENT
from datetime import datetime

# TODO: Implement config parsing

_NGINX_CONFIG_PATH = '/etc/nginx/conf.d/wam.conf'

_NGINX_SERVER_TEMPLATE = """\
server {{
    listen {port};
    server_name {host};
{ssl_config}
    location / {{
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_pass http://localhost:{app_port};
    }}
}}
{ssl_redirect_config}
"""

_NGINX_SSL_TEMPLATE = """
    ssl_certificate {app_certificate};
    ssl_certificate_key {app_certificate_key};
"""

_NGINX_SSL_REDIRECT_TEMPLATE = """
server {{
    listen 80;
    server_name {host};
    return 301 https://{host};
}}
"""

class Registry(Mapping):
    def __init__(self):
        self._cache = {}

    def __getitem__(self, key):
        if key not in self._cache:
            with open(key) as f:
                meta = json.load(f)
                self._cache[key] = meta
        return self._cache[key]

    def __iter__(self):
        raise NotImplementedError()

    def __len__(self):
        raise NotImplementedError()

class WebAppManager:
    """
    Attributes:

    * `config`
    * `apps`
    * `server`
    * `cron`
    * `data_path`
    * `store_path`
    * `ext_path`

    .. attribute: port_range

       See ``port_range`` configuration.

    .. attribute: meta

       Software meta data :class:`Registry`.

    .. attribute: nginx

       :obj:`Nginx` server.
    """

    def __init__(self, config={}, auto_backup=True, **kwargs):
        self.config = {
            'data_path': 'data',
            # TODO: dont even start with hardcoding again. implement config
            # parsing
            'email': 'sven.jms+app.wam@gmail.com', #None
            'port_range': '8000-8079'
        }
        self.config.update(config)

        self.data_path = self.config['data_path']
        self.store_path = os.path.join(self.data_path, 'wam.json')
        self.backup_path = os.path.join(self.data_path, 'backups')
        self.ssl_path = os.path.join(self.data_path, 'ssl')
        self.ext_path = os.path.join(self.data_path, 'ext')
        self.auto_backup = auto_backup

        try:
            self.port_range = tuple(int(p) for p in self.config['port_range'].split('-'))
        except ValueError:
            raise ValueError('port_range')
        if not (len(self.port_range) == 2 and self.port_range[0] < self.port_range[1]):
            raise ValueError('port_range')

        self.meta = Registry()
        self.apps = {}
        args = {}
        if 'nginx_config_path' in kwargs:
            args['config_path'] = kwargs['nginx_config_path']
        self.nginx = Nginx(self, **args)
        self.cron = Cron(self)
        self.logger = logging.getLogger('wam')
        self._logger = self.logger

        self._package_engines = {'apt': Apt(), 'bundler': Bundler(), 'bower': Bower()}
        def get_redis_databases():
            #for app in self.apps:
            #    for database in app.databases:
            #        if database.engine == 'redis':
            #            return database
            return {d for a in self.apps.values() for d in a.databases if d.engine == 'redis'}
        self._database_engines = {
            'postgresql': PostgreSQL(),
            'redis': Redis(get_redis_databases)
        }

    def start(self):
        for d in [self.data_path, self.backup_path, self.ssl_path, self.ext_path]:
            try:
                os.mkdir(d)
            except FileExistsError:
                pass
        self.apps = self.load()['apps']

    def load(self):
        # XXX
        data = {'apps': {}}
        try:
            with open(self.store_path) as f:
                data = json.load(f, object_hook=self._decode)
            #self._logger.debug('Loaded %s', data)
        except FileNotFoundError:
            pass
        return data

        #apps = data['apps']
        #for app in apps.values():
        #    app['jobs'] = dict(
        #        (j['id'], Job(manager=self, **j)) for j in app['jobs'])
        #return {i: App(wam=self, **a) for i, a in apps.items()}

    def _encode(self, object):
        if isinstance(object, set):
            x = {'items': list(object)}
        else:
            try:
                x = object.json()
            except AttributeError:
                # TODO bug report AttributeError in encode
                raise TypeError()
        x['__type__'] = type(object).__name__
        return x

    def _decode(self, json):
        type = json.pop('__type__', None)
        if type:
            if type == 'set':
                return set(json['items'])
            else:
                types = {'App': App, 'Database': Database, 'Job': Job}
                return types[type](wam=self, **json)
        else:
            return json

    def add(self, software_id, url, branch=None, rollback=True):
        """
        """

        if not os.path.isfile(software_id):
            raise ValueError('software_id')

        self._logger.info('Adding %s', url)

        used_ports = {a.port for a in self.apps.values()}
        free_ports = set(range(self.port_range[0], self.port_range[1] + 1)) - used_ports
        port = sorted(free_ports)[0]

        secret = randstr()
        app = App(url, software_id, port, secret, {}, {}, set(), extensions=[], wam=self,
                  branch=branch)
        self.apps[app.id] = app
        mkdir(app.path)
        self.nginx.configure()
        self.store()

        try:
            #app.setup()
            app.update(fresh=True)
            return app
        except ScriptError:
            self.logger.error('app setup failed')
            if rollback:
                self.logger.info('Rolling back %s', app.id)
                self.remove(app)
            # TODO: raise reasonable error
            raise

    def remove(self, app):
        # TODO: include app.backup()
        self._logger.info('Removing %s', app.id)
        try:
            app.cleanup()
        except ScriptError:
            self.logger.error('app cleanup failed, continuing removal')
        os.rename(app.path, '/tmp/wam.backup.{}'.format(randstr()))
        del self.apps[app.id]
        self.nginx.configure()
        self.store()

    def json(self):
        #return {'apps': {i: a.json() for i, a in self.apps.items()}}
        return {'apps': self.apps}

    def store(self):
        j = json.dumps(self.json(), default=self._encode, indent=4)
        #self._logger.debug('Storing %s', j)
        with open(self.store_path, 'w') as f:
            #json.dump(j, f)
            f.write(j)

class App:
    """Web applicaton.

    Attributes:

    * `id`
    * `software_id`
    * `branch`
    * `software_meta`: Description of the software as given in software's
      `webapp.json`.
    * `secret`
    * `installed_packages`
    * `databases`
    * `data_dirs`
    * `jobs`
    * `manager`

    .. attribute:: port

       Port the web server uses to communicate with the application server.
    """

    def __init__(self, id, software_id, port, secret, jobs, installed_packages, databases,
                 extensions, wam, data_dirs=set(), pids=set(), **args):
        self.id = id
        self.software_id = software_id
        self.branch = args['branch']
        self.port = port
        self.secret = secret
        self.installed_packages = installed_packages
        self.databases = databases
        self.extensions = extensions
        self.data_dirs = data_dirs
        self.jobs = jobs
        self.pids = pids
        self.job_user = 'www-data'
        self.wam = wam
        self.manager = wam

        self._logger = logging.getLogger('wam')
        self._software_meta = None
        self._cookies = CookieJar()

    @property
    def sid(self):
        return sub('[\./]', '_', self.id)

    @property
    def software_meta(self):
        if not self._software_meta:
            with open(self.software_id) as f:
                self._software_meta = json.load(f)
            self._software_meta['jobs'] = list(
                {'cmd': j} if isinstance(j, str) else j for j in
                self._software_meta.get('jobs', []))
            self._software_meta.setdefault('extension_path', 'ext')
        return self._software_meta
    meta=software_meta

    @property
    def path(self):
        return os.path.join(self.wam.config['data_path'], self.sid)

    @property
    def url(self):
        return 'http://{}/'.format(self.id)

    @property
    def dbuser(self):
        # TODO random user id
        # mysql user name max length 16
        return self.sid[:16]

    @property
    def is_running(self):
        return bool(self.pids)

    # FIXME: use app.sid for cert paths
    @property
    def certificate_path(self):
        return os.path.join(self.wam.config['data_path'], 'ssl', self.id + '.crt')

    @property
    def certificate_key_path(self):
        return os.path.join(self.wam.config['data_path'], 'ssl', self.id + '.key')

    @property
    def encrypted(self):
        return os.path.isfile(self.certificate_path)

    @property
    def data(self):
        return {
            'port': self.port,
            'path': self.path
        }

    def update(self, fresh=False):
        self._logger.info('Updating %s', self.id)

        # TODO: fresh not via paramater, but as state/property
        if not fresh:
            running = self.is_running
            if running:
                self.stop()
            if self.manager.auto_backup:
                self.backup()

        self._update_code()
        self._update_packages()
        self._update_databases()
        self._update_data_dirs()
        self._call('update')

        self.manager.store()
        if fresh or running:
            self.start()

    def _update_code(self):
        self._logger.info('Updating code')

        try:
            url = self.meta['download']
        except KeyError:
            return

        self._update_repo(self.path, url, branch=self.branch)
        for extension in self.extensions:
            # TODO: remove extension again if needed
            path = os.path.join(self.path, self.meta['extension_path'], extension.replace('/', '-'))
            self._update_repo(path, self.manager.meta[extension]['download'])

    def _update_repo(self, repo, url, branch=None):
        try:
            git_root = (check_output(['git', '-C', repo, 'rev-parse', '--show-toplevel'])
                        .decode().strip())
        except CalledProcessError:
            git_root = None
        # git_root is always absolute, repo may or may not be
        repo_exists = (git_root == os.path.abspath(repo))

        if not repo_exists:
            self._logger.info('Cloning from %s%s', url, '#' + branch if branch else '')
            #url, branch = urldefrag(url)
            cmd = ['git', 'clone', '-q', '--single-branch', url, repo]
            if branch:
                cmd[4:4] = ['-b', branch]
            check_call(cmd)
        else:
            self._logger.info('Pulling from %s', url)
            # Discard all local changes to prevent merge problems
            check_call(['git', '-C', repo, 'reset', '--hard'])
            check_call(['git', '-C', repo, 'fetch'])
            check_call(['git', '-C', repo, 'merge'])

    def _update_packages(self):
        # TODO: Skip already installed packages
        # TODO: Remove packages
        packages_meta = self.meta.get('packages', {})
        for engine, packages in packages_meta.items():
            self.install(engine, set(packages))

    def _update_databases(self):
        target_databases = set(self.meta.get('databases', []))
        current_databases = {d.engine for d in self.databases}
        new = target_databases - current_databases
        old = current_databases - target_databases
        for engine in old:
            # TODO: Delete databases
            pass
        for engine in new:
            self.create_database(engine)

    def _update_data_dirs(self, cleanup=False):
        data_dirs = set(self.software_meta.get('data_dirs', []) if not cleanup else [])
        new = data_dirs - self.data_dirs
        old = self.data_dirs - data_dirs
        for data_dir in old:
            self._logger.info('Deleting data directory %s', data_dir)
            #chown(os.path.join(self.path, path), os.geteuid(), os.getegid())
            # It is safer to remove the tree directly as the job user, which is less privileged
            #check_call(['sudo', '-u', self.job_user, 'rm', '-r', os.path.join(self.path, path)])

            path = os.path.join(self.path, data_dir)
            check_call(['sudo', 'chown', '-R', '{}:{}'.format(os.geteuid(), os.getegid()), path])
            os.rename(path, '/tmp/wam-{}'.format(randstr()))
        for path in new:
            self._logger.info('Creating data directory %s', path)
            path = os.path.join(self.path, path)
            try:
                mkdir(path)
            except FileExistsError:
                # That's okay
                pass
            check_call(['sudo', 'chown', '-R',
                        '{}:{}'.format(self.job_user, self.job_user), path])
            #from shutil import chown
            #chown(path, self.job_user, self.job_user)
        self.data_dirs = data_dirs

    def cleanup(self):
        self.stop()
        if self.manager.auto_backup:
            self.backup()

        self._logger.info('Cleaning up %s', self.id)
        try:
            self._call('cleanup')
        finally:
            self.delete_all_databases()
            self.uninstall_all()

    def backup(self):
        """See :ref:`wam app-backup`."""
        running = self.is_running
        if running:
            self.stop()

        self._logger.info('Backing up %s', self.id)
        backup = os.path.join(self.manager.backup_path,
                              'backup-{}-{}'.format(self.sid, datetime.utcnow().isoformat()))
        os.mkdir(backup)
        self._backup_databases(backup)
        self._backup_data_dirs(backup)
        self._call('backup')

        if running:
            self.start()
        return backup

    def _backup_databases(self, backup):
        for database in self.databases:
            self._logger.info('Backing up %s database', database.engine)
            self.manager._database_engines[database.engine].dump(database, backup)

    def _backup_data_dirs(self, backup):
        for data_dir in self.data_dirs:
            self._logger.info('Backing up data directory %s', data_dir)
            copytree(os.path.join(self.path, data_dir), os.path.join(backup, data_dir))

    def restore(self, backup):
        """See :ref:`wam app-restore`.

        If the backup is not a backup of (the current version) of the app, a :exc:`ValueError`
        (``backup_invalid``) is raised.
        """
        # Validate backup
        for database in self.databases:
            engine = self.manager._database_engines[database.engine]
            if not os.path.isfile(os.path.join(backup, engine.dump_name)):
                raise ValueError('backup_invalid')
        for data_dir in self.data_dirs:
            if not os.path.isdir(os.path.join(backup, data_dir)):
                raise ValueError('backup_invalid')

        running = self.is_running
        if running:
            self.stop()
        if self.manager.auto_backup:
            self.backup()

        self._logger.info('Restoring %s', self.id)
        self._restore_databases(backup)
        self._restore_data_dirs(backup)

        if running:
            self.start()

    def _restore_databases(self, backup):
        for database in self.databases:
            self._logger.info('Restoring %s database', database.engine)
            engine = self.manager._database_engines[database.engine]
            engine.restore(database, os.path.join(backup, engine.dump_name))

    def _restore_data_dirs(self, backup):
        self._update_data_dirs(cleanup=True)
        for data_dir in self.meta.get('data_dirs', []):
            self._logger.info('Restoring data directory %s', data_dir)
            copytree(os.path.join(backup, data_dir), os.path.join(self.path, data_dir))
        self._update_data_dirs()
#        for data_dir in self.data_dirs:
#            root = os.path.join(backup, data_dir)
#            for path, dirs, files in os.walk(root):
#                path = relpath(root, path)
#                for dir in dirs:
#                    try:
#                        os.mkdir(os.path.join(backup, path, dir))
#                    except FileExistsError:
#                        # That's okay
#                        pass
#                for file in files:
#                    copy2(os.path.join(self.path, path, file), os.path.join(backup, path, file))

    def start(self):
        if not self.meta['jobs']:
            return

        if self.pids:
            # this is a restart, good idea here?
            self.stop()

        self._logger.info('Starting %s', self.id)
        for job in self.meta['jobs']:
            cmd = job['cmd'].format(**self.data)
            cwd = job.get('cwd')
            if cwd:
                cwd = cwd.format(**self.data)
            self.start_job(cmd, cwd=cwd)

        self._call('start')
        sleep(2)

    def stop(self):
        if not self.pids:
            return

        self._logger.info('Stopping %s', self.id)
        try:
            self._call('stop')
        finally:
            self.stop_all_jobs()
        sleep(2)

    def start_job(self, cmd, env={}, cwd=None):
        args = shlex.split(cmd)
        args = ['sudo', '-u', self.job_user, 'nohup'] + args
        envi = dict(os.environ)
        envi.update(env)
        #print(args)
        #print(envi)
        # TODO: How to fix buffering?
        with open(os.path.join(self.path, 'log.txt'), 'a') as f:
            f.write('\n{}\n{}\n'.format(datetime.utcnow().isoformat(), ' '.join(args)))
            p = Popen(args, stdin=subprocess.DEVNULL, stdout=f, stderr=f, cwd=cwd, env=envi)
        self.pids.add(p.pid)
        self.manager.store()
        return p.pid

    def stop_job(self, job):
        #try:
        # dammit, sudo -u www-data geht nicht, weil sudo process von start_job
        # als root laeuft.....
        # ignore errors, assume process is already dead
        subprocess.call(['sudo', 'kill', str(job)])
        #    os.kill(job, signal.SIGTERM)
        #except ProcessLookupError:
        #    # it is already dead
        #    pass
        self.pids.remove(job)
        self.manager.store()

    def stop_all_jobs(self):
        for pid in set(self.pids):
            self.stop_job(pid)

    def schedule(self, cmd, time):
        job = Job(randstr(), cmd, time, self.wam)
        self.jobs[job.id] = job
        self.wam.cron.configure()
        self.manager.store()
        return job

    def unschedule(self, job):
        del self.jobs[job.id]
        self.wam.cron.configure()
        self.manager.store()

    def encrypt(self):
        """See :ref:`wam app-encrypt`."""
        """
export DOMAIN=foo.inrain.org
# generate private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $DOMAIN.key
# Generate certificate signing request. Details are ignored by StartSSL, so set
# an empty subject string.
openssl req -new -key $DOMAIN.key -subj / -out $DOMAIN.csr
# do: upload csr to and download crt from StartSSL
# show certificate details
openssl x509 -in $DOMAIN.crt -text
        """
        if self.encrypted:
            raise ValueError('app_already_encrypted')
        # TODO is thre a python way to do this?
        call('openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out {}'.format(
            self.certificate_key_path))
        csr_path = os.path.join(self.wam.config['data_path'], 'ssl', self.id + '.csr')
        call('openssl req -new -key {} -subj / -out {}'.format(
            self.certificate_key_path, csr_path))
        return csr_path

    def encrypt2(self, certificate):
        """See :ref:`wam app-encrypt2`."""
        copyfile(certificate, self.certificate_path)
        # TODO: validate certificate somehow
        call('openssl x509 -in {} -text'.format(self.certificate_path))
        self.manager.nginx.configure()

    def add_extension(self, extension):
        if extension in self.extensions:
            raise ValueError('extension') #TODO
        if not os.path.isfile(extension):
            raise ValueError('extension_not_found') #TODO
        self.extensions.append(extension)
        self.update()

    def remove_extension(self, extension):
        try:
            self.extensions.remove(extension)
        except ValueError:
            raise ValueError('extension') # TODO
        self.update()

    def _call(self, op):
        try:
            script = os.path.join(os.path.dirname(self.software_id), self.meta['hooks'])
        except KeyError:
            return

        env = dict(os.environ)
        env.update({
            'WAM_SCRIPT': __file__,
            'PYTHONPATH': os.path.dirname(__file__) or '.',
            'WAM_DATA_PATH': self.manager.data_path,
            'WAM_APP_ID': self.id
        })
        if self._logger.getEffectiveLevel() == logging.DEBUG:
            env['WAM_VERBOSE'] = '1'

        try:
            self._logger.debug('Calling %s %s', script, op)
            check_call([script, op], env=env)
            #call('./{} {}'.format(self.software_id, op))

        except (FileNotFoundError, CalledProcessError):
            raise ScriptError()

        finally:
            self._logger.debug('%s %s exited', self.software_id, op)

            # Reload all data that may be modified by app script
            data = self.manager.load()
            copy = data['apps'][self.id]
            self.installed_packages = copy.installed_packages
            self.databases = copy.databases
            for id in self.jobs.keys() - copy.jobs.keys():
                self._logger.debug('Cron job %s removed by app script', id)
                del self.jobs[id]
            for id in copy.jobs.keys() - self.jobs.keys():
                self._logger.debug('Cron job %s added by app script', id)
                self.jobs[id] = copy.jobs[id]

    def install(self, engine, packages=set()):
        """Install a set of `packages` with `engine`."""
        self._logger.info('Installing %s', packages)
        # TODO: validate packages somehow? (otherwise may be command lines, bad...)
        if engine not in self.manager._package_engines:
            raise ValueError('engine_unknown')
        self.manager._package_engines[engine].install(packages, self.path)
        if engine not in self.installed_packages:
            self.installed_packages[engine] = set()
        self.installed_packages[engine] |= packages
        self.manager.store()

    def uninstall(self, engine, packages={'auto'}):
        """Uninstall a set of `packages` with `engine`."""
        # TODO: Implement and make this more suffisticated, so that app scripts
        # cannot remove
        # packages (at the moment it for example could install vim, then
        # uninstall vim - and vim would be gone for good...)
        return

        self._logger.info('Uninstalling %s', packages)
        if engine not in {'system', 'bundler'}:
            raise ValueError('engine_unknown')
        if not packages <= self.installed_packages.get(engine, {}):
            raise ValueError('packages_not_installed')

        auto = 'auto' in packages
        pkgs = packages - {'auto'}
        if engine == 'system':
            if pkgs:
                pass
                #check_call(['apt-mark', 'auto'] + packages)
                #check_call(['apt-get', 'autoremove'])
        elif engine == 'bundler':
            # TODO: ipmlement?
            pass

        self.installed_packages[engine] -= packages
        self.manager.store()

    def uninstall_all(self):
        """Uninstall all packages that were installed for the app."""
        #self._logger.info('Uninstalling all packages of the app')
        for engine, packages in self.installed_packages.items():
            self.uninstall(engine, packages)
        # store() already called by uninstall()

    def create_database(self, engine):
        if engine not in self.manager._database_engines:
            raise ValueError('engine_unknown')
        self._logger.info('Creating %s database', engine)
        database = self.manager._database_engines[engine].create(
            self.sid, self.dbuser, self.secret)
        self.databases.add(database)
        self.manager.store()
        return database
        """#sql = _create_db_template.format(name=self.id, pw=self.secret)
        c = db.cursor()
        # TODO why does this not work with ?
        c.execute('CREATE USER {}'.format(self.dbuser))
        c.execute('CREATE DATABASE {}'.format(self.sid))
        # mysql specific??
        c.execute("GRANT ALL ON {}.* TO {} IDENTIFIED BY '{}'".format(self.sid, self.dbuser, self.secret))
        db.close()"""

    def delete_database(self, database):
        self._logger.info('Deleting %s database', database.engine)
        # we only do complete app backups
        #self.backup_database(database)
        self.manager._database_engines[database.engine].delete(database)
        self.databases.remove(database)
        self.manager.store()

    def delete_all_databases(self):
        for database in set(self.databases):
            self.delete_database(database)

    """def _connect_db(self, engine):
        if engine == 'mysql':
            #from getpass import getpass
            #print('please enter MySQL root password')
            #pw = getpass()
            from mysql import connector
            db = connector.connect(user='root',
                                   password=self.config['mysql_password'])
        else:
            raise ValueError('engine_unknown')
        return db"""

    def pull(self):
        call('GIT_DIR={} GIT_WORK_TREE={} git pull'.format(
            os.path.join(self.path, '.git'), self.path))

    def request(self, url, data=None, search=None):
        self._logger.info('requesting {}...'.format(url))
        #cookielib example
        opener = build_opener(
            HTTPCookieProcessor(self._cookies)
        )
        #    urllib2.HTTPHandler(debuglevel=1)
        # copypasta

        url = self.url + url
        if data:
            data = urlencode(data)
        response = opener.open(url, data)
        html = response.read()
        if search:
            match = re.search(search, html)
            if match:
                return match.groups()
        return None

    def json(self):
        attrs = ['id', 'software_id', 'branch', 'port', 'secret', 'jobs', 'data_dirs', 'databases',
        'extensions', 'installed_packages', 'pids']
        json = {a: getattr(self, a) for a in attrs}
        #json['jobs'] = [j.json() for j in self.jobs.values()]
        #json['installed_packages'] = {e: list(p) for e, p
        #                              in self.installed_packages.items()}
        return json

#    def __repr__(self):
#        return json.dumps(self, default=self.manager._encode)

from http.cookiejar import CookieJar
import urllib.request
import re
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, build_opener, urlopen
SERVER_CONFIG_PATH = '/etc/apache2/sites-available/wam.conf'

class Nginx:
    """Nginx server.

    .. attribute:: manager

       Context :obj:`WebAppManager`.
    """

    def __init__(self, manager, config_path='/etc/nginx/conf.d/wam.conf'):
        self.manager = manager
        self.config_path = config_path

    def configure(self):
        servers = []
        for app in self.manager.apps.values():
            port = '80'
            ssl_config = ''
            ssl_redirect_config = ''
            if app.encrypted:
                port = '443 ssl'
                ssl_config = _NGINX_SSL_TEMPLATE.format(
                    app_certificate=os.path.abspath(app.certificate_path),
                    app_certificate_key=os.path.abspath(app.certificate_key_path))
                ssl_redirect_config = _NGINX_SSL_REDIRECT_TEMPLATE.format(host=app.id)

            servers.append(_NGINX_SERVER_TEMPLATE.format(
                host=app.id, port=port, app_port=app.port, ssl_config=ssl_config,
                ssl_redirect_config=ssl_redirect_config))

        with open(self.config_path, 'w') as f:
            f.write('\n'.join(servers))

        check_call(['sudo', 'systemctl', 'reload', 'nginx'])

class PackageEngine:
    def install(self, packages, app_path):
        """Install a set of `packages` for the app located at `app_path`."""
        raise NotImplementedError()

    def uninstall(self, packages, app_path):
        """Uninstall a set of `packages` for the app located at `app_path`."""
        raise NotImplementedError()

class Apt(PackageEngine):
    def install(self, packages, app_path):
        if not packages:
            # Ignore auto
            return
        check_call(['sudo', 'apt-get', '-qy', 'install'] + list(packages))

class Bundler(PackageEngine):
    def install(self, packages, app_path):
        if packages:
            # Implement?
            raise NotImplementedError()
        # TODO: set path to app somehow here!!
        check_call(['bundle', 'install', '--gemfile',
                    os.path.join(app_path, 'Gemfile')])#, '--deployment'])

class Bower(PackageEngine):
    def install(self, packages, app_path):
        if packages:
            # Implement?
            raise NotImplementedError()
        else:
            # maybe use update instead of install here?
            # Change working directory, otherwise .bowerrc is not taken into account
            check_call(['bower', '--config.interactive=false', 'install'], cwd=app_path)

class DatabaseEngine:
    id = None

    def connect(self):
        raise NotImplementedError()

    def create(self, name, user, secret):
        raise NotImplementedError()

    def delete(self, database):
        raise NotImplementedError()

    def dump(self, database, path):
        raise NotImplementedError()

    def restore(self, database, dump_path):
        raise NotImplementedError()

class SQLDatabaseEngine(DatabaseEngine):
    def create(self, name, user, secret):
        db = self.connect()
        # Some databases (e.g. PostgreSQL) don't like CREATE statements in
        # transactions
        db.autocommit = True
        c = db.cursor()
        c.execute("CREATE USER {} PASSWORD '{}'".format(user, secret))
        # TODO: mysql ON {}.* ??
        # TODO: mysql IDENTIFIED BY '{}' ??
        c.execute('CREATE DATABASE {}'.format(name))
        c.execute('GRANT ALL ON DATABASE {} TO {}'.format(name, user))
        db.close()
        return Database(self.id, name, user, secret)

    def delete(self, database):
        db = self.connect()
        # See create()
        db.autocommit = True
        c = db.cursor()
        c.execute('DROP DATABASE IF EXISTS {}'.format(database.name))
        try:
            # mysql has no IF EXISTS or something...
            c.execute('DROP USER {}'.format(database.user))
        except:
            # user (most likely) does not exist, ignore
            pass
        db.close()

    def restore(self, database, dump_path):
        db = self.connect()
        db.autocommit = True
        c = db.cursor()
        c.execute('DROP DATABASE {}'.format(database.name))
        c.execute('CREATE DATABASE {}'.format(database.name))
        c.execute('GRANT ALL ON DATABASE {} TO {}'.format(database.name, database.user))
        db.close()
        self.do_restore(database, dump_path)

    def do_restore(self, database, dump_path):
        raise NotImplementedError()

class PostgreSQL(SQLDatabaseEngine):
    id = 'postgresql'
    dump_name = 'postgresql.sql'

    def connect(self):
        import psycopg2
        db = psycopg2.connect(database='postgres')
        return db

    def dump(self, database, path):
        check_call(['pg_dump', '-O', '-f', os.path.join(path, self.dump_name), database.name])

    def do_restore(self, database, dump_path):
        # NOTE: I cannot use -1, because there are errors about plpgsql

        env = dict(os.environ)
        env['PGPASSWORD'] = database.secret
        check_call(['psql', '-h', 'localhost', '-f', dump_path, database.name, database.user],
                   env=env)

class MySQL(SQLDatabaseEngine):
    # TODO
    def connect(self):
        # TODO: test
        import mysql.connector
        db = mysql.connector.connect(user='root',
                                     password=self.config['mysql_password'])
        return db

    def dump(self, name, path):
        # TODO: test
        with open(os.path.join(path, 'mysql.sql'), 'w') as f:
            check_call(['mysqldump', '-u', 'root', '-p' + self.config['mysql_password'], name], stdout=f)
            #call('mysqldump -u {} -p{} {} > {}'.format(
            #    self.dbuser, self.secret, self.sid,
            #    os.path.join(self.path, 'dump.sql')))

class Redis(DatabaseEngine):
    id = 'redis'
    dump_name = 'redis.rdb'

    def __init__(self, get_redis_databases):
        super().__init__()
        self.get_redis_databases = get_redis_databases

    def create(self, name, user, secret):
        taken = {int(d.name) for d in self.get_redis_databases()}
        free = set(range(8, 15)) - taken
        if not free:
            # TODO: what to do here?
            raise ValueError()
        # TODO: order somehow?
        return Database(self.id, free.pop(), user, secret)

    def delete(self, database):
        # NOTE: we could flush the db
        pass

    def dump(self, database, path):
        from redis import StrictRedis
        r = StrictRedis()
        r.save()
        copyfile('/var/lib/redis/dump.rdb', os.path.join(path, self.dump_name))

    def restore(self, database, dump_path):
        # TODO: problem is that only the whole instance can be dumped and restored easily, not indiviudal
        # databases. Thus restoring an older backup of database A might override stuff from database
        # B. A solution would be to run multiple redis instances (instead of one instance with
        # multiple databases) (advantage would also be access control, ...), but this is not
        # implemented in Debian init yet.
        pass

class Database:
    def __init__(self, engine, name, user, secret, wam=None):
        # TODO: wam is not needed, hack for json loading, what to do here?
        self.engine = engine
        self.name = name
        self.user = user
        self.secret = secret

    def json(self):
        return vars(self)

CRON_CONFIG_PATH = '/etc/cron.d/wam'

class Cron:
    def __init__(self, manager):
        self.manager = manager

    def configure(self):
        x = []
        for app in self.manager.apps.values():
            for job in app.jobs.values():
                x.append("{} {}\n".format(' '.join(job.time), job.cmd))
        cmd = 'crontab -'
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, shell=True)
        p.communicate(''.join(x))
        if p.returncode != 0:
            raise CalledProcessError(p.returncode, cmd)

class Object:
    def json(self):
        return dict((k, v)
            for k, v in vars(self).items() if not k.startswith('_')
                and k != 'manager')

class Job(Object):
    """Cron job.

    Properties:

    * `cmd`
    * `time`
    """
    def __init__(self, id, cmd, time, manager):
        self.id = id
        self.cmd = cmd
        self.time = time
        self.manager = manager

class ScriptError(Exception):
    pass

# setup
# sudo -u www-data mkdir ext/protect
# TODO: vllt uebetrieben, einfach nur ProtectExtension, mit protect(app) reicht
# wohl...
class ProtectApp:
    def __init__(self, app):
        self.app = app
        self.manager = app.wam

    @property
    def protected(self):
        return os.path.isfile(self.htpasswd_path)

    @property
    def htpasswd_path(self):
        return os.path.join(self.manager.ext_path, 'protect/htpasswd')

    def protect(self, pw):
        # FIXME: python way? no pw over commandline!!!!
        # FIXME: chmod!!!
        # TODO: reenable
        #check_call('htpasswd -bc {} "" {}'.format(self.htpasswd_path, pw))
        self.manager.nginx.configure()

# utilities

from argparse import ArgumentParser

def run_app_script():
    parser = ArgumentParser()
    parser.add_argument(
        'command',
        choices=['setup', 'backup', 'update', 'cleanup', 'start', 'stop'])
    args = parser.parse_args()

    level = logging.DEBUG if 'WAM_VERBOSE' in os.environ else logging.INFO
    logging.basicConfig(level=level)

    config = {}
    data_path = os.environ.get('WAM_DATA_PATH')
    if data_path:
        config['data_path'] = data_path

    manager = WebAppManager(config)
    manager.start()

    app_id = os.environ['WAM_APP_ID']
    app = manager.apps[app_id]

    script = sys.modules['__main__']
    try:
        f = getattr(script, args.command)
    except AttributeError:
        return
    f(app)

def call(cmd):
    subprocess.check_call(cmd, shell=True)

def randstr(length=16, charset=ascii_lowercase):
    return ''.join(choice(charset) for i in range(length))

# main

if __name__ == '__main__':
    # TODO: parse args
    #if os.getuid() != 33:
    #    print('run as www-data, please')
    #    sys.exit()

    parser = ArgumentParser(argument_default=argparse.SUPPRESS)
    #parser.add_argument('command', choices=['add', 'remove'])
    parser.add_argument('-v', '--verbose', action='store_true')
    subparsers = parser.add_subparsers()

    # TODO: document: commands where there is risk to loose something create an automatic backup
    # TODO: document: some commands stop and then restart the app.

    def add_cmd(manager, software_id, url, **opts):
        manager.add(software_id, url, **opts)

    # TODO: rename into remove_cmd
    def app_remove_cmd(manager, app_id):
        app = manager.apps[app_id]
        manager.remove(app)

    def app_update_cmd(manager, app_id):
        app = manager.apps[app_id]
        app.update()

    def app_start_cmd(manager, app_id):
        app = manager.apps[app_id]
        app.start()

    def app_stop_cmd(manager, app_id):
        app = manager.apps[app_id]
        app.stop()

    def app_backup_cmd(manager, app_id):
        app = manager.apps[app_id]
        backup = app.backup()
        print('Backup created at: {}'.format(backup))

    def app_restore_cmd(manager, app_id, backup):
        app = manager.apps[app_id]
        app.restore(backup)

    def app_encrypt_cmd(manager, app_id):
        app = manager.apps[app_id]
        csr = app.encrypt()
        print('Certificate signing request created at: {}'.format(csr))
        print('Please submit it to your CA and then call app-encrypt2 with the signed certificate.')

    def app_encrypt2_cmd(manager, app_id, certificate):
        app = manager.apps[app_id]
        app.encrypt2(certificate)

    def app_add_extension_cmd(manager, app_id, extension_id):
        app = manager.apps[app_id]
        app.add_extension(extension_id)

    def app_remove_extension_cmd(manager, app_id, extension_id):
        app = manager.apps[app_id]
        app.remove_extension(extension_id)

    cmd = subparsers.add_parser(
        'add',
        description="""Add an app at a given URL.""")
    cmd.set_defaults(run=add_cmd)
    cmd.add_argument('software_id', help='TODO. webappmetafile')
    cmd.add_argument('url', help='TODO.')
    cmd.add_argument('--branch', help='TODO.')
    cmd.add_argument('--no-rollback', dest='rollback', action='store_false', help='TODO.')

    cmd = subparsers.add_parser(
        'remove',
        description="""Remove the app.""")
    cmd.set_defaults(run=app_remove_cmd)
    cmd.add_argument('app_id', help='App ID.')

    cmd = subparsers.add_parser(
        'app-update',
        description="""Update the app.""")
    cmd.set_defaults(run=app_update_cmd)
    cmd.add_argument('app_id', help='App ID.')

    cmd = subparsers.add_parser(
        'app-start',
        description="""TODO.""")
    cmd.set_defaults(run=app_start_cmd)
    cmd.add_argument('app_id', help='App ID.')

    cmd = subparsers.add_parser(
        'app-stop',
        description="""TODO.""")
    cmd.set_defaults(run=app_stop_cmd)
    cmd.add_argument('app_id',help='App ID.')

    cmd = subparsers.add_parser(
        'app-backup',
        description="""Backup the data of an app.

        The backup is stored at {wam-data-dir}/backups/backup-{app-id}-{timestamp} .
        """)
    cmd.set_defaults(run=app_backup_cmd)
    cmd.add_argument('app_id', help='App ID.')

    cmd = subparsers.add_parser(
        'app-restore',
        description="""Restore the (backup) data for an app.""")
    cmd.set_defaults(run=app_restore_cmd)
    cmd.add_argument('app_id', help='App ID.')
    cmd.add_argument('backup', help='Path to the backup directory that holds the data to restore.')

    cmd = subparsers.add_parser(
        'app-encrypt',
        description="""Enable SSL encryption for the app.

        The first step creates a certificate signing request, ready to be submitted to a CA.""")
    cmd.set_defaults(run=app_encrypt_cmd)
    cmd.add_argument('app_id', help='App ID.')

    cmd = subparsers.add_parser(
        'app-encrypt2',
        description="""Enable SSL encryption for the app.

        The second and last step applies the signed certificate.""")
    cmd.set_defaults(run=app_encrypt2_cmd)
    cmd.add_argument('app_id', help='App ID.')
    cmd.add_argument('certificate', help='Path of the signed certificate file.')

    cmd = subparsers.add_parser('app-add-extension', description='TODO')
    cmd.set_defaults(run=app_add_extension_cmd)
    cmd.add_argument('app_id', help='App ID.')
    cmd.add_argument('extension_id', help='TODO')

    cmd = subparsers.add_parser('app-remove-extension', description='TODO')
    cmd.set_defaults(run=app_remove_extension_cmd)
    cmd.add_argument('app_id', help='App ID.')
    cmd.add_argument('extension_id', help='TODO')

    # extensions
    def protect_app(manager, args):
        app = manager.apps[args.app_id]
        ProtectApp(app).protect(args.password)

    protect_app_cmd = subparsers.add_parser('protect-app')
    protect_app_cmd.set_defaults(run=protect_app)
    protect_app_cmd.add_argument('app_id')
    protect_app_cmd.add_argument('password')

    args = vars(parser.parse_args())
    #print(args)

    verbose = args.pop('verbose', False)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level)

    manager = WebAppManager()
    manager.start()

    run = args.pop('run')
    run(manager, **args)

    # TODO exec command

    #app = wam.apps['humhub.inrain.org']
    #app.backup()
    #app.update()

    # cmd: app-protect <pw>
    # the board is dead long live the board
    #app = ProtectApp(app)
    #app.protect('tbidlltb')

    # highly dangerous now!!!
    #if 'humhub.inrain.org' in wam.apps:
    #    wam.remove(wam.apps['humhub.inrain.org'])
    #wam.add('humhub.py', 'humhub.inrain.org')
