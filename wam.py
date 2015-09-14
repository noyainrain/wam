#!/usr/bin/env python3

"""wam!"""

import sys
import os
import signal
import json
import subprocess
import logging
import shlex
from subprocess import Popen, CalledProcessError, check_call, check_output
from shutil import copyfile, make_archive
from random import choice
from string import ascii_lowercase
from urllib.parse import urldefrag
from re import sub
from os import path, mkdir
from errno import ENOENT

# TODO: Implement config parsing

_NGINX_CONFIG_PATH = '/etc/nginx/conf.d/wam.conf'

_NGINX_SERVER_TEMPLATE = """\
server {{
    listen {port};
    server_name {host};
    location / {{
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_pass http://localhost:{app_port};
    }}
}}
"""

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

    .. attribute: nginx

       :obj:`Nginx` server.
    """

    def __init__(self, config={}, **kwargs):
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
        self.ext_path = os.path.join(self.data_path, 'ext')

        try:
            self.port_range = tuple(int(p) for p in self.config['port_range'].split('-'))
        except ValueError:
            raise ValueError('port_range')
        if not (len(self.port_range) == 2 and self.port_range[0] < self.port_range[1]):
            raise ValueError('port_range')

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
        for d in [self.data_path, self.backup_path, self.ext_path]:
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

    def add(self, software_id, url, rollback=True):
        """
        add / activate instance of app at url.
        `app_id` is an identifier, either known to system or an webapp meta file or
        an HTTP URL pointing to a webapp meta file
        """

        if not os.path.isfile(software_id):
            raise ValueError('software_id')

        self._logger.info('Adding %s', url)

        used_ports = {a.port for a in self.apps.values()}
        free_ports = set(range(self.port_range[0], self.port_range[1] + 1)) - used_ports
        port = sorted(free_ports)[0]

        secret = randstr()
        app = App(url, software_id, port, secret, {}, {}, set(), wam=self)
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

    def __init__(self, id, software_id, port, secret, jobs, installed_packages, databases, wam,
                 data_dirs=set(), pids=set()):
        self.id = id
        self.software_id = software_id
        self.port = port
        self.secret = secret
        self.installed_packages = installed_packages
        self.databases = databases
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

    def encrypt(self):
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
        # TODO: return what? better csr blob?
        return csr_path

    def encrypt2(self, certificate):
        with open(self.certificate_path, 'w') as f:
            f.write(certificate)
        # TODO: validate certificate somehow
        call('openssl x509 -in {} -text'.format(self.certificate_path))
        self.manager.nginx.configure()

    def setup(self):
        raise NotImplementedError()
        """
        should setup
         * config
         * datastores (db, directories)
        """
        self._call('setup')

        self._update_code()
        self._update_packages()
        self._update_databases()
        self._update_data_dirs()

        # TODO: should we really rollback if start fails? maybe a warning is the better option (i.e. handle neat exception)
        self.start()

    def update(self, fresh=False):
        self._logger.info('Updating %s', self.id)

        # TODO: fresh not via paramater, but as state/property
        if not fresh:
            running = self.is_running
            if running:
                self.stop()
            self.backup()

        self._update_code()
        self._update_packages()
        self._update_databases()
        self._update_data_dirs()
        self._call('update')

        if fresh or running:
            self.start()

    def _update_code(self):
        self._logger.info('Updating code')

        try:
            url = self.meta['download']
        except KeyError:
            return

        try:
            git_root = (check_output(['git', '-C', self.path, 'rev-parse', '--show-toplevel'])
                        .decode().strip())
        except CalledProcessError:
            git_root = None
        repo_exists = (git_root == self.path)

        if not repo_exists:
            self._logger.info('Cloning from %s', url)
            url, branch = urldefrag(url)
            cmd = ['git', 'clone', '-q', '--single-branch', url, self.path]
            if branch:
                cmd[4:4] = ['-b', branch]
            check_call(cmd)
        else:
            self._logger.info('Pulling from %s', url)
            check_call(['git', '-C', self.path, 'fetch'])
            check_call(['git', '-C', self.path, 'merge'])

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

    def _restore_databases(self, backup):
        for database in self.databases:
            self._logger.info('Restoring %s database', database.engine)
            engine = self.manager._database_engines[database.engine]
            engine.restore(os.path.join(backup, engine.dump_name))

    def _update_data_dirs(self):
        data_dirs = set(self.software_meta.get('data_dirs', []))
        new = data_dirs - self.data_dirs
        old = self.data_dirs - data_dirs
        for path in old:
            self._logger.debug('Resetting data directory %s', path)
            check_call([
                'sudo', 'chown', '-R',
                '{}:{}'.format(os.geteuid(), os.getegid()),
                os.path.join(self.path, path)])
            #chown(os.path.join(self.path, path), os.geteuid(), os.getegid())
        for path in new:
            self._logger.debug('Setting data directory %s', path)
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
        self.manager.store()

    def _backup_data_dirs(self, backup_path):
        from shutil import copytree
        for data_dir in self.data_dirs:
            copytree(os.path.join(self.path, data_dir), os.path.join(backup_path, data_dir))

    def _restore_data_dirs(self, backup):
        pass

    def backup(self):
        # TODO: app settings should also be backed up, so a wam app can be
        # restored just by selecting a .tar.gz file
        self._logger.info('Backing up %s', self.id)
        running = self.is_running
        if running:
            self.stop()

        from datetime import datetime
        backup_path = os.path.join(self.manager.backup_path,
                                   'backup-{}-{}'.format(self.sid, datetime.utcnow().isoformat()))
        #os.makedirs(backup_path)
        os.mkdir(backup_path)

        try:
            self._call('backup')
        except CalledProcessError as e:
            raise ValueError('user_script') # TODO: own error

        # TODO: only backup datadirs and db
        self._backup_all_databases(backup_path)
        self._backup_data_dirs(backup_path)


        # TODO: other directory (e.g. var/www/wam/backup)?
        #make_archive('/tmp/wam.backup.{}.{}'.format(self.sid, randstr()),
        #             'gztar', self.wam.config['data_path'], self.sid, verbose=2)
        if running:
            self.start()

        return backup_path

    def restore(self, backup):
        self._logger.info('Restoring %s', self.id)
        running = self.is_running
        if running:
            self.stop()
        self.backup()

        self._restore_databases(backup)
        self._restore_data_dirs(backup)

        if running:
            self.start()

    def cleanup(self):
        self._logger.info('Cleaning up %s', self.id)
        self.stop()
        self.backup()

        try:
            self._call('cleanup')
        finally:
            self.delete_all_databases()
            self.uninstall_all()

    def start(self):
        self._logger.info('Starting %s', self.id)
        if self.pids:
            # this is a restart, good idea here?
            self.stop()

        jobs = self.meta['jobs']
        for job in jobs:
            cmd = job['cmd'].format(**self.data)
            cwd = job.get('cwd')
            if cwd:
                cwd = cwd.format(**self.data)
            self.start_job(cmd, cwd=cwd)

        self._call('start')

    def stop(self):
        self._logger.info('Stopping %s', self.id)
        try:
            self._call('stop')
        finally:
            self.stop_all_jobs()

    def start_job(self, cmd, env={}, cwd=None):
        args = shlex.split(cmd)
        args = ['sudo', '-u', self.job_user] + args
        envi = dict(os.environ)
        envi.update(env)
        #print(args)
        #print(envi)
        p = Popen(args, env=envi, cwd=cwd)
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
        self._logger.info('Creating database')
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
        self._logger.info('Deleting database')
        # we only do complete app backups
        #self.backup_database(database)
        self.manager._database_engines[database.engine].delete(database)
        self.databases.remove(database)
        self.manager.store()

    def delete_all_databases(self):
        for database in set(self.databases):
            self.delete_database(database)

    def backup_database(self, database, path):
        self._logger.info('Backing up database %s', database.engine)
        self.manager._database_engines[database.engine].dump(database, path)

    def _backup_all_databases(self, path):
        for db in self.databases:
            self.backup_database(db, path)

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
        attrs = ['id', 'software_id', 'port', 'secret', 'jobs', 'databases', 'installed_packages',
                 'pids']
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
            servers.append(_NGINX_SERVER_TEMPLATE.format(port=80, host=app.id, app_port=app.port))
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
            check_call(
                ['bower', '--config.cwd=' + app_path, '--config.interactive=false', 'install'])

class DatabaseEngine:
    id = None

    def connect(self):
        raise NotImplementedError()

    def create(self, name, user, secret):
        db = self.connect()
        # Some databases (e.g. PostgreSQL) don't like CREATE statements in
        # transactions
        db.autocommit = True
        c = db.cursor()
        c.execute('CREATE DATABASE {}'.format(name))
        c.execute("CREATE USER {} PASSWORD '{}'".format(user, secret))
        # TODO: mysql ON {}.* ??
        # TODO: mysql IDENTIFIED BY '{}' ??
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

    def dump(self, database, path):
        raise NotImplementedError()

    def restore(self, database, dump_path):
        raise NotImplementedError()

class PostgreSQL(DatabaseEngine):
    id = 'postgresql'
    dump_name = 'postgresql.sql'

    def connect(self):
        import psycopg2
        db = psycopg2.connect(database='postgres')
        return db

    def dump(self, database, path):
        with open(os.path.join(path, self.dump_name), 'w') as f:
            check_call(['pg_dump', database.name], stdout=f)

    def restore(self, database, dump_path):
        with open(dump_path) as f:
            check_call(['psql', '-1', database.name], stdin=f)

class MySQL(DatabaseEngine):
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

    parser = ArgumentParser()
    #parser.add_argument('command', choices=['add', 'remove'])
    parser.add_argument('-v', '--verbose', action='store_true')
    subparsers = parser.add_subparsers(dest='cmd')
    add_cmd = subparsers.add_parser('add')
    add_cmd.add_argument('software_id')
    add_cmd.add_argument('url')
    add_cmd.add_argument('--no-rollback', dest='rollback', action='store_false')
    remove_cmd = subparsers.add_parser('remove')
    remove_cmd.add_argument('app_id')
    app_start_cmd = subparsers.add_parser('app-start')
    app_start_cmd.add_argument('app_id')
    app_stop_cmd = subparsers.add_parser('app-stop')
    app_stop_cmd.add_argument('app_id')
    app_update_cmd = subparsers.add_parser('app-update')
    app_update_cmd.add_argument('app_id')
    app_backup_cmd = subparsers.add_parser('app-backup')
    app_backup_cmd.add_argument('app_id')

    # extensions
    def protect_app(manager, args):
        app = manager.apps[args.app_id]
        ProtectApp(app).protect(args.password)
    protect_app_cmd = subparsers.add_parser('protect-app')
    protect_app_cmd.set_defaults(run=protect_app)
    protect_app_cmd.add_argument('app_id')
    protect_app_cmd.add_argument('password')

    args = parser.parse_args()
    #print(args)

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level)

    manager = WebAppManager()
    manager.start()

    if args.cmd == 'add':
        manager.add(args.software_id, args.url, rollback=args.rollback)
    elif args.cmd == 'remove':
        app = manager.apps[args.app_id]
        manager.remove(app)
    elif args.cmd == 'app-start':
        app = manager.apps[args.app_id]
        app.start()
    elif args.cmd == 'app-stop':
        app = manager.apps[args.app_id]
        app.stop()
    elif args.cmd == 'app-backup':
        app = manager.apps[args.app_id]
        app.backup()
    elif args.cmd == 'app-update':
        app = manager.apps[args.app_id]
        app.update()
    else:
        print(args)
        args.run(manager, args)

    # TODO exec command

    #app = wam.apps['humhub.inrain.org']
    #app.backup()
    #app.update()

    # cmd: app-protect <pw>
    # the board is dead long live the board
    #app = ProtectApp(app)
    #app.protect('tbidlltb')

    # cmd: app-encrypt <id>
    # step1
    #csr_path = app.encrypt()
    #print('certificate signing request: {}'.format(csr_path))
    #print('please submit it and call encrypt2 with certificate')

    # cmd: app-encrypt2 <id> <certificate-path>
    # step2
    #certificate_path = 'foo.crt'
    #with open(certificate_path) as f:
    #    certificate = f.read()
    #app.encrypt2(certificate)

    # highly dangerous now!!!
    #if 'humhub.inrain.org' in wam.apps:
    #    wam.remove(wam.apps['humhub.inrain.org'])
    #wam.add('humhub.py', 'humhub.inrain.org')
