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
import shutil
from time import sleep
from itertools import chain, groupby
from collections.abc import Mapping
from subprocess import Popen, CalledProcessError, check_call, check_output
from shutil import copyfile, copytree, make_archive
from random import choice
from string import ascii_lowercase
from urllib.parse import urlparse, urldefrag
from re import sub
from os import path, mkdir
from errno import ENOENT
from datetime import datetime

# TODO: Implement config parsing

_NGINX_CONFIG_PATH = '/etc/nginx/conf.d/wam.conf'

# TODO: certbot causes a duplicate hash bucket size error
# (https://github.com/certbot/certbot/pull/924/files)
_NGINX_TEMPLATE = """\
client_max_body_size 512m;
# Make longer domain names possible
#server_names_hash_bucket_size 64;
#proxy_headers_hash_bucket_size 64;

{config}
"""

_NGINX_SERVER_TEMPLATE = """\
server {{
    listen 443 ssl;
    server_name {host};
    ssl_certificate /etc/letsencrypt/live/{host}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{host}/privkey.pem;
{locations}
{more}
}}

server {{
    listen 80;
    server_name {host};
    return 301 https://{host};
}}
"""

_NGINX_PROXY_TEMPLATE = """\
    location {app.url.slashed_path} {{
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_read_timeout 1h;
        proxy_pass http://localhost:{app.port};
    }}
"""

# TODO: remove location / from below
# TODO: merge proxy from above with this??
# exclude for owncloud: ^/data
_NGINX_STATIC_TEMPLATE = """\
    location {url} {{
        root {path};

        location ~ {exclude} {{
            return 404;
        }}
    }}
"""

_NGINX_PHPFPM_TEMPLATE = """\
    # TODO: move into location
    index index.php;

    location {app.url.slashed_path} {{
        root {app.path.abs};
        try_files $uri $uri/ {app.url.path}/index.php?$args;
        #alias {app.path.abs}/;
        #index index.php;

        # TODO: Do not hardcode
        location ~ ^/data {{
            return 404;
        }}
    }}

    # TODO: move to top location
    location ~ \.php(/|$) {{
        root {app.path.abs};
        #alias {app.path.abs};
        fastcgi_split_path_info ^(.+?\.php)(/.*)?$;
        #fastcgi_split_path_info ^{app.url.path}(.+?\.php)(/.*)?$;
        try_files $fastcgi_script_name =404;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        # http://trac.nginx.org/nginx/ticket/321
        set $path_info $fastcgi_path_info;
        fastcgi_param PATH_INFO $path_info;
        include fastcgi_params;
        fastcgi_pass unix:/var/run/php/php7.3-fpm.sock;
    }}
"""

_NGINX_PROTECT_TEMPLATE = """\
    auth_basic {id};
    auth_basic_user_file {auth_path};
"""

import yaml

class Registry(Mapping):
    def __init__(self):
        self._cache = {}

    def __getitem__(self, key):
        if key not in self._cache:
            with open(key) as f:
                meta = yaml.safe_load(f)
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
            'user': None,
            'password': None,
            'email': None,
            'port_range': '8000-8079',
            'certbot': True
        }
        self.config.update(config)

        self.data_path = self.config['data_path']
        self.store_path = os.path.join(self.data_path, 'wam.json')
        self.backup_path = os.path.join(self.data_path, 'backups')
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

        self.package_engines = {'apt': Apt(), 'pip': Pip(), 'bundler': Bundler(), 'bower': Bower()}
        def get_redis_databases():
            #for app in self.apps:
            #    for database in app.databases:
            #        if database.engine == 'redis':
            #            return database
            #return {d for a in self.apps.values() for d in a.databases.values() if d.engine == 'redis'}
            return {a.databases['redis'] for a in self.apps.values() if 'redis' in a.databases}
        self.database_engines = {
            'postgresql': PostgreSQL(),
            'mysql': MySQL(),
            'redis': Redis(get_redis_databases)
        }
        # TODO: remove this, just for backwards compatibility
        self._package_engines = self.package_engines
        self._database_engines = self.database_engines

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
                types = {'App': App, 'Database': Database, 'Extension': Extension, 'Job': Job}
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
        app = App(url, software_id, port, secret, {}, {}, databases={}, extensions={}, wam=self,
                  branch=None)

        # Get TLS certificate
        if self.config['certbot']:
            check_call(['sudo', 'certbot', 'certonly', '-n', '--nginx', '-d', app.url.host])

        self.apps[app.id] = app
        mkdir(app.path)

        self.nginx.configure()
        self.store()

        try:
            #app.setup()
            app.update(branch=branch, fresh=True)
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
        trash(app.path)
        del self.apps[app.id]
        # Remove TLS certificate
        # sudo certbot revoke -n --cert-path=/etc/letsencrypt/live/{app.id}/cert.pem
        self.nginx.configure()
        self.store()

    def update(self):
        for app in self.apps.values():
            app.update()

    # TODO: Rename
    def startx(self):
        for app in self.apps.values():
            app.start()

    def stop(self):
        for app in self.apps.values():
            app.stop()

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

    .. attribute:: extensions

       Map of installed extensions.
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
            self._software_meta = {
                'download': None, # TODO: must be set?
                'mode': 'proxy',
                'stack': [],
                'packages': {},
                'databases': [],
                'data_dirs': [],
                'files': {},
                'jobs': [],
                'hook': None,
                'hooks': None,
                'extension_path': 'ext',
                'default_extensions': []
            }
            meta = self.manager.meta[self.software_id]
            self._software_meta.update(meta)
            if isinstance(self._software_meta['stack'], str):
                self._software_meta['stack'] = [self._software_meta['stack']]
            self._software_meta['jobs'] = list(
                {'cmd': j} if isinstance(j, str) else j for j in
                    self._software_meta.get('jobs', []))
        return self._software_meta
    meta=software_meta

    @property
    def path(self):
        class pathstr(str):
            def __init__(self, value):
                self.abs = os.path.abspath(value)
        return pathstr(os.path.join(self.wam.config['data_path'], self.sid))

    @property
    def url(self):
        class urlstr(str):
            def __init__(self, value):
                tokens = urlparse(value)
                self.host = tokens.hostname
                self.path = tokens.path
                self.slashed_path = self.path or '/'
        return urlstr('https://{}'.format(self.id))

    @property
    def is_running(self):
        return bool(self.meta['mode'] == 'phpfpm' or self.pids)

    @property
    def data(self):
        # TODO: we dont need this anymore, how awesome, we can just pass the app object to
        # templates, yehaaaa
        return {
            'port': self.port,
            'path': self.path,
            'databases': self.databases
        }

    def update(self, branch=None, fresh=False):
        self._logger.info('Updating %s', self.id)

        if branch:
            self.branch = branch

        # TODO: fresh not via paramater, but as state/property
        if not fresh:
            running = self.is_running
            if running:
                self.stop()
            if self.manager.auto_backup:
                self.backup()

        self._reset_data_dirs()

        self._update_default_extensions()
        self._update_code()
        self._update_stack()
        self._update_packages()
        self._update_databases()
        self._update_data_dirs()
        self._update_files()

        self._set_data_dirs()

        self._run_hook()
        self._call('update')

        self.manager.store()
        if fresh or running:
            self.start()

    def _update_default_extensions(self):
        default_exts = {reponame(u): u for u in self.meta['default_extensions']}
        current = self.extensions.keys() & default_exts.keys()
        new = default_exts.keys() - self.extensions.keys()
        for id in current:
            ext = self.extensions[id]
            url = default_exts[id]
            if ext.url != url:
                ext.set_url(url)
        for id in new:
            ext = Extension(default_exts[id], self.id, self.wam)
            self.extensions[ext.id] = ext

    def _update_code(self):
        self._logger.info('Updating code')

        url = self.meta['download']
        if not url:
            return

        self._update_repo(self.path, url, branch=self.branch)
        for extension in self.extensions.values():
            #path = os.path.join(self.path, self.meta['extension_path'], extension.id)
            self._update_repo(extension.path, extension.url)

    def _update_repo(self, repo, url, branch=None):
        try:
            git_root = check_output(['git', '-C', repo, 'rev-parse', '--show-toplevel'],
                                    stderr=subprocess.DEVNULL)
            git_root = git_root.decode().strip()
        except CalledProcessError:
            git_root = None
        # git_root is always absolute, repo may or may not be
        repo_exists = (git_root == os.path.abspath(repo))

        url, default_branch = urldefrag(url)
        branch = branch or default_branch or 'master'

        if not repo_exists:
            self._logger.info('Cloning from %s%s', url, '#' + branch if branch else '')
            cmd = ['git', 'clone', '-q', '--recursive', '--single-branch', url, repo]
            if branch:
                cmd[5:5] = ['-b', branch]
            try:
                check_call(cmd)
            except CalledProcessError:
                raise OSError('git')
        else:
            self._logger.info('Pulling from %s', url)
            try:
                origin_url = check_output(['git', '-C', repo, 'config', '--get', 'remote.origin.url']).decode().strip()
                if url != origin_url:
                    check_call(['git', '-C', repo, 'remote', 'set-url', 'origin', url])
                # If we are not on a branch (e.g. checked out a tag), FETCH_HEAD is needed
                check_call(['git', '-C', repo, 'fetch', 'origin', branch])
                check_call(['git', '-C', repo, 'checkout', 'FETCH_HEAD'])
                check_call(['git', '-C', repo, 'submodule', 'sync'])
                check_call(['git', '-C', repo, 'submodule', 'update', '--recursive'])
            except CalledProcessError:
                raise OSError('git')

    def _update_stack(self):
        # Stack = runtime + package manager
        self._logger.info('Updating stack')
        # js: (nodejs-legacy, npm + npm->bower) here we would have to implement class Npm also

        if 'ruby' in self.meta['stack']:
            if subprocess.call(['which', 'ruby-install']) != 0:
                check_call(['git', 'clone', '--single-branch', '--branch=v0.6.0',
                            'https://github.com/postmodern/ruby-install.git'], cwd='/tmp')
                check_call(['sudo', 'make', 'install'], cwd='/tmp/ruby-install')
            if subprocess.call(['which', 'chruby-exec']) != 0:
                check_call(['git', 'clone', '--single-branch', '--branch=v0.3.9',
                            'https://github.com/postmodern/chruby.git'], cwd='/tmp')
                check_call(['sudo', 'make', 'install'], cwd='/tmp/chruby')
            check_call(['sudo', 'ruby-install', '--latest', '--no-reinstall', 'ruby'])
            check_call(['sudo', 'bash', '-c', '. /usr/local/share/chruby/chruby.sh && chruby ruby && gem install bundler'])

        alias = {
            'nodejs': ['npm'],
            'php5': ['php5-fpm', 'php5-gd', 'php5-curl', 'php5-mcrypt', 'php5-mysqlnd',
                     'php5-sqlite'],
            'php': ['php-fpm', 'php-cli', 'php-gd', 'php-curl', 'php-intl', 'php-mbstring',
                    'php-mysql', 'php-sqlite3', 'php-xml', 'php-zip'],
            'python3': ['python3-pip', 'python3-venv']
        }
        packages = set(chain.from_iterable(alias[s] for s in self.meta['stack'] if s in alias))
        self.install('apt', packages)

        if 'python3' in self.meta['stack']:
            check_call(['python3', '-m', 'venv', os.path.join(self.path, '.venv')])

    def _update_packages(self):
        # TODO: Skip already installed packages
        # TODO: Remove packages
        packages_meta = self.meta.get('packages', {})
        for engine, packages in packages_meta.items():
            # TODO: install apt packages before others
            self.install(engine, set(packages))

    def _update_databases(self):
        target_databases = set(self.meta.get('databases', []))
        current_databases = set(self.databases)
        new = target_databases - current_databases
        old = current_databases - target_databases
        for engine in old:
            # TODO: Delete databases
            pass
        for engine in new:
            self.manager.database_engines[engine].setup()
            self.create_database(engine)

    def _set_data_dirs(self):
        if self.data_dirs:
            check_call(['sudo', 'chown', '-R', '{}:{}'.format(self.job_user, self.job_user)] +
                       [os.path.join(self.path, d) for d in self.data_dirs])

    def _reset_data_dirs(self):
        #for data_dir in self.data_dirs:
            #self._logger.info('Deleting data directory %s', data_dir)
            #chown(os.path.join(self.path, path), os.geteuid(), os.getegid())
            # It is safer to remove the tree directly as the job user, which is less privileged
            #check_call(['sudo', '-u', self.job_user, 'rm', '-r', os.path.join(self.path, path)])
            #os.rename(path, '/tmp/wam-{}'.format(randstr()))
            #check_call(['sudo', 'chown', '-R', '{}:{}'.format(os.geteuid(), os.getegid()), path])
            #path = os.path.join(self.path, data_dir)
        if self.data_dirs:
            check_call(['sudo', 'chown', '-R', '{}:{}'.format(os.geteuid(), os.getegid())] +
                       [os.path.join(self.path, d) for d in self.data_dirs])

    def _update_data_dirs(self, cleanup=False):
        data_dirs = set(self.software_meta.get('data_dirs', []) if not cleanup else [])
        #old = self.data_dirs - data_dirs
        #for data_dir in old:
        #    self._logger.info('Deleting data directory %s', data_dir)
        #    #chown(os.path.join(self.path, path), os.geteuid(), os.getegid())
        #    # It is safer to remove the tree directly as the job user, which is less privileged
        #    #check_call(['sudo', '-u', self.job_user, 'rm', '-r', os.path.join(self.path, path)])
        #    path = os.path.join(self.path, data_dir)
        #    check_call(['sudo', 'chown', '-R', '{}:{}'.format(os.geteuid(), os.getegid()), path])
        #    os.rename(path, '/tmp/wam-{}'.format(randstr()))
        new = data_dirs - self.data_dirs
        for path in new:
            self._logger.info('Creating data directory %s', path)
            path = os.path.join(self.path, path)
            try:
                mkdir(path)
            except FileExistsError:
                # That's okay
                pass
        self.data_dirs = data_dirs

    def _update_files(self):
        self._logger.info('Updating files')
        for name, content in self.meta['files'].items():
            self._logger.info('Writing ' + name)
            with open(os.path.join(self.path, name), 'w') as f:
                f.write(content.format(app=self, wam=self.manager))

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
        for database in self.databases.values():
            self._logger.info('Backing up %s database', database.engine)
            self.manager._database_engines[database.engine].dump(database, backup)

    def _backup_data_dirs(self, backup):
        for data_dir in self.data_dirs:
            self._logger.info('Backing up data directory %s', data_dir)
            # TODO comment about why some apps are stupid and with chmod
            d = os.path.join(self.path, data_dir)
            check_call(['sudo', 'chmod', '-R', 'a+rX', d])
            copytree(d, os.path.join(backup, data_dir), symlinks=True)

    def restore(self, backup):
        """See :ref:`wam app-restore`.

        If the backup is not a backup of (the current version) of the app, a :exc:`ValueError`
        (``backup_invalid``) is raised.
        """
        # Validate backup
        for database in self.databases.values():
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
        for database in self.databases.values():
            self._logger.info('Restoring %s database', database.engine)
            engine = self.manager._database_engines[database.engine]
            engine.restore(database, os.path.join(backup, engine.dump_name))

    def _restore_data_dirs(self, backup):
        self._reset_data_dirs()
        for data_dir in self.meta.get('data_dirs', []):
            self._logger.info('Restoring data directory %s', data_dir)
            path = os.path.join(self.path, data_dir)
            trash(path)
            copytree(os.path.join(backup, data_dir), path, symlinks=True)
        self._set_data_dirs()
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
            cmd = job['cmd'].format(app=self, wam=self.manager)
            self.start_job(cmd, cwd=self.path)

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
        # TODO use self._script(cmd, job_user=True)
        if 'ruby' in self.meta['stack']:
            args = ['bash', '-c', '. /usr/local/share/chruby/chruby.sh && chruby ruby && GEM_HOME=$GEM_ROOT exec ' + cmd]
        elif 'python3' in self.meta['stack']:
            args = ['bash', '-c', '. .venv/bin/activate && ' + cmd]
        else:
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

    def add_extension(self, url):
        if reponame(url) in self.extensions:
            raise ValueError('extension') #TODO
        ext = Extension(url, self.id, self.wam)
        self.extensions[ext.id] = ext
        self._update_repo(ext.path, ext.url)
        self.manager.store()
        return ext

    def remove_extension(self, ext):
        trash(ext.path)
        del self.extensions[ext.id]
        self.manager.store()

    def _script(self, script):
        # bash required by chruby
        p = Popen(['bash', '-e'], stdin=subprocess.PIPE, cwd=self.path)
        script = script.format(app=self, wam=self.manager)
        if 'ruby' in self.meta['stack']:
            script = '. /usr/local/share/chruby/chruby.sh\nchruby ruby\nexport GEM_HOME=$GEM_ROOT\n' + script
        if 'python3' in self.meta['stack']:
            script = '. .venv/bin/activate\n' + script
        p.communicate(script.encode('utf-8'))
        if p.returncode:
            raise ScriptError()

    def _run_hook(self):
        if not self.meta['hook']:
            return
        self._script(self.meta['hook'])

    def _call(self, op):
        if not self.meta['hooks']:
            return

        script = os.path.join(os.path.dirname(self.software_id), self.meta['hooks'])

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
        database = self.manager._database_engines[engine].create(self.sid, self.secret)
        self.databases[database.engine] = database
        self.manager.store()
        return database

    def delete_database(self, database):
        self._logger.info('Deleting %s database', database.engine)
        # we only do complete app backups
        #self.backup_database(database)
        self.manager._database_engines[database.engine].delete(database)
        del self.databases[database.engine]
        self.manager.store()

    def delete_all_databases(self):
        for database in list(self.databases.values()):
            self.delete_database(database)

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

        apps = sorted(self.manager.apps.values(), key=lambda a: (a.url.host, a.url.path))
        for host, group in groupby(apps, lambda a: a.url.host):
            group = list(group)
            app = group[0]

            ext = ProtectExtension(self.manager)
            more = ext.get_nginx_server_config(app)

            locations = []
            for app in group:
                if app.meta['mode'] == 'proxy':
                    #more = ext.get_nginx_proxy_config(app)
                    location_config = _NGINX_PROXY_TEMPLATE.format(app=app)
                elif app.meta['mode'] == 'phpfpm':
                    location_config = _NGINX_PHPFPM_TEMPLATE.format(app=app)
                else:
                    assert(False)
                locations.append(location_config)
            locations = '\n'.join(locations)

            servers.append(_NGINX_SERVER_TEMPLATE.format(host=host, locations=locations,
                                                         more=more or ''))

        with open(self.config_path, 'w') as f:
            f.write(_NGINX_TEMPLATE.format(config='\n'.join(servers)))

        check_call(['sudo', 'service', 'nginx', 'reload'])

class PackageEngine:
    # TODO: maybe packages should either be packages or a path to the app.....
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

class Pip(PackageEngine):
    def install(self, packages, app_path):
        args = list(packages) if packages else ['-r', os.path.join(app_path, 'requirements.txt')]
        args = ' '.join(args)
        check_call(['bash', '-c', '. {}/.venv/bin/activate && pip3 install -U {}'.format(app_path, args)])

class Bundler(PackageEngine):
    def install(self, packages, app_path):
        if packages:
            # Implement?
            raise NotImplementedError()
        check_call([
            'sudo', 'bash', '-c',
            '. /usr/local/share/chruby/chruby.sh && chruby ruby && bundle install --gemfile ' + os.path.join(app_path, 'Gemfile')])

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
    dump_name = None

    def setup(self):
        pass

    def connect(self):
        raise NotImplementedError()

    def create(self, name, secret):
        raise NotImplementedError()

    def delete(self, database):
        raise NotImplementedError()

    def dump(self, database, path):
        raise NotImplementedError()

    def restore(self, database, dump_path):
        raise NotImplementedError()

class SQLDatabaseEngine(DatabaseEngine):
    create_user_query = None
    grant_query = None
    quote = '"'

    def create(self, name, secret):
        user = randstr()
        db = self.connect()
        # Some databases (like PostgreSQL) don't like CREATE statements in transactions
        db.autocommit = True
        c = db.cursor()
        c.execute(self.create_user_query.format(user=user, secret=secret))
        c.execute('CREATE DATABASE {q}{}{q}'.format(name, q=self.quote))
        c.execute(self.grant_query.format(name=name, user=user))
        db.close()
        return Database(self.id, name, user, secret)

    def delete(self, database):
        db = self.connect()
        # See create()
        db.autocommit = True
        c = db.cursor()
        c.execute('DROP DATABASE IF EXISTS {q}{}{q}'.format(database.name, q=self.quote))
        try:
            # mysql has no IF EXISTS or something...
            c.execute('DROP USER {q}{}{q}'.format(database.user, q=self.quote))
        except:
            # user (most likely) does not exist, ignore
            pass
        db.close()

    def restore(self, database, dump_path):
        db = self.connect()
        db.autocommit = True
        c = db.cursor()
        c.execute('DROP DATABASE {q}{}{q}'.format(database.name, q=self.quote))
        c.execute('CREATE DATABASE {q}{}{q}'.format(database.name, q=self.quote))
        c.execute(self.grant_query.format(name=database.name, user=database.user))
        db.close()
        self.do_restore(database, dump_path)

    def do_restore(self, database, dump_path):
        raise NotImplementedError()

class PostgreSQL(SQLDatabaseEngine):
    id = 'postgresql'
    dump_name = 'postgresql.sql'
    create_user_query = 'CREATE USER "{user}" PASSWORD \'{secret}\''
    grant_query = 'GRANT ALL ON DATABASE "{name}" TO "{user}"'

    def setup(self):
        try:
            import psycopg2
        except ImportError:
            Apt().install({'postgresql', 'python3-psycopg2'}, None)
            subprocess.call(['sudo', '-u', 'postgres', 'psql', '-c',
                             'CREATE USER {} WITH SUPERUSER'.format(os.environ['USER'])])

    def connect(self):
        import psycopg2
        return psycopg2.connect(database='postgres')

    def dump(self, database, path):
        check_call(['pg_dump', '-O', '-f', os.path.join(path, self.dump_name), database.name])

    def do_restore(self, database, dump_path):
        # NOTE: I cannot use -1, because there are errors about plpgsql

        env = dict(os.environ)
        env['PGPASSWORD'] = database.secret
        check_call(['psql', '-h', 'localhost', '-f', dump_path, database.name, database.user],
                   env=env)

_MYSQL_CNF_TEMPLATE = """\
[client]
user = root
password = {pw}
"""

class MySQL(SQLDatabaseEngine):
    id = 'mysql'
    dump_name = 'mysql.sql'
    create_user_query = 'CREATE USER "{user}" IDENTIFIED BY "{secret}"'
    grant_query = 'GRANT ALL ON `{name}`.* TO "{user}"'
    quote = '`'

    def setup(self):
        try:
            import mysql
        except ImportError:
            pw = randstr()
            check_call([
                'sudo', 'sh', '-c',
                'echo mysql-server mysql-server/root_password password {} | debconf-set-selections'.format(pw)])
            check_call([
                'sudo', 'sh', '-c',
                'echo mysql-server mysql-server/root_password_again password {} | debconf-set-selections'.format(pw)])
            Apt().install({'default-mysql-server', 'python3-mysql.connector'}, None)
            with open(os.path.expanduser('~/.my.cnf'), 'w') as f:
                f.write(_MYSQL_CNF_TEMPLATE.format(pw=pw))

    def connect(self):
        from mysql import connector
        # XXX in v2 we can use the .my.cnf file:
        #return connector.connect(option_files=os.path.expanduser('~/.my.cnf'))
        password = list(open(os.path.expanduser('~/.my.cnf')))[2].split()[2]
        return connector.connect(user='root', password=password)

    def dump(self, database, path):
        with open(os.path.join(path, self.dump_name), 'w') as f:
            check_call(['mysqldump', database.name], stdout=f)

    def do_restore(self, database, dump_path):
        with open(dump_path) as f:
            check_call(['mysql', database.name], stdin=f)

class Redis(DatabaseEngine):
    id = 'redis'
    dump_name = 'redis.rdb'

    def __init__(self, get_redis_databases):
        super().__init__()
        self.get_redis_databases = get_redis_databases

    def setup(self):
        # FIXME: Fails for Python apps that install redis-py as dependency. We should check
        # explicitly if the server is installed.
        try:
            import redis
        except ImportError:
            Apt().install({'redis-server', 'python3-redis'}, None)

    def create(self, name, secret):
        taken = {int(d.name) for d in self.get_redis_databases()}
        free = set(range(8, 15)) - taken
        if not free:
            # TODO: what to do here?
            raise ValueError()
        # TODO: order somehow?
        return Database(self.id, free.pop(), None, secret)

    def delete(self, database):
        # NOTE: we could flush the db
        pass

    def dump(self, database, path):
        from redis import StrictRedis
        r = StrictRedis()
        r.save()
        # XXX: compatibility with non systemd, remove again
        # FIXME: /var/lib/redis is not readable and accessable
        check_call(['sudo', 'chmod', 'o+r', '/var/lib/redis/dump.rdb'])
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

class Extension:
    def __init__(self, url, app, wam):
        self._app_id = app
        self.url = url
        self.wam = wam

    @property
    def id(self):
        return reponame(self.url)

    @property
    def app(self):
        return self.wam.apps[self._app_id]

    @property
    def path(self):
        return os.path.join(self.app.path, self.app.meta['extension_path'], self.id)

    def set_url(self, url):
        # NOTE at the moment, one cannot change the repo name in the URL. later maybe store id as
        # own field (automatically retrieved from url when ext is added), and make any url possible.
        if reponame(url) != self.id:
            raise ValueError('reponame') # TODO
        # TODO implement new url, something like git remote set-url
        self.url = url
        self.app._update_repo(self.path, self.url)
        self.wam.store()

    def json(self):
        return {
            'url': self.url,
            'app': self._app_id
        }

def reponame(url):
    return os.path.splitext(os.path.basename(os.path.abspath(urlparse(url).path)))[0]

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
class ProtectExtension:
    def __init__(self, manager):
        self.manager = manager

    def protect(self, app, user, pw):
        if app.url.path:
            raise ValueError('app_url_not_root')

        from crypt import crypt
        x = '{}:{}'.format(user, crypt(pw))
        with open(self._get_auth_path(app), 'w') as f:
            f.write(x)
        self.manager.nginx.configure()

    def unprotect(self, app):
        trash(self._get_auth_path(app))
        self.manager.nginx.configure()

    def get_nginx_server_config(self, app):
        path = self._get_auth_path(app)
        if os.path.isfile(path):
            return _NGINX_PROTECT_TEMPLATE.format(id=app.id, auth_path=os.path.abspath(path))
        return None

    #def get_nginx_proxy_config(self, app):
    #    if os.path.isfile(self._get_auth_path(app)):
    #        return '        proxy_set_header X-Forwarded-For 127.0.0.1;'
    #    return None

    def _get_auth_path(self, app):
        return os.path.join(self.manager.ext_path, 'protect', app.id)

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

def trash(path):
    os.rename(path, '/tmp/{}.{}'.format(os.path.basename(path), randstr()))

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

    def list_cmd(manager):
        for app in sorted(manager.apps.values(), key=lambda a: a.id):
            print('* {} [{}]{}'.format(app.id, 'running' if app.is_running else 'stopped',
                                       ' [\u03bb{}]'.format(app.branch) if app.branch else ''))

    def update_cmd(manager):
        manager.update()

    def start_cmd(manager):
        manager.startx()

    def stop_cmd(manager):
        manager.stop()

    def app_update_cmd(manager, app_id, **opts):
        app = manager.apps[app_id]
        app.update(**opts)

    cmd = subparsers.add_parser(
        'app-update',
        description="""Update the app.""")
    cmd.set_defaults(run=app_update_cmd)
    cmd.add_argument('app_id', help='App ID.')
    cmd.add_argument('--branch', help='TODO.')

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

    def app_list_extensions_cmd(manager, app_id):
        app = manager.apps[app_id]
        for ext in sorted(app.extensions.values(), key=lambda e: e.id):
            print('* {} ({})'.format(ext.id, ext.url))

    cmd = subparsers.add_parser('app-list-extensions', description='TODO')
    cmd.set_defaults(run=app_list_extensions_cmd)
    cmd.add_argument('app_id', help='App ID.')

    def app_add_extension_cmd(manager, app_id, extension_id):
        app = manager.apps[app_id]
        app.add_extension(extension_id)
        print('Note that some extensions require an update of the application.')

    def app_remove_extension_cmd(manager, app_id, extension_id):
        app = manager.apps[app_id]
        app.remove_extension(app.extensions[extension_id])

    def extension_set_url_cmd(manager, app_id, extension_id, url):
        app = manager.apps[app_id]
        ext = app.extensions[extension_id]
        ext.set_url(url)

    cmd = subparsers.add_parser('extension-set-url', description='TODO')
    cmd.set_defaults(run=extension_set_url_cmd)
    cmd.add_argument('app_id', help='App ID.')
    cmd.add_argument('extension_id', help='Extension ID.')
    cmd.add_argument('url', help='TODO.')

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
        'list',
        description="""List all apps.""")
    cmd.set_defaults(run=list_cmd)

    cmd = subparsers.add_parser(
        'update',
        description="""Update all apps.""")
    cmd.set_defaults(run=update_cmd)

    cmd = subparsers.add_parser(
        'start',
        description="""Start all apps.""")
    cmd.set_defaults(run=start_cmd)

    cmd = subparsers.add_parser(
        'stop',
        description="""Stop all apps.""")
    cmd.set_defaults(run=stop_cmd)

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

    cmd = subparsers.add_parser('app-add-extension', description='TODO')
    cmd.set_defaults(run=app_add_extension_cmd)
    cmd.add_argument('app_id', help='App ID.')
    cmd.add_argument('extension_id', help='TODO')

    cmd = subparsers.add_parser('app-remove-extension', description='TODO')
    cmd.set_defaults(run=app_remove_extension_cmd)
    cmd.add_argument('app_id', help='App ID.')
    cmd.add_argument('extension_id', help='TODO')

    def protect_app_cmd(manager, app_id, user, password):
        ext = ProtectExtension(manager)
        app = manager.apps[app_id]
        ext.protect(app, user, password)
    cmd = subparsers.add_parser('protect-app', description='TODO')
    cmd.set_defaults(run=protect_app_cmd)
    cmd.add_argument('app_id', help='App ID.')
    cmd.add_argument('user', help='TODO.')
    cmd.add_argument('password', help='TODO.')

    def unprotect_app_cmd(manager, app_id):
        ext = ProtectExtension(manager)
        app = manager.apps[app_id]
        ext.unprotect(app)
    cmd =subparsers.add_parser('unprotect-app', description='TODO.')
    cmd.set_defaults(run=unprotect_app_cmd)
    cmd.add_argument('app_id', help='App ID.')

    args = vars(parser.parse_args())
    #print(args)

    verbose = args.pop('verbose', False)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level)

    # TODO: Handle errors
    from configparser import ConfigParser
    config = ConfigParser()
    config.read('.wam.conf')

    manager = WebAppManager(config=dict(config['wam']))
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
