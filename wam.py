#!/usr/bin/env python3

"""wam!"""

import sys
import os
import json
import subprocess
import logging
from subprocess import CalledProcessError, check_call
from shutil import make_archive
from random import choice
from string import ascii_lowercase
from re import sub
from os import path, mkdir
from errno import ENOENT

# TODO: Implement config parsing

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
    """

    def __init__(self, config={}):
        self.config = {
            'data_path': '/var/www/wam'
        }
        self.config.update(config)

        self.data_path = self.config['data_path']
        self.store_path = os.path.join(self.data_path, 'wam.json')
        self.ext_path = os.path.join(self.data_path, 'ext')

        self.apps = {}
        self.server = WebServer(self)
        self.cron = Cron(self)
        self.logger = logging.getLogger('wam')
        self._logger = self.logger

    def start(self):
        self.apps = self.load()['apps']

    def load(self):
        # XXX
        data = {'apps': {}}
        try:
            with open(self.store_path) as f:
                data = json.load(f, object_hook=self._decode)
            self._logger.debug('Loaded %s', data)
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
                types = {'App': App, 'Job': Job}
                return types[type](wam=self, **json)
        else:
            return json

    def add(self, software_id, url):
        """
        add / activate instance of app at url.
        `app_id` is an identifier, either known to system or an webapp meta file or
        an HTTP URL pointing to a webapp meta file
        """

        self._logger.info('Adding %s', url)
        secret = randstr()
        app = App(url, software_id, secret, {}, {}, self)
        self.apps[app.id] = app
        mkdir(app.path)
        self.server.configure()
        self.store()

        try:
            app.setup()
            return app
        except CalledProcessError as e:
            self.logger.error('app setup failed, rolling back')
            self.remove(app)
            raise

    def remove(self, app):
        # TODO: include app.backup()
        self._logger.info('Removing %s', app.id)
        try:
            app.cleanup()
        except CalledProcessError as e:
            self.logger.error('app cleanup failed, continuing removal')
        os.rename(app.path, '/tmp/wam.backup.{}'.format(randstr()))
        del self.apps[app.id]
        self.server.configure()
        self.store()

    def json(self):
        #return {'apps': {i: a.json() for i, a in self.apps.items()}}
        return {'apps': self.apps}

    def store(self):
        j = json.dumps(self.json(), default=self._encode)
        self._logger.debug('Storing %s', j)
        with open(self.store_path, 'w') as f:
            #json.dump(j, f)
            f.write(j)

class App:
    """Web applicaton.

    Attributes:

    * `id`
    * `software_id`
    * `secret`
    * `installed_packages`
    * `jobs`
    * `manager`
    """

    def __init__(self, id, software_id, secret, jobs, installed_packages, wam):
        self.id = id
        self.software_id = software_id
        self.secret = secret
        self.installed_packages = installed_packages
        self.jobs = jobs
        self.wam = wam
        self.manager = wam
        self._logger = logging.getLogger('wam')
        self._cookies = CookieJar()

    @property
    def sid(self):
        return sub('[\./]', '_', self.id)

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
        self.wam.server.configure()

    def setup(self):
        """
        should setup
         * config
         * datastores (db, directories)
        """
        self._call('setup')

    def backup(self):
        # TODO: app settings should also be backed up, so a wam app can be
        # restored just by selecting a .tar.gz file
        self._logger.info('creating a backup of %s...', self.id)
        try:
            self._call('backup')
        except CalledProcessError as e:
            raise ValueError('user_script') # TODO: own error
        # TODO: replace id with timestamp
        # TODO: other directory (e.g. var/www/wam/backup)?
        make_archive('/tmp/wam.backup.{}.{}'.format(self.sid, randstr()),
                     'gztar', self.wam.config['data_path'], self.sid, verbose=2)

    def update(self):
        self.backup()
        self._logger.info('updating %s...', self.id)
        self._call('update')

    def cleanup(self):
        self._call('cleanup')
        self.uninstall_all()

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
        os.environ['WAM_DATA_PATH'] = self.manager.data_path
        os.environ['WAM_APP_ID'] = self.id
        if self._logger.getEffectiveLevel() == logging.DEBUG:
            os.environ['WAM_VERBOSE'] = '1'

        try:
            self._logger.debug('ENTERING SUBPROCESS for %s', op)
            check_call([self.software_id, op])
            #call('./{} {}'.format(self.software_id, op))
            self._logger.debug('EXITING SUBPROCESS for %s', op)

            # Reload all data that may be modified by app script
            data = self.manager.load()
            copy = data['apps'][self.id]
            self.installed_packages = copy.installed_packages
            for id in self.jobs.keys() - copy.jobs.keys():
                self._logger.debug('Cron job %s removed by app script', id)
                del self.jobs[id]
            for id in copy.jobs.keys() - self.jobs.keys():
                self._logger.debug('Cron job %s added by app script', id)
                self.jobs[id] = copy.jobs[id]

        except CalledProcessError as e:
            print('TODO: ROLLBACK')
            raise
        finally:
            del os.environ['WAM_DATA_PATH']
            del os.environ['WAM_APP_ID']
            os.environ.pop('WAM_VERBOSE', None)

    def install(self, engine, packages={'auto'}):
        """Install a set of `packages` with `engine`."""
        self._logger.info('Installing %s', packages)
        # TODO: validate packages somehow?
        auto = 'auto' in packages
        pkgs = list(packages - {'auto'})
        if engine == 'system':
            # ignore auto, not supported
            if pkgs:
                check_call(['sudo', 'apt-get', '-y', 'install'] + pkgs)
        elif engine == 'bundler':
            if auto:
                check_call(['bundle', 'install', '--deployment'])
            # TODO: Implement non-auto?
        else:
            raise ValueError('engine_unknown')

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

    def create_db(self, engine):
        db = self._connect_db(engine)
        self._logger.info('creating database...')
        #sql = _create_db_template.format(name=self.id, pw=self.secret)
        c = db.cursor()
        # TODO why does this not work with ?
        c.execute('CREATE USER {}'.format(self.dbuser))
        c.execute('CREATE DATABASE {}'.format(self.sid))
        # mysql specific??
        c.execute("GRANT ALL ON {}.* TO {} IDENTIFIED BY '{}'".format(self.sid, self.dbuser, self.secret))
        db.close()

    def delete_db(self, engine):
        # XXX TODO: backup to local dir
        db = self._connect_db(engine)
        self._logger.info('deleting database...')
        c = db.cursor()
        if engine == 'mysql':
            from mysql.connector import OperationalError
        try:
            user = self.sid[:16]
            c.execute('DROP USER {}'.format(self.dbuser))
        except OperationalError as e:
            # user does not exist, ignore
            pass
        c.execute('DROP DATABASE IF EXISTS {}'.format(self.sid))
        db.close()

    def backup_db(self, engine):
        if engine == 'mysql':
            call('mysqldump -u {} -p{} {} > {}'.format(
                self.dbuser, self.secret, self.sid,
                os.path.join(self.path, 'dump.sql')))
        else:
            raise ValueError('engine_unknown')

    def _connect_db(self, engine):
        if engine == 'mysql':
            #from getpass import getpass
            #print('please enter MySQL root password')
            #pw = getpass()
            from mysql import connector
            db = connector.connect(user='root',
                                   password=self.config['mysql_password'])
        else:
            raise ValueError('engine_unknown')
        return db

    def clone(self, url):
        call('git clone {} {}'.format(url, self.path))

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
        json = dict(
            (a, getattr(self, a)) for a
            in ['id', 'software_id', 'secret', 'jobs', 'installed_packages'])
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

class WebServer:
    def __init__(self, wam):
        self.wam = wam

    def configure(self):
        # TODO: implement nginx
        return

        self._logger.info('configuring Apache httpd...')
        hosts = []
        for app in self.wam.apps.values():
            port = 80
            ssl = ''
            if app.encrypted:
                ssl = SERVER_SSL_TEMPLATE.format(
                    certificate_path=app.certificate_path,
                    certificate_key_path=app.certificate_key_path)
                port = 443

            # extensions
            more = ''
            x = ProtectApp(app)
            if x.protected:
                more = SERVER_PW_TEMPLATE.format(path=app.path, id=app.id,
                                                 htpasswd_path=x.htpasswd_path)

            hosts.append(SERVER_HOST_TEMPLATE.format(
                port=port, host=app.id, path=app.path, ssl=ssl, more=more))
        with open(SERVER_CONFIG_PATH, 'w') as f:
            f.write('\n'.join(hosts))
        call('sudo /usr/sbin/service apache2 reload')

# TODO: wam logfile
SERVER_HOST_TEMPLATE = """\
<VirtualHost *:{port}>
    ServerName {host}
    ServerAlias www.{host}
    DocumentRoot {path}

    {ssl}

    {more}
</VirtualHost>
"""

SERVER_SSL_TEMPLATE = """\
    SSLEngine on
    SSLCertificateFile {certificate_path}
    SSLCertificateKeyFile {certificate_key_path}
"""

SERVER_PW_TEMPLATE = """\
    <Directory {path}>
        AuthType Basic
        AuthName {id}
        AuthUserFile {htpasswd_path}
        Require valid-user
    </Directory>
"""

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
        call('htpasswd -bc {} "" {}'.format(self.htpasswd_path, pw))
        self.manager.server.configure()

# utilities

from argparse import ArgumentParser

def run_app_script():
    parser = ArgumentParser()
    parser.add_argument('command', choices=['setup', 'backup', 'update', 'cleanup'])
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
        f(app)
    except AttributeError:
        pass

def call(cmd):
    subprocess.check_call(cmd, shell=True)

def randstr(length=16, charset=ascii_lowercase):
    return ''.join(choice(charset) for i in range(length))

# main

if __name__ == '__main__':
    # TODO: parse args
    if os.getuid() != 33:
        print('run as www-data, please')
        sys.exit()

    logging.basicConfig(level=logging.DEBUG)
    wam = WebAppManager()
    wam.start()

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
