#!/usr/bin/env python3

"""wam!"""

import sys
import os
import json
import subprocess
import logging
from subprocess import CalledProcessError
from shutil import make_archive
from random import choice
from string import ascii_lowercase
from re import sub
from os import path, mkdir
from errno import ENOENT

# TODO: Implement config parsing

APPS_PATH = '/var/www/wam'
STORE_PATH = os.path.join(APPS_PATH, 'wam.json')
DATA_PATH = APPS_PATH
EXT_PATH = os.path.join(DATA_PATH, 'ext')

class WebAppManager:
    """
    Attributes:

     * `apps`
    """

    def __init__(self):
        self.apps = {}
        self.server = WebServer(self)
        self.cron = Cron(self)

    def start(self):
        data = []
        try:
            with open(STORE_PATH) as f:
                data = json.load(f)
        except IOError as e:
            if e.errno != ENOENT:
                raise

        for app in data:
            app['jobs'] = dict(
                (j['id'], Job(manager=self, **j)) for j in app['jobs'])
        self.apps = dict((a['id'], App(wam=self, **a)) for a in data)

    def add(self, software_id, url):
        """
        add / activate instance of app at url.
        `app_id` is an identifier, either known to system or an webapp meta file or
        an HTTP URL pointing to a webapp meta file
        """

        logging.info('adding %s...', url)
        secret = randstr()
        app = App(url, software_id, secret, {}, self)
        self.apps[app.id] = app
        mkdir(app.path)
        self.server.configure()
        self.store()

        try:
            app.setup()
        except CalledProcessError as e:
            logger.error('app setup failed, rolling back')
            self.remove(app)
            return

    def remove(self, app):
        # TODO: include app.backup()
        logging.info('removing %s...', app.id)
        try:
            app.cleanup()
        except CalledProcessError as e:
            logger.error('app cleanup failed, continuing removal')
        os.rename(app.path, '/tmp/wam.backup.{}'.format(randstr()))
        del self.apps[app.id]
        self.server.configure()
        self.store()

    def store(self):
        with open(STORE_PATH, 'w') as f:
            json.dump([a.json() for a in self.apps.values()], f)

class App:
    def __init__(self, id, software_id, secret, jobs, wam):
        self.id = id
        self.software_id = software_id
        self.secret = secret
        self.jobs = jobs
        self.wam = wam
        self._cookies = CookieJar()

    @property
    def sid(self):
        return sub('[\./]', '_', self.id)

    @property
    def path(self):
        return os.path.join(APPS_PATH, self.sid)

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
        return os.path.join(DATA_PATH, 'ssl', self.id + '.crt')

    @property
    def certificate_key_path(self):
        return os.path.join(DATA_PATH, 'ssl', self.id + '.key')

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
        csr_path = os.path.join(DATA_PATH, 'ssl', self.id + '.csr')
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
        logging.info('creating a backup of %s...', self.id)
        try:
            self._call('backup')
        except CalledProcessError as e:
            raise ValueError('user_script') # TODO: own error
        # TODO: replace id with timestamp
        # TODO: other directory (e.g. var/www/wam/backup)?
        make_archive('/tmp/wam.backup.{}.{}'.format(self.sid, randstr()),
                     'gztar', APPS_PATH, self.sid, verbose=2)

    def update(self):
        self.backup()
        logging.info('updating %s...', self.id)
        self._call('update')

    def cleanup(self):
        self._call('cleanup')

    def schedule(self, cmd, time):
        job = Job(randstr(), cmd, time, self.wam)
        self.jobs[job.id] = job
        self.wam.cron.configure()
        self.wam.store()
        return job

    def unschedule(self, job):
        del self.jobs[job.id]
        self.wam.cron.configure()
        self.wam.store()

    def _call(self, op):
        os.environ['WAM_APP_ID'] = self.id
        try:
            call('./{} {}'.format(self.software_id, op))
        #except CalledProcessError as e:
        #    print('TODO: ROLLBACK')
        #    raise
        finally:
            del os.environ['WAM_APP_ID']

    def create_db(self, engine):
        db = self._connect_db(engine)
        logging.info('creating database...')
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
        logging.info('deleting database...')
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
        logging.info('requesting {}...'.format(url))
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
            (a, getattr(self, a)) for a in ['id', 'software_id', 'secret'])
        json['jobs'] = [j.json() for j in self.jobs.values()]
        return json

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
        logging.info('configuring Apache httpd...')
        hosts = []
        for app in wam.apps.values():
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
        return os.path.join(EXT_PATH, 'protect/htpasswd')

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

    logging.basicConfig(level=logging.DEBUG)
    manager = WebAppManager()
    manager.start()

    app_id = os.environ['WAM_APP_ID']
    app = manager.apps[app_id]

    script = sys.modules['__main__']
    f = getattr(script, args.command)
    f(app)

def call(cmd):
    subprocess.check_call(cmd, shell=True)

def randstr(length=16, charset=ascii_lowercase):
    return ''.join(choice(charset) for i in xrange(length))

# main

if __name__ == '__main__':
    # TODO: parse args, execute command
    if os.getuid() != 33:
        print('run as www-data, please')
        sys.exit()

    logging.basicConfig(level=logging.DEBUG)
    wam = WebAppManager()
    wam.start()

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
