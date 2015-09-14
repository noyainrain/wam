# wam!

"""test"""

import os
import json
from tempfile import NamedTemporaryFile, mkdtemp, mktemp
from subprocess import CalledProcessError, call, check_call
from contextlib import contextmanager
from shutil import copyfile
from unittest import TestCase
from wam import WebAppManager, Apt, Bundler, Bower, PostgreSQL, Database, ScriptError

RES_PATH = os.path.join(os.path.dirname(__file__), 'res')

class WamTestCase(TestCase):
    def setUp(self, **args):
        d = mktemp()
        #print(d)
        #os.mkdir(d)
        #d = mkdtemp()
        config = {'data_path': d}
        args.setdefault('nginx_config_path', '/tmp/wam.conf')

        self.manager = WebAppManager(config=config, **args)
        self.manager.start()

    def tearDown(self):
        for app in list(self.manager.apps.values()):
            self.manager.remove(app)

    @contextmanager
    def tmp_app(self, meta={}):
        with tmp_software(meta) as software_id:
            app = self.manager.add(software_id, 'localhoax')
            yield app

def process_exists(pid):
    try:
        os.kill(pid, 0)
        return True
    except PermissionError as e:
        print(e)
        return True
    except ProcessLookupError as e:
        print(e)
        return False

class WebAppManagerTest(WamTestCase):
    def test_add(self):
        with tmp_software({}) as software_id:
            app = self.manager.add(software_id, 'localhost')
            self.assertTrue(self.manager.port_range[0] <= app.port <= self.manager.port_range[1])

    def test_add_script_broken(self):
        with tmp_software({'hooks': '/bin/false'}) as software_id:
            with self.assertRaises(ScriptError):
                self.manager.add(software_id, 'localhost')
            self.assertFalse(self.manager.apps)

    def test_add_script_broken_no_rollback(self):
        with tmp_software({'hooks': '/bin/false'}) as software_id:
            with self.assertRaises(ScriptError):
                self.manager.add(software_id, 'localhost', rollback=False)
            self.assertTrue(self.manager.apps)

class AppTest(WamTestCase):
    # TODO: test doesnt work anymore because setup now creates datadirs....
    #def test_clone(self):
    #    # TODO: assert somehow
    #    # TODO: Also test single branch
    #    #self.app.clone('https://github.com/NoyaInRain/wam.git')
    #    self.app.clone('.')

    #def test_clone_branch(self):
    #    #self.app.clone('https://github.com/NoyaInRain/wam.git#master')
    #    self.app.clone('.#master')

    def setUp(self):
        super().setUp()
        self.app = self.manager.add('res/test.json', 'localhost')

    def test_start_stop(self):
        meta = {'jobs': ['sleep 42']}
        with self.tmp_app(meta) as app:
            app.start()
            self.assertTrue(app.pids)
            job = list(app.pids)[0]
            self.assertTrue(process_exists(job))
            app.stop()
            self.assertFalse(app.pids)
            #self.assertFalse(process_exists(job))

    def test_start_job(self):
        job = self.app.start_job('sleep 42')
        self.assertTrue(process_exists(job))
        self.assertIn(job, self.app.pids)

    def test_stop_job(self):
        job = self.app.start_job('sleep 42')
        self.app.stop_job(job)
        self.assertNotIn(job, self.app.pids)
        # TODO: why does this not work?
        #self.assertFalse(process_exists(job))

    def test_stop_job_job_dead(self):
        job = self.app.start_job('true')
        self.app.stop_job(job)

    def test_stop_all_jobs(self):
        self.app.start_job('sleep 42')
        self.app.stop_all_jobs()
        self.assertFalse(self.app.pids)

    def test_update_code(self):
        with self.tmp_app({'download': '.'}) as app:
            self.assertTrue(os.path.isfile(os.path.join(app.path, 'wam.py')))

    def test_update_code_repo_exists(self):
        with self.tmp_app({'download': '.'}) as app:
            # NOTE: better test would be to commit something and then test if it is fetched
            app.update()

    #def test_install(self):
    #    self.app.install('apt', {'python3-yapsy'})
    #    self.assertIn('python3-yapsy', self.app.installed_packages['apt'])

    def test_update_packages(self):
        meta = {
            'name': 'test',
            'packages': {
                'apt': ['python3-yapsy']
            }
        }
        with self.tmp_app(meta) as app:
            self.assertIn('python3-yapsy', app.installed_packages['apt'])

    def test_update_databases(self):
        with self.tmp_app({'databases': ['postgresql']}) as app:
            self.assertTrue(app.databases)
            self.assertEqual(list(app.databases)[0].engine, 'postgresql')

    def test_update_data_dirs(self):
        dirs = {'a': 33, 'b': 33}
        meta = {
            "data_dirs": ["a", "b"]
        }
        with self.tmp_app(meta) as app:
            self.assertEqual(app.data_dirs, {'a', 'b'})
            for path, uid in dirs.items():
                self.assertEqual(os.stat(os.path.join(app.path, path)).st_uid, uid)

    def test_update_data_dirs_changed(self):
        # XXX what an ugly hack... please add a cool way to update software meta
        # file
        self.app._software_meta = json.loads('{"data_dirs": ["b", "c"]}')
        dirs = {'a': os.geteuid(), 'b': 33, 'c': 33}

        self.app.update()
        self.assertEqual(self.app.data_dirs, {'b', 'c'})
        for path, uid in dirs.items():
            self.assertEqual(os.stat(os.path.join(self.app.path, path)).st_uid,
                             uid)

    def test_backup(self):
       with self.tmp_app({'databases': ['postgresql'], 'data_dirs': ['a', 'b']}) as app:
           check_call(['sudo', '-u', app.job_user, 'cp', os.path.join(RES_PATH, 'test.json'),
                       os.path.join(app.path, 'a/test.json')])
           backup = app.backup()
           self.assertTrue(os.path.isfile(os.path.join(backup, PostgreSQL.dump_name)))
           self.assertTrue(os.path.isfile(os.path.join(backup, 'a/test.json')))

@contextmanager
def tmp_software(meta):
    with NamedTemporaryFile(mode='w') as f:
        json.dump(meta, f)
        f.flush()
        yield f.name

class AppDatabaseTest(WamTestCase):
    def setUp(self):
        super().setUp()
        self.app = self.manager.add('res/test.json', 'localhost')
        try:
            self.database = self.app.create_database('postgresql')
        except:
            # if create_database dies half way through, remove it
            self.manager._database_engines['postgresql'].delete(Database(
                'postgresql', self.app.sid, self.app.dbuser, self.app.secret))
            raise

    def tearDown(self):
        super().tearDown()
        self.manager._database_engines['postgresql'].delete(self.database)

    def test_create_database(self):
        #database = self.app.create_database('postgresql')
        self.assertIn(self.database, self.app.databases)

    def test_delete_database(self):
        self.app.delete_database(self.database)
        self.assertNotIn(self.database, self.app.databases)

    def test_delete_all_databases(self):
        self.app.delete_all_databases()
        self.assertFalse(self.app.databases)

class NginxTest(WamTestCase):
    def test_configure(self):
        with self.tmp_app():
            self.manager.nginx.configure()
            self.assertFalse(call(['sudo', 'nginx', '-c', os.path.abspath('res/nginx.conf'),
                                   '-t']))

#class PackageEngineTestMixin:
#    def test_install(self):
#       self.engine.install({}, self.app)

class AptTest(TestCase):
    def test_install(self):
        app_path = mkdtemp()
        apt = Apt()
        # most unpopular Python3 Debian package
        # http://popcon.debian.org/stable/main/by_inst
        apt.install({'python3-yapsy'}, app_path)

class BundlerTest(TestCase):
    def test_install(self):
        app_path = mkdtemp()
        copyfile(os.path.join(RES_PATH, 'Gemfile'), os.path.join(app_path, 'Gemfile'))
        bundler = Bundler()
        bundler.install({}, app_path)

class BowerTest(TestCase):
    def test_install(self):
        app_path = mkdtemp()
        copyfile(os.path.join(RES_PATH, 'bower.json'), os.path.join(app_path, 'bower.json'))
        bower = Bower()
        bower.install({}, app_path)
        self.assertTrue(os.path.isdir(os.path.join(app_path, 'bower_components/jquery')))

class DatabaseEngineTestMixin:
    def setUp(self, engine):
        self.engine = engine

    def test_create(self):
        # Implicitly tests connect() and delete()
        try:
            database = self.engine.create('litterbox', 'cat', 'purr')
        finally:
            self.engine.delete(
                Database('postgresql', 'litterbox', 'cat', 'purr'))

    def test_dump(self):
        d = mkdtemp()
        #print(d)
        try:
            database = self.engine.create('litterbox', 'cat', 'purr')
            self.engine.dump(database, d)
            self.assertTrue(os.path.isfile(os.path.join(d, self.engine.dump_name)))
        finally:
            self.engine.delete(
                Database(self.engine.id, 'litterbox', 'cat', 'purr'))

class PostgreSQLTest(TestCase, DatabaseEngineTestMixin):
    def setUp(self):
        DatabaseEngineTestMixin.setUp(self, PostgreSQL())

class RedisTest(WamTestCase, DatabaseEngineTestMixin):
    def setUp(self):
        super().setUp()
        DatabaseEngineTestMixin.setUp(self,
                                      self.manager._database_engines['redis'])
