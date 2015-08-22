# wam!

"""test"""

import os
import json
from tempfile import mkdtemp
from shutil import copyfile
from unittest import TestCase
from wam import WebAppManager, Apt, Bundler, PostgreSQL, Database

class WamTestCase(TestCase):
    res_path = os.path.join(os.path.dirname(__file__), 'res')

    def setUp(self):
        d = mkdtemp()
        #print(d)
        self.manager = WebAppManager({'data_path': d})
        self.manager.start()
        self.app = self.manager.add('res/test.py', 'localhost')

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

    def test_install(self):
        self.app.install('apt', {'python3-yapsy'})
        self.assertIn('python3-yapsy', self.app.installed_packages['apt'])

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

    def test_setup(self):
        dirs = {'a': 33, 'b': 33}

        app = self.manager.add('res/test.py', 'localhoax')
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

class AppDatabaseTest(WamTestCase):
    def setUp(self):
        super().setUp()
        try:
            self.database = self.app.create_database('postgresql')
        except:
            # if create_database dies half way through, remove it
            self.manager._database_engines['postgresql'].delete(Database(
                'postgresql', self.app.sid, self.app.dbuser, self.app.secret))
            raise

    def tearDown(self):
        self.manager._database_engines['postgresql'].delete(self.database)
        super().tearDown()

    def test_create_database(self):
        #database = self.app.create_database('postgresql')
        self.assertIn(self.database, self.app.databases)

    def test_delete_database(self):
        self.app.delete_database(self.database)
        self.assertNotIn(self.database, self.app.databases)

    def test_delete_all_databases(self):
        self.app.delete_all_databases()
        self.assertFalse(self.app.databases)

#class PackageEngineTestMixin:
#    def test_install(self):
#       self.engine.install({}, self.app)

class AptTest(WamTestCase):
    def test_install(self):
        apt = Apt()
        # most unpopular Python3 Debian package
        # http://popcon.debian.org/stable/main/by_inst
        apt.install({'python3-yapsy'}, self.app)

class BundlerTest(WamTestCase):
    def test_install(self):
        copyfile(os.path.join(self.res_path, 'Gemfile'),
                 os.path.join(self.app.path, 'Gemfile'))
        bundler = Bundler()
        bundler.install({}, self.app)

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
            self.assertTrue(os.path.isfile(os.path.join(d, 'postgresql.sql')))
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
