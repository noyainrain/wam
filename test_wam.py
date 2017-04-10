# wam!

"""test"""

import os
import json
from tempfile import NamedTemporaryFile, mkdtemp, mktemp
from subprocess import CalledProcessError, call, check_call, check_output
from contextlib import contextmanager
from shutil import copyfile
from unittest import TestCase
from wam import WebAppManager, Apt, Pip, Bundler, Bower, PostgreSQL, MySQL, Database, ScriptError

RES_PATH = os.path.join(os.path.dirname(__file__), 'res')

# XXX
#import logging
#logging.basicConfig(level=logging.INFO)

class WamTestCase(TestCase):
    def setUp(self, **args):
        d = mktemp()
        #print(d)
        #os.mkdir(d)
        #d = mkdtemp()
        config = {'data_path': d, 'certbot': False}
        args.setdefault('nginx_config_path', '/tmp/wam.conf')
        args.setdefault('auto_backup', False)

        self.manager = WebAppManager(config=config, **args)
        self.manager.start()

    def tearDown(self):
        for app in list(self.manager.apps.values()):
            self.manager.remove(app)

    @contextmanager
    def tmp_app(self, meta={}, id='localhoax'):
        with tmp_software(meta) as software_id:
            app = self.manager.add(software_id, id)
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

    #def test_install(self):
    #    self.app.install('apt', {'python3-yapsy'})
    #    self.assertIn('python3-yapsy', self.app.installed_packages['apt'])

    def test_update_default_extensions(self):
        with self.tmp_app({'default_extensions': ['.']}) as app:
            self.assertIn('wam', app.extensions)

    def test_update_default_extensions_changed(self):
        with self.tmp_app({'default_extensions': ['.']}) as app:
            with open(app.software_id, 'w') as f:
                f.write('default_extensions: [.#test]')
            del self.manager.meta._cache[app.software_id] #XXX
            app._software_meta = None
            app.update()
            self.assertEqual(app.extensions['wam'].url, '.#test')

    def test_update_stack(self):
        with self.tmp_app({'stack': ['python3']}) as app:
            self.assertEqual(call(['which', 'pip3']), 0)

    def test_update_stack_ruby(self):
        with self.tmp_app({'stack': ['ruby']}) as app:
            self.assertTrue(check_output(['bash', '-c', '. /usr/local/share/chruby/chruby.sh && chruby']))

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
            self.assertEqual(app.databases['postgresql'].engine, 'postgresql')

    def test_update_data_dirs(self):
        meta = {
            'data_dirs': ['a', 'b']
        }
        data_dirs = {'a', 'b'}
        with self.tmp_app(meta) as app:
            self.assertEqual(app.data_dirs, data_dirs)
            for data_dir in data_dirs:
                self.assertEqual(os.stat(os.path.join(app.path, data_dir)).st_uid, 33)

    def test_update_data_dirs_changed(self):
        with self.tmp_app({'data_dirs': ['a', 'b']}) as app:
            with open(app.software_id, 'w') as f:
                f.write('{"data_dirs": ["b", "c"]}')
            # XXX what an ugly hack... please add a cool way to update software meta file
            del self.manager.meta._cache[app.software_id]
            app._software_meta = None

            data_dirs = {'b', 'c'}
            app.update()
            self.assertEqual(app.data_dirs, data_dirs)
            self.assertEqual(os.stat(os.path.join(app.path, 'a')).st_uid, os.getuid())
            for data_dir in data_dirs:
                self.assertEqual(os.stat(os.path.join(app.path, data_dir)).st_uid, 33)

    def test_update_files(self):
        meta = {
            'files': {
                'foo.txt': 'a = {app.id}\nb\nc'
            }
        }
        with self.tmp_app(meta) as app:
            data = open(os.path.join(app.path, 'foo.txt')).read()
            self.assertEqual(data, 'a = localhoax\nb\nc')

    def test_update_hook(self):
        with self.tmp_app({'hook': 'touch foo.txt'}) as app:
            self.assertTrue(os.path.isfile(os.path.join(app.path, 'foo.txt')))

    def test_update_hook_stack_ruby(self):
        with self.tmp_app({'stack': 'ruby', 'hook': 'echo $(chruby) > foo.txt'}) as app:
            with open(os.path.join(app.path, 'foo.txt')) as f:
                self.assertTrue(f.read())

    def test_backup(self):
        with self.tmp_app({'databases': ['postgresql'], 'data_dirs': ['a', 'b']}) as app:
            self._copy_to_data_dir(app, 'test.json', 'a')
            backup = app.backup()
            self.assertTrue(os.path.isfile(os.path.join(backup, PostgreSQL.dump_name)))
            self.assertTrue(os.path.isfile(os.path.join(backup, 'a/test.json')))

    def test_restore(self):
        with self.tmp_app({'databases': ['postgresql'], 'data_dirs': ['a', 'b']}) as app:
            self._copy_to_data_dir(app, 'test.json', 'a')
            backup = app.backup()
            self._copy_to_data_dir(app, 'Gemfile', 'a')
            app.restore(backup)
            self.assertTrue(os.path.isfile(os.path.join(app.path, 'a/test.json')))
            self.assertFalse(os.path.exists(os.path.join(app.path, 'a/Gemfile')))

    def test_add_extension(self):
        with self.tmp_app({'download': '.'}) as app:
            ext = app.add_extension('.')
            self.assertIn(ext.id, app.extensions)
            self.assertTrue(os.path.isfile(os.path.join(ext.path, 'wam.py')))

    def test_remove_extension(self):
        with self.tmp_app({'download': '.'}) as app:
            ext = app.add_extension('.')
            app.remove_extension(ext)
            self.assertNotIn(ext.id, app.extensions)
            self.assertFalse(os.path.exists(ext.path))

    def _copy_to_data_dir(self, app, file, data_dir):
        check_call(['sudo', '-u', app.job_user, 'cp', os.path.join(RES_PATH, file),
                    os.path.join(app.path, data_dir, file)])

class AppUpdateCodeTest(WamTestCase):
    def setUp(self):
        super().setUp()
        self.remote = mkdtemp()
        check_output(['git', 'clone', '-q', '.', self.remote])
        check_output(['git', '-C', self.remote, 'branch', 'test', 'HEAD^'])

    def commit(self, path, text):
        with open(os.path.join(self.remote, path), 'a') as f:
            f.write(text + '\n')
        check_output(['git', '-C', self.remote, 'commit', '-am', 'Add stuff'])

    def test_update_code(self):
        with self.tmp_app({'download': self.remote}) as app:
            self.assertTrue(os.path.isfile(os.path.join(app.path, 'wam.py')))

    def test_update_code_branch(self):
        with self.tmp_app({'download': self.remote}) as app:
            app.update(branch='test')
            self.assertEqual(app.branch, 'test')
            self.assertTrue(os.path.isfile(os.path.join(app.path, 'wam.py')))

    def test_update_code_remote_changes(self):
        with self.tmp_app({'download': self.remote}) as app:
            self.commit('wam.py', '# foo')
            app.update()

    def test_update_code_remote_data_dir_changes(self):
        with self.tmp_app({'download': self.remote, 'data_dirs': ['webapps']}) as app:
            self.commit('webapps/discourse.yaml', '# foo')
            app.update()

    #def test_update_code_local_changes(self):
    #    with self.tmp_app({'download': self.remote}) as app:
    #        self.commit('# foo')
    #        with open(os.path.join(app.path, 'wam.py'), 'a') as f:
    #            f.write('# bar\n')
    #        app.update()

class ExtensionTest(WamTestCase):
    def test_set_url(self):
        with self.tmp_app({'download': '.'}) as app:
            ext = app.add_extension('.')
            ext.set_url('.#test')
            self.assertEqual(ext.url, '.#test')

@contextmanager
def tmp_software(meta):
    with NamedTemporaryFile(mode='w') as f:
        json.dump(meta, f)
        f.flush()
        yield f.name

"""class AppDatabaseTest(WamTestCase):
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
        self.assertFalse(self.app.databases)"""

class NginxTest(WamTestCase):
    def test_configure(self):
        with self.tmp_app(id='localhost'):
            with self.tmp_app(id='localhoax'):
                with self.tmp_app({'mode': 'phpfpm'}, id='localhoax/foo'):
                    self.manager.nginx.configure()
                    self.assertGoodConfig()

    def assertGoodConfig(self):
        if call(['sudo', 'nginx', '-c', os.path.abspath('res/nginx.conf'), '-t']):
            raise AssertionError('bad_nginx_config')

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

class PipTest(TestCase):
    def setUp(self):
        self.pip = Pip()

    def test_install(self):
        self.pip.install({'simplejson'}, '/tmp')

    def test_install_auto(self):
        app_path = mktemp()
        os.mkdir(app_path)
        copyfile(os.path.join(RES_PATH, 'requirements.txt'),
                 os.path.join(app_path, 'requirements.txt'))
        self.pip.install({}, app_path)

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
        self.engine.setup()
        #try:
        self.database = self.engine.create('litterbox', 'secr3t')
        #except:
        #    # If create() fails half way through, clean up
        #    self.engine.delete(Database(self.engine.id, 'litterbox', 'cat', 'secr3t'))
        #    raise

    def tearDown(self):
        self.engine.delete(self.database)

    #def test_create(self):
    #    # Implicitly tests connect()
    #    try:
    #        database = self.engine.create('litterbox2', 'secr3t')
    #    finally:
    #        self.engine.delete(Database(self.engine.id, 'litterbox2', 'cat2', 'secr3t'))

    def test_delete(self):
        self.engine.delete(self.database)

    def test_dump(self):
        d = mkdtemp()
        print(d)
        self.engine.dump(self.database, d)
        self.assertTrue(os.path.isfile(os.path.join(d, self.engine.dump_name)))

    def test_restore(self):
        d = mkdtemp()
        self.engine.dump(self.database, d)
        self.engine.restore(self.database, os.path.join(d, self.engine.dump_name))

class PostgreSQLTest(TestCase, DatabaseEngineTestMixin):
    def setUp(self):
        DatabaseEngineTestMixin.setUp(self, PostgreSQL())

    def tearDown(self):
        DatabaseEngineTestMixin.tearDown(self)

class MySQLTest(TestCase, DatabaseEngineTestMixin):
    def setUp(self):
        DatabaseEngineTestMixin.setUp(self, MySQL())

    def tearDown(self):
        DatabaseEngineTestMixin.tearDown(self)

class RedisTest(WamTestCase, DatabaseEngineTestMixin):
    def setUp(self):
        super().setUp()
        DatabaseEngineTestMixin.setUp(self, self.manager._database_engines['redis'])

    def tearDown(self):
        DatabaseEngineTestMixin.tearDown(self)
        super().tearDown()
