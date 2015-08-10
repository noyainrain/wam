#!/usr/bin/env python3

import os
import wam

def setup(app):
    app.clone('https://github.com/humhub/humhub.git')
    app.create_db('mysql')

    search = 'value="([^"]*)" name="CSRF_TOKEN"'
    token = app.request('index.php?r=installer/setup/database',
                        search=search)[0]

    data = {
        'CSRF_TOKEN': token,
        'DatabaseForm[hostname]': 'localhost',
        'DatabaseForm[username]': app.dbuser,
        'DatabaseForm[password]': app.secret,
        'DatabaseForm[database]': app.sid,
        'yt0': 'Next'
    }
    token = app.request('index.php?r=installer/setup/database', data, search)[0]

    data = {
        'CSRF_TOKEN': token,
        'ConfigBasicForm[name]': app.id,
        'yt0': 'Next'
    }
    token = app.request('index.php?r=installer/config/basic', data, search)[0]

    data = {
        'CSRF_TOKEN': token,
        'yform_7323618': '1',
        'User[username]': app.wam.user,
        'User[email]': app.wam.email,
        'UserPassword[newPassword]': app.wam.pw,
        'UserPassword[newPasswordConfirm]': app.wam.pw,
        'Profile[firstname]': app.wam.user,
        'Profile[lastname]': 'X',
        'save': 'Create Admin Account'
    }
    # TODO: search for success term
    app.request('index.php?r=installer/config/admin', data)

    # TODO: configure E-Mail sender address service@humhub.inrain.org
    # TODO: configure lang from wam setting
    # Anzeigename (Format) -> nick

    # TODO: urlrewriting
    # https://github.com/humhub/humhub/blob/master/protected/docs/guide/administration/installation.md

    yiic = os.path.join(app.path, 'protected/yiic')
    app.schedule('{} cron hourly >/dev/null 2>&1'.format(yiic),
                 ('30', '*', '*', '*', '*'))
    app.schedule('{} cron daily >/dev/null 2>&1'.format(yiic),
                 ('0', '18', '*', '*', '*'))

def backup(app):
    app.backup_db('mysql')

def update(app):
    app.pull()
    wam.call('{} update --interactive=0'.format(
        os.path.join(app.path, 'protected/yiic')))

def cleanup(app):
    app.delete_db('mysql')

"""CREATE DATABASE `humhub` CHARACTER SET utf8 COLLATE utf8_general_ci;
GRANT ALL ON `humhub`.* TO `humhub_dbuser`@localhost IDENTIFIED BY
'password_changeme';
FLUSH PRIVILEGES;"""

if __name__ == '__main__':
    wam.run_app_script()
