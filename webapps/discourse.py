#!/usr/bin/env python3

# see https://github.com/discourse/discourse/blob/master/docs/DEVELOPER-ADVANCED.md

import os
import wam
from wam import call

CONFIG_TEMPLATE = """\
db_host = localhost
db_name = {db_name}
db_username = {db_username}
db_password = {db_password}
hostname = "{hostname}"
redis_db = {redis_db}
serve_static_assets = true
serve_static_files = true
developer_emails = {developer_emails}
"""

# TODO: because it is so short now, convert it to a POSIX shell script

#def setup(app):
def update(app):
    #app.clone('https://github.com/discourse/discourse.git#stable')
    #app.install('apt', {'postgresql-contrib', 'libpq-dev', 'libxml2', 'imagemagick'})
    #app.install('bundler')
    #psql_db = app.create_database('postgresql')
    #redis_db = app.create_database('redis')
    # TODO: make databases accessible by engine
    psql_db = next(d for d in app.databases if d.engine == 'postgresql')
    redis_db = next(d for d in app.databases if d.engine == 'redis')
    call('psql -d {} -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;"'.format(psql_db.name))
    call('psql -d {} -c "CREATE EXTENSION IF NOT EXISTS hstore;"'.format(psql_db.name))
    config = CONFIG_TEMPLATE.format(
        db_name=psql_db.name, db_username=psql_db.user,
        db_password=psql_db.secret, hostname=app.id, redis_db=redis_db.name,
        developer_emails=app.manager.config['email'])
    with open(os.path.join(app.path, 'config/discourse.conf'), 'w') as f:
        f.write(config)
    gemfile = os.path.join(app.path, 'Gemfile')
    rakefile = os.path.join(app.path, 'Rakefile')
    # TODO: just use check_call here
    call('sudo -u {} BUNDLE_GEMFILE={} RAILS_ENV=production bundle exec rake -f {} db:migrate'.format(app.job_user, gemfile, rakefile))
    call('sudo -u {} BUNDLE_GEMFILE={} RAILS_ENV=production bundle exec rake -f {} assets:precompile'.format(app.job_user, gemfile, rakefile))

#def start(app):
    # TODO: look in the discourse startup util scripts how to run it without cd
    #gemfile = os.path.join(app.path, 'Gemfile')
    #env = {'BUNDLE_GEMFILE': gemfile, 'RAILS_ENV': 'production'}
    #app.start_job('bundle exec rails server -e production', cwd=app.path)
    #app.start_job('bundle exec sidekiq -e production', cwd=app.path)

# ARCHIVE OR DELETE(ONLY IF ABOVE WORKS GOOD ENOUGH)
# sudo apt-get install -t jessie-backports docker.io
# git clone https://github.com/discourse/discourse_docker.git .
# cp samples/standalone.yml containers/app.yml
# # heavily cleanup app.yml
# # docker could use --net=host -- not that easy with the luancher script.
# # configure postfix to function as a relay when messages are comming from docker
# # ip...
# sudo ./launcher bootstrap app
# sudo ./launcher start app
# # docker must be run as root (or someone in the docker group, but docker can do
# # much, so it is not a good idea to give www-data docker control)

    ## try beta?????, stable seems to work
    #sudo -u www-data git clone -b stable --single-branch https://github.com/discourse/discourse.git .
    #sudo apt-get install postgresql-contrib libpq-dev libxml2 imagemagick
    #sudo -u www-data bundle install --deployment
    #sudo -u postgres psql -c "CREATE USER discourse PASSWORD 'discourse';"
    ## TODO: maybe owner can be done with portable GRANT statement
    #sudo -u postgres psql -c "CREATE DATABASE discourse OWNER discourse;"
    #sudo -u postgres psql -d discourse -c "CREATE EXTENSION hstore;"
    #sudo -u postgres psql -d discourse -c "CREATE EXTENSION pg_trgm;"
    #sudo -u www-data cp /home/noya/config/discourse.conf config/discourse.conf
    #sudo -u www-data RAILS_ENV=production bundle exec rake db:migrate
    #sudo -u www-data RAILS_ENV=production bundle exec rake assets:precompile

if __name__ == '__main__':
    wam.run_app_script()
