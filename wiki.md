# dependencies
# apt-get install python-mysql.connector

# TODO add argparse with first command `wam app_encrypt <id>` and

# https://chimeracoder.github.io/docker-without-docker/

```
setup:
TODO /etc/sudoers.d/wam (remember to chmod)
sudo -u www-data mkdir /var/www/wam # TODO: default owner of var/www is maybe already www-data?
sudo -u www-data mkdir /var/www/wam/ssl
sudo -u www-data mkdir /var/www/wam/ext
sudo chmod go= /var/www/wam/ssl
sudo touch /etc/apache2/sites-available/wam.conf
sudo chown www-data:www-data /var/www/wam \
    /etc/apache2/sites-available/wam.conf
sudo a2ensite wam.conf
```

# dependencies:
projects wam.json/webapp.json describes dependencies
wam automatically installs those dependencies
class System(object):
    def install_dependency(name):
        pass
supports debian, maps names like mysql, node, python-django, etc. to debian package
names
default map is delivered with wam
for beginning: directly debian package name?

# market:
online market database, that is retrieved by wam
entries contain small description and link to repo / wam.json

# script interface for utilities:
those methods read the set env variables
wam create_db
wam remove_db
wam clone
...

def init(instance):
    instance.call('wget http://ftp.drupal.org/files/projects/commons-7.x-3.20-core.tar.gz')
    instance.call('tar --strip-components=1 -xf commons-7.x-3.20-core.tar.gz')
    instance.call('chown -R www-data:www-data sites/default')
    instance.set_php_config('max_execution_time', '120') # maybe not, maybe this should be the default for wam...
    # TODO: open URL, wait for user input
    # better: auto visit / post to urls
    # even better: call some drupal.php script?
    #  see https://github.com/drush-ops/drush

    instance.create_database('mysql')

