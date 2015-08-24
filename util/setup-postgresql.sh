#!/bin/sh

set -e

WAMUSER=$USER

sudo apt-get -qy install postgresql python3-psycopg2
# TODO: better way? superuser needed for extensions, but can drop all databases
# etc.
sudo -u postgres psql -c "CREATE USER $WAMUSER WITH SUPERUSER"
#sudo -u postgres psql -c "CREATE USER $WAMUSER WITH CREATEDB CREATEROLE"
#sudo -u postgres psql -c "ALTER USER $WAMUSER WITH SUPERUSER"
