#!/usr/bin/env python3

#!/bin/sh
set -e

AGENDA_PATH=/opt/agenda

apt-get install python3-tornado redis-server python3-redis nodejs-legacy npm
npm install -g bower

adduser --system --home $AGENDA_PATH agenda
sudo -u agenda git clone --single-branch https://github.com/NoyaInRain/agenda.git $AGENDA_PATH

cd $AGENDA_PATH

sudo -u agenda bower --config.interactive=false update

# TODO: see wiki.md, make wiki entry

if __name__ == '__main__':
    # TODO
