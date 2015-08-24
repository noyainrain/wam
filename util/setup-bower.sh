#!/bin/sh

set -e

sudo apt-get -qy install nodejs-legacy npm
sudo npm --spin=false install -g bower
