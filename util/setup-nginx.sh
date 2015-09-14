#!/bin/sh

sudo apt-get -qy install nginx
sudo touch /etc/nginx/conf.d/wam.conf
sudo chown $USER:$USER /etc/nginx/conf.d/wam.conf
