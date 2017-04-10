#!/bin/sh

set -e

sudo mkdir /etc/letsencrypt/live/localhost
sudo mkdir /etc/letsencrypt/live/localhoax
sudo ln -s /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/letsencrypt/live/localhost/fullchain.pem;
sudo ln -s /etc/ssl/private/ssl-cert-snakeoil.key /etc/letsencrypt/live/localhost/privkey.pem;
sudo ln -s /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/letsencrypt/live/localhoax/fullchain.pem;
sudo ln -s /etc/ssl/private/ssl-cert-snakeoil.key /etc/letsencrypt/live/localhoax/privkey.pem;
