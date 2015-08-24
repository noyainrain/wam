#!/bin/sh

set -e

echo postfix postfix/main_mailer_type select Internet Site | sudo debconf-set-selections
echo postfix postfix/mailname string $(hostname) | sudo debconf-set-selections
sudo apt-get -qy install postfix
## TODO: seems like it must be owned by root
#cp "$PWD/aliases" /etc/aliases
#newaliases
