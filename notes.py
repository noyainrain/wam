# TODO:
#systemd service file for wam: call app.start for all apps. on stop, call
#app.stop for all apps.

class App:
    def start(self):
        pass
    def stop(self)
        pass


----

app.create_db('postgresql')

=>

def create_db(engine):
    self.setup_component(engine)

=>

def setup_component(component):
    if component == 'postgresql':
        self.install('system', 'postgresql')
        # apt-get -y install postgresql # ...

    # ...

        # TODO: could be gem install bundler instead of debian version, try beta branch
        # of discourse to be sure
        apt-get -y install bundler

        # redis
        apt-get -y install redis-server

        # postfix
        echo postfix postfix/main_mailer_type select Internet Site | sudo debconf-set-selections
        echo postfix postfix/mailname string sirius.inrain.org | sudo debconf-set-selections
        apt-get -y install postfix

# * wam: sandstorm.io im auge behalten looks nice, but very unstable, not very
# clear yet, much adjustement for apps needed
# android market foo -> sandstorm.io (und im hinterkopf behalten)
# for now, wam is just an easy tool to install web app instances as a sysadmin

#  * wam documentation:
#    * wam is like android market etc. for web apps (including user management
#      (via LDAP))
#    * easy to install multiple instances
#    * brings smtp server, analytics etc. with it
#    * software, file etc. of app controlled by wam, should _not_ be hand edited
#      by admins
#    * for now wam is on single server
#      * later, maybe: wam, nginx, ldap, mail, analytics on one node, apps could
#        be installed by wam on other nodes then
#    * install as a service, starts all installed apps (tornado/rake/... servers
#      etc.)
#      * needs additional start and stop command?
#    * user identity management is sugar on top:
#      * without group, an instance is isolated (either no LDAP, or more likely
#        LDAP with group that is named like instance)
#      * instead of ldap, openid is a choice also
#      * good way to research: go through popular open source software, look for
#        authentication that they use out of the box, go for most popular
#    * for my app servers use std setup.sh/config
#      * in setup.sh we can use wam, but there are open questions (e.g. forced to
#        use LDAP?, source code is touched by autoupdate/deploy?)
#      * support software (smtp, analytics, feedback forum...) also installed via
#        setup.sh
#      * idea: category appserver with setup.sh that installs this
