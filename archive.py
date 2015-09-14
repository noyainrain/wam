class WebServer:
    def __init__(self, wam):
        self.wam = wam

    def configure(self):
        # TODO: implement nginx
        return

        self._logger.info('configuring Apache httpd...')
        hosts = []
        for app in self.wam.apps.values():
            port = 80
            ssl = ''
            if app.encrypted:
                ssl = SERVER_SSL_TEMPLATE.format(
                    certificate_path=app.certificate_path,
                    certificate_key_path=app.certificate_key_path)
                port = 443

            # extensions
            more = ''
            x = ProtectApp(app)
            if x.protected:
                more = SERVER_PW_TEMPLATE.format(path=app.path, id=app.id,
                                                 htpasswd_path=x.htpasswd_path)

            hosts.append(SERVER_HOST_TEMPLATE.format(
                port=port, host=app.id, path=app.path, ssl=ssl, more=more))
        with open(SERVER_CONFIG_PATH, 'w') as f:
            f.write('\n'.join(hosts))
        call('sudo /usr/sbin/service apache2 reload')

# TODO: wam logfile
SERVER_HOST_TEMPLATE = """\
<VirtualHost *:{port}>
    ServerName {host}
    ServerAlias www.{host}
    DocumentRoot {path}

    {ssl}

    {more}
</VirtualHost>
"""

SERVER_SSL_TEMPLATE = """\
    SSLEngine on
    SSLCertificateFile {certificate_path}
    SSLCertificateKeyFile {certificate_key_path}
"""

SERVER_PW_TEMPLATE = """\
    <Directory {path}>
        AuthType Basic
        AuthName {id}
        AuthUserFile {htpasswd_path}
        Require valid-user
    </Directory>
"""

