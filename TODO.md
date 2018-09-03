# wam! ToDos

## Issues

* Make it possible to install apps under a subpath

  Useful for debugging e.g. path resolution: `error_log /var/log/nginx/debug.log debug;`

* Only keep n backups

* Convert data_dirs to data_paths to enable files

  For Owncloud, add `data/ownloud.db`, so only database (but not files) will be included in regular
  backups.

* Implement update of repository URLs

  Change of repo URLs happens only rarely, but when it does, the app is unusable. Also make possible
  for extensions.

* Owncloud: Update disables extensions, but does not reenable again

* Handle IO errors

  E.g. if git fails due to network down / repo deleted etc. print a nice error message

* Strict-Transport-Security

* integration tests for all webapps, install + uninstall

* start/stop befehle, stoppstartet alle apps

  Including service file, die wam start aufruft

* Refactor encrypt/2

  Rename encrypt() and encrypt2() to something like prepare\_encrypt() and encrypt(). encrypt()
  should then optionally accept a *privatekey*, so externally created/managed certificates can
  easily be used.

* Build auto-update feature into wam!

  Should do rollback on failure. Update could be triggered via cron job.

* Make nginx serve files defined via `static`

  See sample `wam.conf`

## Development Discussion

* watch: data dirs owner conflicts with update (git reset does not have priviliges to change
  those directories)

* Complex plugins

  Maybe not as plugins, but include in hook (e.g. git clone/fetch/checkout plus call of make etc)

  * contacts: make
  * calendar: sudo npm install -g yarn && make
