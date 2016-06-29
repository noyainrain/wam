wam! ToDos
==========

## Issues

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
