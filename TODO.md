wam! ToDos
==========

## Issues

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
