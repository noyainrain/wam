wam! ToDos
==========

## Issues

* Refactor encrypt/2

  Rename encrypt() and encrypt2() to something like prepare\_encrypt() and encrypt(). encrypt()
  should then optionally accept a *privatekey*, so externally created/managed certificates can
  easily be used.

* Reenable password protection (with nginx)

* meetling.json uses incorrect Redis database

  Instead call `python3 -m meetling --redis-url={databases.redis.name}`.

* Build auto-update feature into wam!

  Should do rollback on failure. Update could be triggered via cron job.

* Make nginx serve files defined via `static`

  See sample `wam.conf`

## Development Discussion

* ...
