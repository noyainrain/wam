#!/usr/bin/env python3

import wam

def setup(app):
    # most unpopular Python3 Debian package
    # http://popcon.debian.org/stable/main/by_inst
    app.install('system', {'python3-yapsy'})

if __name__ == '__main__':
    wam.run_app_script()
