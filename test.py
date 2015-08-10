#!/usr/bin/env python3

import os
import sys
import logging
from tempfile import mkdtemp
from wam import WebAppManager

def main(args):
    logging.basicConfig(level=logging.INFO)
    #logging.basicConfig(level=logging.DEBUG)
    # XXX
    os.environ['PYTHONPATH'] = '.'
    d = mkdtemp()
    print(d)
    manager = WebAppManager({'data_path': d})
    manager.start()
    app = manager.add('webapps/sample.py', 'example.org')
    manager.remove(app)
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
