#!/usr/bin/env python
# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import sys
import time

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_RUNNING
from lib.cuckoo.core.database import TASK_COMPLETED, TASK_RECOVERED
from lib.cuckoo.core.database import TASK_REPORTED, TASK_FAILED_ANALYSIS
from lib.cuckoo.core.database import TASK_FAILED_PROCESSING

def timestamp(dt):
    """Returns the timestamp of a datetime object."""
    return time.mktime(dt.timetuple())

def main(analysis_id):
    db = Database()
    analysis_task = db.view_task(analysis_id)
    if analysis_task:
        mname = analysis_task.machine
        if mname:
            print mname
        else:
            print "NotSet"
        return
    print "NotFound"
    return

if __name__ == "__main__":
    analysis_id = sys.argv[1]
    main(analysis_id)
