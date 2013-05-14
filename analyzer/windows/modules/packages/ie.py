# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class IE(Package):
    """Internet Explorer analysis package."""

    def start(self, url):
        free = self.options.get("free", False)
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=os.path.join(os.getenv("ProgramFiles"), "Internet Explorer", "iexplore.exe"), args="\"%s\"" % url, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Internet Explorer process, analysis aborted")

        if not free and suspended:
            #p.inject(dll=os.path.join("dll", "cuckoomon.dll.ie"))
            p.inject(dll=os.path.join("dll", "cuckoomon.dll"))
            p.resume()
            return p.pid
        else:
            return None

    def check(self):
        return True

    def finish(self):
        if self.options.get("procmemdump", False):
            for pid in self.pids:
                p = Process(pid=pid)
                p.dump_memory()

        return True
