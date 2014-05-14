# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)

class Dll(Package):
    """DLL analysis package."""

    def start(self, path):
        free = self.options.get("free", False)
        function = self.options.get("function", "DllMain")
        arguments = self.options.get("arguments", None)
        dll = self.options.get("dll", None)
        suspended = True
        if free:
            suspended = False

        ### JG: added detection for control panel applications
        if not path.endswith('.cpl'):
            args = "{0},{1}".format(path, function)
            if arguments:
                args += " {0}".format(arguments)
            exe_path = "C:\\WINDOWS\\system32\\rundll32.exe"
        else:
            args = "{0}".format(path)
            if arguments:
                args += " {0}".format(arguments)
            exe_path = "C:\\WINDOWS\\system32\\control.exe"

        log.info("starting DLL with: %s" % (args))

        p = Process()
        if not p.execute(path=exe_path, args=args, suspended=suspended):
            raise CuckooPackageError("Unable to execute rundll32, "
                                     "analysis aborted")

        if not free and suspended:
            p.inject(dll)
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
