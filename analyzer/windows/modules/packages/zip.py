# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
from zipfile import ZipFile, BadZipfile

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError
from lib.api.process import Process

log = logging.getLogger()

class Zip(Package):
    """Zip analysis package."""

    def start(self, path):
        root = os.environ["TEMP"]
        password = self.options.get("password", None)

        start_as = "sample.exe"
        with ZipFile(path, "r") as archive:
            try:
                for item in archive.filelist:
                    fname = item.filename
                    if fname.endswith('.exe') or fname.endswith('.bat') or fname.endswith('.com'):
                        start_as = fname
                        break
            except StandardError as e:
                raise CuckooPackageError("Unable to get executable file from zip (%s)" % (e))
            try:
                archive.extractall(path=root, pwd=password)
            except BadZipfile as e:
                raise CuckooPackageError("Invalid Zip file")
            except RuntimeError:
                try:
                    archive.extractall(path=root, pwd=self.options.get("password", "infected"))
                except RuntimeError as e:
                    raise CuckooPackageError("Unable to extract Zip file, unknown password?")

        file_path = os.path.join(root, self.options.get("file", start_as))
        free = self.options.get("free", False)
        args = self.options.get("arguments", None)
        suspended = True
        if free:
            suspended = False

        log.info("starting from ZIP file: %s %s" % (file_path, args))

        p = Process()
        if not p.execute(path=file_path, args=args, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial process, analysis aborted (%s)" % (file_path))

        if not free and suspended:
            p.inject()
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
