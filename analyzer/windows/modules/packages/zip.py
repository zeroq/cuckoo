# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
from zipfile import ZipFile, BadZipfile

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError
from lib.api.process import Process

log = logging.getLogger(__name__)

class Zip(Package):
    """Zip analysis package."""

    def start(self, path):
        root = os.environ["TEMP"]
        password = self.options.get("password", None)
        default_file_name = "sample.exe"

        start_as = "sample.exe"
        with ZipFile(path, "r") as archive:
            try:
                ### JG: added finding filename of executable in provided zip file
                for item in archive.filelist:
                    fname = item.filename
                    if fname.endswith('.exe') or fname.endswith('.bat') or fname.endswith('.com'):
                        start_as = fname
                        break
            except StandardError as e:
                raise CuckooPackageError("Unable to get executable file from zip (%s)" % (e))
            zipinfos = archive.infolist()
            try:
                archive.extractall(path=root, pwd=password)
            except BadZipfile as e:
                raise CuckooPackageError("Invalid Zip file")
            except RuntimeError:
                try:
                    password = self.options.get("password", "infected")
                    archive.extractall(path=root, pwd=password)
                except RuntimeError as e:
                    raise CuckooPackageError("Unable to extract Zip file: "
                                             "{0}".format(e))

        file_name = self.options.get("file", start_as)
        file_path = os.path.join(root, file_name)

        dll = self.options.get("dll", None)
        free = self.options.get("free", False)
        args = self.options.get("arguments", None)
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=file_path, args=args, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial process, "
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
