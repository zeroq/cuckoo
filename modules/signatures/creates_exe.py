# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesExe(Signature):
    name = "creates_exe"
    description = "Creates/Modifies/Reads a Windows executable on the filesystem"
    severity = 2
    categories = ["generic"]
    authors = ["Cuckoo Developers"]
    minimum = "0.5"

    def run(self):
        for file_path in self.results["behavior"]["summary"]["files"]:
            if file_path.lower().endswith(".exe") and file_path.lower() != "c:\\%s" % self.results["target"]["file"]["name"].lower():
                self.data.append({"file_name" : file_path})
        if len(self.data)>0:
            return True
        return False
