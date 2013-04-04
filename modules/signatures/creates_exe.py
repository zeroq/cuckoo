# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesExe(Signature):
    name = "creates_exe"
    description = "Creates a Windows executable on the filesystem"
    severity = 2
    categories = ["generic"]
    authors = ["Jan Goebel"]
    minimum = "0.5"

    def run(self):
        try:
            for filedict in self.results["newsummary"]["filesystem"]["write"]:
       	        file_path = filedict["filename"]
                if file_path.lower().endswith(".exe"):
                    if {"file_name" : file_path} not in self.data:
                        self.data.append({"file_name" : file_path})
        except:
            pass
        if len(self.data)>0:
            return True
        return False
