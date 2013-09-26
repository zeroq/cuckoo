# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesExe(Signature):
    name = "creates_exe"
    description = "Creates a Windows executable in the filesystem"
    severity = 2
    categories = ["generic"]
    authors = ["Jan Goebel"]
    minimum = "0.5"

    def run(self):
        try:
            for filedict in self.results["newsummary"]["filesystem"]["write"]:
       	        file_path = filedict["filename"]
                if file_path.lower().endswith(".exe") or file_path.lower().endswith(".com") or file_path.lower().endswith(".bat"):
                    if {"file_name" : file_path} not in self.data:
                        self.data.append({"file_name" : file_path})
            ### {"status": "1", "accessmodes": ["FILE_COPY"], "destination_filename": "C:\\Documents and Settings\\All Users\\svchost.exe", "source_filename": "C:\\DOCUME~1\\ADMINI~1\\LOCALS~1\\Temp\\Voter-885940-6755.pdf.exe", "debug": "CopyFileA", "type": "file", "statusmessage": "Unknown"}
            for filedict in self.results["newsummary"]["filesystem"]["copy"]:
                file_path = filedict['destination_filename']
                if file_path.lower().endswith(".exe") or file_path.lower().endswith(".com") or file_path.lower().endswith(".bat"):
                    if {"file_name" : file_path} not in self.data:
                        self.data.append({"file_name" : file_path})
        except:
            pass
        if len(self.data)>0:
            return True
        return False
