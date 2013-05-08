# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import codecs
import time

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.core.database import Database

class Debug(Processing):
    """Analysis debug information."""

    def run(self):
        """Run debug analysis.
        @return: debug information dict.
        """
        self.key = "debug"
        debug = {"log" : "", "errors" : []}

        if os.path.exists(self.log_path):
            try:
                debug["log"] = codecs.open(self.log_path, "rb", "utf-8").read()
            except ValueError as e:
                raise CuckooProcessingError("Error decoding %s: %s" % (self.log_path, e))
            except (IOError, OSError) as e:
                raise CuckooProcessingError("Error opening %s: %s" % (self.log_path, e))

        ### JG: added retries to avoid error on database locked
        retries = 5
        worked = False

        while not worked and retries > 0:
            try:
                for error in Database().view_errors(int(self.cfg.analysis.id)):
                    debug["errors"].append(error.message)
                worked = True
                retries = 0
            except:
                retries -= 1
                time.sleep(5)

        return debug
