# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__)

class Persistence(Signature):
    name = "persistence"
    description = "Creates an autorun entry in the registry (persistence)"
    severity = 2
    categories = ["generic"]
    authors = ["Jan Goebel"]
    minimum = "0.5"

    def run(self):
        try:
            for regdict in self.results["newsummary"]["registry"]["write"]:
       	        reg_path = regdict["path"]
                reg_hive = regdict["hive"]
                if reg_path.lower().endswith("software\\microsoft\\windows\\currentversion\\run"):
                    if {"reg_path" : reg_hive+'\\'+reg_path} not in self.data:
                        self.data.append({"reg_path" : reg_hive+'\\'+reg_path})
        except StandardError as e:
            log.warning("persistence signature failed: %s" % (e))
            pass
        if len(self.data)>0:
            return True
        return False
