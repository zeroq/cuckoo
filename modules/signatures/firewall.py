# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__)

class Persistence(Signature):
    name = "persistence"
    description = "Disables firewall notifications"
    severity = 1
    categories = ["generic"]
    authors = ["Jan Goebel"]
    minimum = "0.5"

    def run(self):
        try:
            for regdict in self.results["newsummary"]["registry"]["write"]:
       	        reg_path = regdict["path"]
                reg_hive = regdict["hive"]
                if reg_path.lower().endswith("currentcontrolset\\services\\sharedaccess\\parameters\\firewallpolicy\\standardprofile") and "DisableNotifications" in regdict["key"] and "1" in regdict["value"]:
                    if {"reg_path" : reg_hive+'\\'+reg_path} not in self.data:
                        self.data.append({"reg_path" : reg_hive+'\\'+reg_path})
        except StandardError as e:
            log.warning("firewall signature failed: %s" % (e))
            pass
        if len(self.data)>0:
            return True
        return False
