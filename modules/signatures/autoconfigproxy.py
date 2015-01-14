# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__)

class Persistence(Signature):
    name = "proxyaware"
    description = "Malware sets proxy configuration (proxyconfig)"
    severity = 2
    categories = ["generic"]
    authors = ["Jan Goebel"]
    minimum = "0.5"

    def run(self):
        try:
            for regdict in self.results["newsummary"]["registry"]["write"]:
       	        reg_path = regdict["path"]
                reg_hive = regdict["hive"]
                reg_keys = regdict["key"]
                reg_values = regdict["value"]
                if reg_path.lower().endswith("software\\microsoft\\windows\\currentversion\\internet settings") and "AutoConfigURL" in reg_keys:
                    if {"reg_path" : reg_hive+'\\'+reg_path} not in self.data:
                        self.data.append({"reg_path" : reg_hive+'\\'+reg_path+'\\AutoConfigURL -> "%s"' % (reg_values[-1])})
        except StandardError as e:
            log.warning("proxyconfig signature failed: %s" % (e))
            pass
        if len(self.data)>0:
            return True
        return False
