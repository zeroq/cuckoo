# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__)

class Crypto(Signature):
    name = "crypto"
    description = "Loads cryptographic functionality (probably ransomware)"
    severity = 2
    categories = ["generic"]
    authors = ["Jan Goebel"]
    minimum = "0.5"

    def run(self):
        try:
            for item in self.results['behavior']['enhanced']:
                if item['object'] == 'library' and 'data' in item:
                    if 'file' in item['data'] and item['data']['file'].lower() == 'cryptsp.dll':
                        self.data.append({"file_name": item['data']['file'].lower()})
                    if 'file' in item['data'] and item['data']['file'].lower() == 'cryptbase.dll':
                        self.data.append({"file_name": item['data']['file'].lower()})
                    if 'file' in item['data'] and item['data']['file'].lower() == 'crypt32.dll':
                        self.data.append({"file_name": item['data']['file'].lower()})
        except StandardError as e:
            log.warning("crypto signature failed: %s" % (e))
        if len(self.data)>0:
            return True
        return False
