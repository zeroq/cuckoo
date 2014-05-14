# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import urllib
import urllib2
import logging

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.objects import File

log = logging.getLogger(__name__)

VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/vtapi/v2/file/report"
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/vtapi/v2/url/report"

class VirusTotal(Processing):
    """Gets antivirus signatures from VirusTotal.com"""

    def run(self):
        """Runs VirusTotal processing
        @return: full VirusTotal report.
        """
        self.key = "virustotal"
        virustotal = []

        key = self.options.get("key", None)
        if not key:
            raise CuckooProcessingError("VirusTotal API key not "
                                        "configured, skip")

        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("File {0} not found, skipping it".format(self.file_path))

            resource = File(self.file_path).get_md5()
            url = VIRUSTOTAL_FILE_URL
        elif self.task["category"] == "url":
            resource = self.task["target"]
            url = VIRUSTOTAL_URL_URL

        data = urllib.urlencode({"resource": resource, "apikey": key})

        try:
            if self.options.get("proxy", None):
                log.debug("using proxy for connection to virustotal: %s %s:%s" % (self.options.get("pprotocol"), self.options.get("pserver"), self.options.get("pport")))
                proxy = urllib2.ProxyHandler({'%s' % (self.options.get("pprotocol")): '%s:%s' % (self.options.get("pserver"), self.options.get("pport"))})
                opener = urllib2.build_opener(proxy)
                urllib2.install_opener(opener)
            request = urllib2.Request(url, data)
            response = urllib2.urlopen(request)
            response_data = response.read()
        except urllib2.URLError as e:
            #raise CuckooProcessingError("Unable to establish connection to VirusTotal: {0}".format(e))
            log.error("Unable to establish connection to VirusTotal: %s" % e)
            return virustotal
        except urllib2.HTTPError as e:
            #raise CuckooProcessingError("Unable to perform HTTP request to VirusTotal (http code={0})".format(e.code))
            log.error("Unable to perform HTTP request to VirusTotal (http code=%s)" % e.code)
            return virustotal

        try:
            virustotal = json.loads(response_data)
        except ValueError as e:
            #raise CuckooProcessingError("Unable to convert response to JSON: {0}".format(e))
            log.error("Unable to convert response to JSON: {0}".format(e))
            return virustotal
        except StandardError as e:
            log.error("VirusTotal Error: %s" % (e))
            return virustotal

        if "scans" in virustotal:
            items = virustotal["scans"].items()
            virustotal["scans"] = dict((engine.replace(".", "_"), signature)
                                       for engine, signature in items)

        return virustotal
