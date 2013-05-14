# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import urllib
import urllib2
import logging

from lib.cuckoo.common.objects import File
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

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

        VIRUSTOTAL_KEY = self.options.get("key", None)
        if not VIRUSTOTAL_KEY:
            raise CuckooProcessingError("VirusTotal API key not configured, skip")

        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("File %s not found, skip" % self.file_path)

            resource = File(self.file_path).get_md5()
            url = VIRUSTOTAL_FILE_URL
        elif self.task["category"] == "url":
            resource = self.task["target"]
            url = VIRUSTOTAL_URL_URL
        else:
            log.warning("Analysis not of type FILE or URL, skipping VirusTotal")
            return virustotal

        data = urllib.urlencode({"resource" : resource, "apikey" : VIRUSTOTAL_KEY})

        try:
            if self.options.get("proxy"):
                log.info("using proxy for connection to virustotal: %s %s:%s" % (self.options.get("pprotocol"), self.options.get("pserver"), self.options.get("pport")))
                proxy = urllib2.ProxyHandler({'%s' % (self.options.get("pprotocol")): '%s:%s' % (self.options.get("pserver"), self.options.get("pport"))})
                opener = urllib2.build_opener(proxy)
                urllib2.install_opener(opener)
            request = urllib2.Request(url, data)
            response = urllib2.urlopen(request)
        except urllib2.URLError as e:
            raise CuckooProcessingError("Unable to establish connection to VirusTotal: %s" % e)
        except urllib2.HTTPError as e:
            raise CuckooProcessingError("Unable to perform HTTP request to VirusTotal (http code=%s)" % e.code)

        try:
            virustotal = json.loads(response.read())
        except ValueError as e:
            raise CuckooProcessingError("Unable to convert response to JSON: {0}".format(e))

        if "scans" in virustotal:
            virustotal["scans"] = dict([(engine.replace(".", "_"), signature) for engine, signature in virustotal["scans"].items()])

        return virustotal
