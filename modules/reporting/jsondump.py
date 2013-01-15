# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import codecs

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class JsonDump(Report):
    """Saves analysis results in JSON format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        try:
            report = codecs.open(os.path.join(self.reports_path, "report.json"), "w", "utf-8")
            json.dump(results, report, sort_keys=False, indent=4)
            report.close()
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON report: %s" % e)

        ###JG: add splitted report
        try:
            reportFile = os.path.join(self.reports_path, "report.json")
            if os.path.exists(reportFile):
                report = codecs.open(reportFile, "r", "utf-8")
                obj = json.load(report)
                report.close()

                dest = os.path.join(self.reports_path, "jsonparts")
                if not os.path.exists(dest):
                    os.makedirs(dest)

                for k in obj.keys():
                    partName = os.path.join(dest, k+'.json')
                    fp = codecs.open(partName, 'w', "utf-8")
                    json.dump(obj[k], fp)
                    fp.close()
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON partial reports: %s" % e)
