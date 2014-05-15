# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import codecs
import logging

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class JsonDump(Report):
    """Saves analysis results in JSON format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        log = logging.getLogger("jsondump")

        failure = False
        try:
            path = os.path.join(self.reports_path, "report.json")
            report = codecs.open(path, "w", "utf-8")
            json.dump(results, report, sort_keys=False, indent=4)
            report.close()
        except (UnicodeError, TypeError, IOError) as e:
            failure = True
            log.error("json failure: %s" % (e))
            #raise CuckooReportError("Failed to generate JSON report: %s" % e)

        ###JG: add splitted report
        try:
            obj = None
            reportFile = os.path.join(self.reports_path, "report.json")
            if os.path.exists(reportFile) and not failure:
                try:
                    report = codecs.open(reportFile, "r", "utf-8")
                    obj = json.load(report)
                    report.close()
                except ValueError as e:
                    log.warning("json malformed trying something ... : %s" % (e))
                    report = codecs.open(reportFile, "r", "utf-8")
                    pjson = report.read()
                    pjson = pjson.replace('"calls":','"calls": [')
                    try:
                        obj = json.loads(pjson)
                    except:
                        nres = []
                        llist = pjson.split('\n')
                        for line in llist:
                            if line.count('"calls":')>0 and line.count('[')==0:
                                nres.append('"calls": [')
                            nres.append(line)
                        tc = "\n".join(nres)
                        try:
                            obj = json.loads(tc)
                        except StandardError as e:
                            log.warning("failed splitting json report ...")
                            obj = None
                    report.close()
                if obj:
                    dest = os.path.join(self.reports_path, "jsonparts")
                    if not os.path.exists(dest):
                        os.makedirs(dest)

                    for k in obj.keys():
                        partName = os.path.join(dest, k+'.json')
                        fp = codecs.open(partName, 'w', "utf-8")
                        json.dump(obj[k], fp)
                        fp.close()
                    return
            if not obj:
                ### try to work on results
                dest = os.path.join(self.reports_path, "jsonparts")
                if not os.path.exists(dest):
                    os.makedirs(dest)

                for k in results.keys():
                    try:
                        partName = os.path.join(dest, k+'.json')
                        fp = codecs.open(partName, 'w', "utf-8")
                        json.dump(results[k], fp)
                        fp.close()
                    except (UnicodeError, TypeError, IOError) as e:
                        log.error("failed splitted dump: %s" % (e))
                        continue
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON partial reports: %s" % e)
