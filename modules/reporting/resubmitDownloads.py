# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import codecs
import json
import sqlite3
import logging
import magic
import time

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.objects import File

class resubmitDownloads(Report):
    """Submit downloaded files to analysis."""

    def get_type(self, file_path):
        """Get MIME file type.
        @return: file type.
        """
        try:
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            file_type = ms.file(file_path)
        except:
            try:
                file_type = magic.from_file(file_path)
            except:
                try:
                    import subprocess
                    file_process = subprocess.Popen(['file',
                                                     '-b',
                                                     file_path],
                                                    stdout = subprocess.PIPE)
                    file_type = file_process.stdout.read().strip()
                except:
                    return None
        finally:
            try:
                ms.close()
            except:
                pass

        return file_type

    def run(self, results):
        """Run analysis of downloaded files.
        @return: Nothing.
        """

        log = logging.getLogger("resubmissions")
        filesToLoad = []

        downloadDir = os.path.abspath(os.path.join(self.analysis_path, "downloads"))
        if not os.path.exists(downloadDir):
            os.makedirs(downloadDir)
        jsonReport = os.path.join(self.analysis_path, "reports/report.json")
        if os.path.exists(jsonReport):
            try:
                report = codecs.open(jsonReport, "r", "utf-8")
                obj = json.load(report)
                report.close()
            except StandardError as e:
                log.warning("Unable to load JSON dump: %s" % (e))
                return None

            for httpRequest in obj['network']['http']:
                if httpRequest['method'].lower() == 'get' and httpRequest['uri'].lower().endswith('.exe'):
                    filesToLoad.append([httpRequest['uri'], httpRequest['user-agent']])
        else:
            log.warning("JSON report missing at %s" % (jsonReport))
            return None

        sucessfullDownloads = []
        import urllib2
        import hashlib
        import zlib
        proxy = urllib2.ProxyHandler({'http': 'proxy.siemens.de:81'})
        for uriList in filesToLoad:
            try:
                if uriList[0].count('192.168.56.')>0:
                    log.info("skip local download: %s" % (uriList[0]))
                else:
                    log.info("try to download: %s" % (uriList[0]))
                opener = urllib2.build_opener(proxy)
                opener.addheaders = [('User-agent', uriList[1])]
                urllib2.install_opener(opener)
                r = urllib2.urlopen(uriList[0])
                filePath = os.path.abspath(os.path.join(downloadDir, os.path.basename(uriList[0])))
                with open(filePath, "wb") as local_file:
                    local_file.write(r.read())
                ### generate hashes
                fileContent = open(filePath, 'r').read()
                fileSize = len(fileContent)
                fileType = self.get_type(filePath)
                md5Hash = hashlib.md5(fileContent).hexdigest()
                crc32Hash = '%x' % (zlib.crc32(fileContent))
                sha1Hash = hashlib.sha1(fileContent).hexdigest()
                sha256Hash = hashlib.sha256(fileContent).hexdigest()
                sha512Hash = hashlib.sha512(fileContent).hexdigest()
                ### append to result list
                sucessfullDownloads.append([filePath, fileSize, fileType, md5Hash, crc32Hash, sha1Hash, sha256Hash, sha512Hash])
                log.info("download: %s successfull" % (uriList[0]))
            except StandardError as e:
                log.warning("failed to download file (%s), %s" % (uriList[0], e))
                continue

        if len(sucessfullDownloads)>0:
            try:
                conn = sqlite3.connect('/opt/git/cuckoo/db/cuckoo.db')
            except StandardError as e:
                log.warning("failed connecting to sqlite database! (%s)" % (e))
                return None
            cur = conn.cursor()
            for item in sucessfullDownloads:
                # check if already exists
                query = "SELECT * FROM \"samples\" WHERE md5 = '%s' AND sha256 = '%s' LIMIT 1" % (item[3], item[6])
                cur.execute(query)
                data = cur.fetchone()
                if data == None:
                    ### first create new sample entry
                    query = "INSERT INTO \"samples\" (file_size, file_type, md5 , crc32, sha1, sha256, sha512) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (item[1], item[2], item[3], item[4], item[5], item[6], item[7])
                    cur.execute(query)
                    conn.commit()
                    sampleID = cur.lastrowid
                    ### then create new task
                    query = "INSERT INTO \"tasks\" (target, category, timeout, priority, machine, package, platform, memory, enforce_timeout, sample_id, interaction, internet, added_on, options) VALUES ('%s', 'file', '200', '1', 'SBox1', 'exe', 'windows', '0', '0', '%s', '0', '0', '%s', '')" % (item[0], sampleID, time.strftime('%Y-%m-%d %H:%M:%S'))
                    cur.execute(query)
                    conn.commit()
                    continue
                else:
                    log.info("file (%s) already analyzed previously (%s)" % (item[0], item[3]))
                    continue
            conn.close()
        return None
