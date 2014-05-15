# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import stat
import getpass
import logging
import subprocess

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_GUEST_PORT

log = logging.getLogger(__name__)

class FakeDNS(Auxiliary):
    def start(self):
        fakedns = self.options.get("fakedns", None)
        listen_ip = self.options.get("", "192.168.57.1")

        withInternet = self.task.internet

        if not fakedns or not os.path.exists(fakedns):
            log.error("FakeDNS does not exist at path \"%s\", DNS "
                      "emulation aborted", fakedns)
            return

        pargs = ['sudo', '%s' % fakedns, listen_ip, '%s' % withInternet]

        try:
            self.proc = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (OSError, ValueError):
            log.exception("Failed to start fakeDNS server (ip=%s, internet=%s)", listen_ip, withInternet)
            return

        log.info("Started fakeDNS server with PID %d (ip=%s, internet=%s)", self.proc.pid, listen_ip, withInternet)

    def stop(self):
        """Stop fakeDNS server.
        @return: operation status.
        """
        if self.proc and not self.proc.poll():
            try:
                self.proc.terminate()
            except:
                try:
                    if not self.proc.poll():
                        log.debug("Killing fakeDNS")
                        self.proc.kill()
                except OSError as e:
                    try:
                        os.system("sudo kill %s" % (self.proc.pid, ))
                    except Exception as e:
                        log.warning("Error killing fakeDNS: %s. Continue", e)
                except Exception as e:
                    log.exception("Unable to stop fakeDNS with pid %d: %s",
                                  self.proc.pid, e)
