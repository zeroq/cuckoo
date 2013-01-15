# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import stat
import logging
import subprocess

from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT
log = logging.getLogger(__name__)

class fakeDNS:
    """fakeDNS manager."""

    def __init__(self, fakeDNS):
        """@param fakeDNS: tcpdump path."""
        self.fakeDNS = fakeDNS
        self.proc = None

    def start(self, ip=None, withInternet=0):
        """Start sniffing.
        @param withInternet: return real IP addresses.
        @param ip: listen on given IP address.
        @return: operation status.
        """
        if not self.fakeDNS or not os.path.exists(self.fakeDNS):
            log.error("fakeDNS does not exist at path \"%s\", network capture aborted" % self.fakeDNS)
            return False

        if not ip:
            log.warning("No listen IP address given, using default (192.168.56.1)")
            ip = '192.168.56.1'

	if not withInternet in [0, 1]:
            log.warning("Wrong value for withInternet, setting to no Internet.")
            withInternet = 0

        pargs = ['/usr/bin/sudo', '%s' % self.fakeDNS, ip, '%s' % withInternet]

        try:
            self.proc = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (OSError, ValueError) as e:
            log.exception("Failed to start fakeDNS server (ip=%s, withInternet=%s)" % (ip, withInternet))
            return False

        log.info("Started fakeDNS server (ip=%s, withInternet=%s)" % (ip, withInternet))

        return True

    def stop(self):
        """Stop sniffing.
        @return: operation status.
        """
        if self.proc and not self.proc.poll():
            try:
                self.proc.terminate()
            except:
                try:
                    if not self.proc.poll():
                        log.debug("Killing fakeDNS server")
                        self.proc.kill()
                except OSError as e:
                    # Avoid "tying to kill a died process" error.
                    log.debug("Error killing fakeDNS server: %s. Continue" % e)
                    pass
                except Exception as e:
                    log.exception("Unable to stop the fakeDNS server with pid %d" % self.proc.pid)
                    return False

        return True

if __name__ == '__main__':
	import time
	t = fakeDNS('/opt/cuckoo/utils/fakeDNSserver.py')
	t.start(withInternet=1)
	try:
		while True:
			time.sleep(0.0001)
	except:
		t.stop()
	print "done"
