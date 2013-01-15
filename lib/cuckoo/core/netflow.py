# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import stat
import logging
import subprocess
import signal

from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT

log = logging.getLogger(__name__)

class Netflow:
    """Netflow manager."""

    def __init__(self, fprobe, nfcapd):
        """
        @param fprobe: fprobe path.
        @param nfcapd: nfcapd path.
        """
        self.fprobe = fprobe
        self.nfcapd = nfcapd
        self.collector = None
        self.generator = None

    def start(self, interface, dst, dport, file_path):
        """Start sniffing.
        @param interface: interface to collect netflow on
        @param dst: ip address to send netflow to
        @param dport: port to send netflow to
        @return: operation status.
        """
        if not self.fprobe or not os.path.exists(self.fprobe):
            log.error("fprobe does not exist at path \"%s\", network capture aborted" % self.fprobe)
            return False
        if not self.nfcapd or not os.path.exists(self.nfcapd):
            log.error("nfcapd does not exist at path \"%s\", network capture aborted" % self.nfacpd)
            return False

        if not file_path or not os.path.exists(file_path):
            log.error("path to write netflow data to does not exist \"%s\", capture aborted" % (file_path))
            return False

        if not interface:
            log.warning("No interface given, using default (vboxnet0)")
            interface = 'vboxnet0'

	if not dst:
            log.warning("No destination IP given, using default (127.0.0.1).")
            dst = "127.0.0.1"

        if not dport:
            log.warning("No destination port given, using default (6666)")
            dport = "6666"

        pargs = ['/usr/bin/sudo', '%s' % self.nfcapd, '-b', '%s' % dst, '-p', '%s' % dport, '-l', file_path]

        try:
            self.collector = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (OSError, ValueError) as e:
            log.exception("Failed to start nfcapd (bind=%s, port=%s, dir=%s)" % (dst, dport, file_path))
            return False
        log.info("Started nfcapd (bind=%s, port=%s, dir=%s)" % (dst, dport, file_path))

        pargs = ['/usr/bin/sudo', '%s' % self.fprobe, '-p', '-i', interface, '%s:%s' % (dst, dport),'-l', '2', '-f', 'ip and not port %s' % (CUCKOO_GUEST_PORT)]

        try:
            self.generator = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (OSError, ValueError) as e:
            log.exception("Failed to start fprobe (interface=%s)" % (interface))
            return False
        log.info("Started fprobe (interface=%s)" % (interface))

        return True

    def stop(self):
        """Stop sniffing.
        @return: operation status.
        """
        if self.collector and not self.collector.poll():
            try:
                self.collector.terminate()
            except:
                try:
                    if not self.collector.poll():
                        log.warning("Killing nfcapd server")
                        self.collector.kill()
                except OSError as e:
                    # Avoid "tying to kill a died process" error.
                    log.error("Error killing nfcapd server: %s. Continue" % e)
                    pass
                except Exception as e:
                    log.exception("Unable to stop the nfcapd server with pid %d" % self.collector.pid)
                    return False

        if self.generator and not self.generator.poll():
            try:
                self.generator.terminate()
            except:
                try:
                    if not self.generator.poll():
                        log.warning("Killing fprobe")
                        self.generator.kill()
                except OSError as e:
                    # Avoid "tying to kill a died process" error.
                    log.error("Error killing fprobe: %s. Continue" % e)
                    try:
                        pidPath = "/var/run/fprobe.pid"
                        if os.path.exists(pidPath):
                            fp = open(pidPath, 'r')
                            pid = int(fp.read())
                            fp.close()
                            os.kill(pid,signal.SIGTERM)
                            log.info("successfully killed fprobe")
                    except Exception, why:
                        log.error("kill by PID failed %s" % why)
                        pass
                except Exception as e:
                    log.exception("Unable to stop the fprobe with pid %d" % self.generator.pid)
                    return False

        return True
