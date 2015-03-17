# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import stat
import getpass
import logging
import subprocess
import signal

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_GUEST_PORT

log = logging.getLogger(__name__)

class Netflow(Auxiliary):
    def start(self):
        fprobe = self.options.get("generator", "/usr/sbin/fprobe")
        nfcapd = self.options.get("collector", "/usr/bin/nfcapd")
        destination = self.options.get("destination", "127.0.0.1")
        interface = self.options.get("interface")
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id))
        host = self.machine.ip
        nflowPort = int(self.machine.ip.split('.')[-1])*1000

        if not os.path.exists(fprobe):
            log.error("Fprobe does not exist at path \"%s\", netflow "
                      "capture aborted", fprobe)
            return
        if not os.path.exists(nfcapd):
            log.error("Nfcapd does not exist at path \"%s\", netflow "
                      "calture aborted", nfcapd)

        if not interface:
            log.error("Network interface not defined, network capture aborted")
            return

        if not os.path.exists(file_path):
            log.error("Analysis directory does not exist, capture aborted")
            return

        #pargs = ['/usr/bin/sudo', '%s' % nfcapd, '-b', '%s' % destination, '-p', '%s' % nflowPort, '-l', file_path]
        pargs = ['%s' % nfcapd, '-b', '%s' % destination, '-p', '%s' % nflowPort, '-l', file_path]

        try:
            self.collector = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (OSError, ValueError):
            log.exception("Failed to start nfcapd (bind=%s, port=%s, "
                          "dump path=%s)", destination, nflowPort, file_path)
            return

        log.info("Started nfcapd with PID %d (bind=%s, port=%s, "
                 "dump path=%s)", self.collector.pid, destination, nflowPort, file_path)

        #pargs = ['/usr/bin/sudo', '%s' % fprobe, '-p', '-i', interface, '%s:%s' % (destination, nflowPort),'-l', '2', '-f', 'ip and not port %s and not (host %s and port %s)' % (CUCKOO_GUEST_PORT, str(Config().resultserver.ip), str(Config().resultserver.port))]
        pargs = ['%s' % fprobe, '-p', '-i', interface, '%s:%s' % (destination, nflowPort),'-l', '2', '-f', 'ip and not port %s and not (host %s and port %s)' % (CUCKOO_GUEST_PORT, str(Config().resultserver.ip), str(Config().resultserver.port))]

        try:
            self.generator = subprocess.Popen(pargs, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)
        except (OSError, ValueError):
            log.exception("Failed to start fprobe (interface=%s)" % (interface))
            return

        log.info("Started fprobe with PID %d (interface=%s)" % (self.generator.pid, interface))

    def stop(self):
        """Stop netflow.
        @return: operation status.
        """
        if self.generator and not self.generator.poll():
            try:
                self.generator.terminate()
            except:
                try:
                        log.warning("killing netflow generator")
                        self.generator.kill()
                except OSError as e:
                    log.warning("Error killing generator: %s. Continue", e)
                    try:
                        os.kill(self.generator.pid, signal.SIGTERM)
                    except Exception as e:
                        log.error("generator kill by PID failed: %s" % (e))
                        os.system("sudo kill %d" % (self.proc.pid))
                        pass
                except Exception as e:
                    log.exception("Unable to stop the fprobe netflow generator with pid %d: %s", self.generator.pid, e)
                    return False
        if self.collector and not self.collector.poll():
            try:
                self.collector.terminate()
            except:
                try:
                    if not self.collector.poll():
                        log.warning("killing netflow collector")
                        self.collector.kill()
                except OSError as e:
                    log.error("Error killing netflow collector: %s. Continue" % e)
                    pass
                except Exception as e:
                    log.exception("Unable to stop the nfcapd server with pid %d", self.collector.pid)
                    return False
        return True
