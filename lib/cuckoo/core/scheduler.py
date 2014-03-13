# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import shutil
import logging
import Queue
from threading import Thread, Lock

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooMachineError
from lib.cuckoo.common.exceptions import CuckooGuestError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.abstracts import  MachineManager
from lib.cuckoo.common.objects import Dictionary, File
from lib.cuckoo.common.utils import  create_folders, create_folder
from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.core.resultserver import Resultserver
from lib.cuckoo.core.sniffer import Sniffer
from lib.cuckoo.core.processor import Processor
from lib.cuckoo.core.reporter import Reporter
from lib.cuckoo.core.plugins import import_plugin, list_plugins

### JG:
import subprocess
from lib.cuckoo.core.fakeDNS import fakeDNS
from lib.cuckoo.core.netflow import Netflow

log = logging.getLogger(__name__)

mmanager = None
machine_lock = Lock()

class AnalysisManager(Thread):
    """Analysis Manager.

    This class handles the full analysis process for a given task. It takes
    care of selecting the analysis machine, preparing the configuration and
    interacting with the guest agent and analyzer components to launch and
    complete the analysis and store, process and report its results.
    """

    def __init__(self, task, error_queue):
        """@param task: task object containing the details for the analysis."""
        Thread.__init__(self)
        Thread.daemon = True

        self.task = task
        self.errors = error_queue
        self.cfg = Config()
        self.storage = ""
        self.binary = ""

    def init_storage(self):
        """Initialize analysis storage folder."""
        self.storage = os.path.join(CUCKOO_ROOT,
                                    "storage",
                                    "analyses",
                                    str(self.task.id))

        # If the analysis storage folder already exists, we need to abort the
        # analysis or previous results will be overwritten and lost.
        if os.path.exists(self.storage):
            log.error("Analysis results folder already exists at path \"%s\","
                      " analysis aborted", self.storage)
            return False

        # If we're not able to create the analysis storage folder, we have to
        # abort the analysis.
        try:
            create_folder(folder=self.storage)
        except CuckooOperationalError:
            log.error("Unable to create analysis folder %s", self.storage)
            return False

        return True

    def store_file(self):
        """Store a copy of the file being analyzed."""
        if not os.path.exists(self.task.target):
            log.error("The file to analyze does not exist at path \"%s\", "
                      "analysis aborted", self.task.target)
            return False

        sha256 = File(self.task.target).get_sha256()
        self.binary = os.path.join(CUCKOO_ROOT, "storage", "binaries", sha256)

        if os.path.exists(self.binary):
            log.info("File already exists at \"%s\"", self.binary)
        else:
            # TODO: do we really need to abort the analysis in case we are not
            # able to store a copy of the file?
            try:
                shutil.copy(self.task.target, self.binary)
            except (IOError, shutil.Error) as e:
                log.error("Unable to store file from \"%s\" to \"%s\", "
                          "analysis aborted", self.task.target, self.binary)
                return False

        try:
            new_binary_path = os.path.join(self.storage, "binary")

            if hasattr(os, "symlink"):
                os.symlink(self.binary, new_binary_path)
            else:
                shutil.copy(self.binary, new_binary_path)
        except (AttributeError, OSError) as e:
            log.error("Unable to create symlink/copy from \"%s\" to \"%s\"", self.binary, self.storage)

        return True

    def acquire_machine(self):
        """Acquire an analysis machine from the pool of available ones."""
        machine = None

        # Start a loop to acquire the a machine to run the analysis on.
        while True:
            machine_lock.acquire()
            # If the user specified a specific machine ID or a platform to be
            # used, acquire the machine accordingly.
            machine = mmanager.acquire(machine_id=self.task.machine,
                                       platform=self.task.platform)
            machine_lock.release()

            # If no machine is available at this moment, wait for one second
            # and try again.
            if not machine:
                log.debug("Task #%d: no machine available yet", self.task.id)
                time.sleep(1)
            else:
                log.info("Task #%d: acquired machine %s (label=%s)", self.task.id, machine.name, machine.label)
                break

        return machine

    def build_options(self):
        """Generate analysis options.
        @return: options dict.
        """
        options = {}

        options["id"] = self.task.id
        options["ip"] = self.cfg.resultserver.ip
        options["port"] = self.cfg.resultserver.port
        options["category"] = self.task.category
        options["target"] = self.task.target
        options["package"] = self.task.package
        options["options"] = self.task.options
        options["enforce_timeout"] = self.task.enforce_timeout

        ### JG: added interaction and internet options
        options["interaction"] = int(self.task.interaction)
        options["internet"] = int(self.task.internet)
        if self.task.filename == None:
            self.task.filename = self.task.target
        options["filename"] = File(self.task.filename).get_name()

        if not self.task.timeout or self.task.timeout == 0:
            options["timeout"] = self.cfg.timeouts.default
        else:
            options["timeout"] = self.task.timeout

        ### JG: added check for interaction mode
        if self.task.category == "file" and options["interaction"] < 2:
            options["file_name"] = File(self.task.target).get_name()
            options["file_type"] = File(self.task.target).get_type()
        else:
            options["file_name"] = ""
            options["file_type"] = ""

        return options

    def launch_analysis(self):
        """Start analysis."""
        sniffer = None
        succeeded = False

        log.info("Starting analysis of %s \"%s\" (task=%d)", self.task.category.upper(), self.task.target, self.task.id)

        # Initialize the the analysis folders.
        if not self.init_storage():
            return False

        ### JG: added interaction
        if self.task.category == "file" and self.task.interaction < 2:
            # Store a copy of the original file.
            if not self.store_file():
                return False

        # Generate the analysis configuration file.
        options = self.build_options()

        ### JG: added log output
        if options['interaction'] > 0:
            log.info("Starting analysis by interactive command shell or browser")

        # Acquire analysis machine.
        machine = self.acquire_machine()

        # At this point we can tell the Resultserver about it
        try:
            Resultserver().add_task(self.task, machine)
        except Exception as e:
            mmanager.release(machine.label)
            self.errors.put(e)

        # If enabled in the configuration, start the tcpdump instance.
        if self.cfg.sniffer.enabled:
            sniffer = Sniffer(self.cfg.sniffer.tcpdump)
            sniffer.start(interface=self.cfg.sniffer.interface,
                          host=machine.ip,
                          file_path=os.path.join(self.storage, "dump.pcap"))

        ### JG: If enabled in the configuration, start the netflow probe instance.
        if self.cfg.netflow.enabled:
            fprobe = Netflow(self.cfg.netflow.generator, self.cfg.netflow.collector)
            nflowPort = int(machine.ip.split('.')[-1])
            fprobe.start(interface=self.cfg.sniffer.interface, dst=self.cfg.netflow.destination, dport=nflowPort, file_path=os.path.join(self.storage))
        else:
            fprobe = False

        ### JG: If enabled in the configuration, start the fake DNS server.
        if self.cfg.fakedns.enabled:
            fdns = fakeDNS(self.cfg.fakedns.fakedns)
            fdns.start(ip=self.cfg.fakedns.dnsip, withInternet=options["internet"])
        else:
            fdns = False

        ### JG: check if NAT should be enabled
        if options["internet"]:
            try:
                pargs = ['/usr/bin/sudo', self.cfg.nat.enable]
                enableNAT = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except (OSError, ValueError) as e:
                log.error("Failed to enable NAT" % (e))
        else:
            try:
                pargs = ['/usr/bin/sudo', self.cfg.nat.disable]
                disableNAT = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except (OSError, ValueError) as e:
                log.error("Failed to disable NAT" % (e))

        try:
            # Mark the selected analysis machine in the database as started.
            guest_log = Database().guest_start(self.task.id,
                                               machine.name,
                                               machine.label,
                                               mmanager.__class__.__name__)
            # Start the machine.
            mmanager.start(machine.label)
        except CuckooMachineError as e:
            log.error(str(e), extra={"task_id" : self.task.id})

            # Stop the sniffer.
            if sniffer:
                sniffer.stop()
            ### JG: Stop netflow
            if fprobe:
                fprobe.stop()
            ### JG: Stop fakeDNS
            if fdns:
                fdns.stop()
            ### JG: Disable NAT
            if options["internet"]:
                try:
                    pargs = ['/usr/bin/sudo', self.cfg.nat.disable]
                    disableNAT = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except (OSError, ValueError) as e:
                    log.error("Failed to enable NAT: %s" % (e))

            return False
        else:
            try:
                # Initialize the guest manager.
                guest = GuestManager(machine.name, machine.ip, machine.platform)
                # Start the analysis.
                guest.start_analysis(options)
		log.info("guest initialization successfull.")
            except CuckooGuestError as e:
                log.error(str(e), extra={"task_id" : self.task.id})

                # Stop the sniffer.
                if sniffer:
                    sniffer.stop()
                ### JG: Stop netflow
                if fprobe:
                    fprobe.stop()
                ### JG: Stop fakeDNS
                if fdns:
                    fdns.stop()
                ### JG: Disable NAT
                if options["internet"]:
                    try:
                        pargs = ['/usr/bin/sudo', self.cfg.nat.disable]
                        disableNAT = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    except (OSError, ValueError) as e:
                        log.error("Failed to enable NAT: %s" % (e))

                return False
            else:
                # Wait for analysis completion.
                try:
                    guest.wait_for_completion()
                    succeeded = True
                except CuckooGuestError as e:
                    log.error(str(e), extra={"task_id" : self.task.id})
                    succeeded = False

        finally:
            # Stop the sniffer.
            if sniffer:
                sniffer.stop()
            ### JG: Stop netflow
            if fprobe:
                fprobe.stop()
            ### JG: Stop fakeDNS
            if fdns:
                fdns.stop()
            ### JG: Disable NAT
            if options["internet"]:
                try:
                    pargs = ['/usr/bin/sudo', self.cfg.nat.disable]
                    disableNAT = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except (OSError, ValueError) as e:
                    log.error("Failed to enable NAT: %s" % (e))

            # Take a memory dump of the machine before shutting it off.
            if self.cfg.cuckoo.memory_dump or self.task.memory:
                try:
                    mmanager.dump_memory(machine.label,
                                         os.path.join(self.storage, "memory.dmp"))
                except NotImplementedError:
                    log.error("The memory dump functionality is not available "
                              "for current machine manager")
                except CuckooMachineError as e:
                    log.error(e)

            try:
                # Stop the analysis machine.
                mmanager.stop(machine.label)
            except CuckooMachineError as e:
                log.warning("Unable to stop machine %s: %s", machine.label, e)

            # Market the machine in the database as stopped.
            Database().guest_stop(guest_log)

            try:
                # Release the analysis machine.
                mmanager.release(machine.label)
            except CuckooMachineError as e:
                log.error("Unable to release machine %s, reason %s. "
                          "You might need to restore it manually", machine.label, e)

            # after all this, we can make the Resultserver forget about it
            Resultserver().del_task(self.task, machine)

        return succeeded

    def process_results(self):
        """Process the analysis results and generate the enabled reports."""
        try:
            logs_path = os.path.join(self.storage, "logs")
            for csv in os.listdir(logs_path):
                if not csv.endswith(".raw"):
                    if csv.endswith(".csv"):
                        self.reduceCSV(os.path.join(logs_path, csv))
                    continue
                csv = os.path.join(logs_path, csv)
                if os.stat(csv).st_size > self.cfg.processing.analysis_size_limit:
                    log.error("Analysis file %s is too big to be processed, "
                              "analysis aborted. Process it manually with the "
                              "provided utilities", csv)
                    return False
        except OSError as e:
            log.warning("Error accessing analysis logs (task=%d): %s", self.task.id, e)

        ### JG: added interaction parameter
        results = Processor(self.task.id, self.task.interaction).run()
        Reporter(self.task.id, self.task.interaction).run(results)

        # If the target is a file and the user enabled the option,
        # delete the original copy.
        if self.task.category == "file" and self.cfg.cuckoo.delete_original:
            try:
                os.remove(self.task.target)
            except OSError as e:
                log.error("Unable to delete original file at path \"%s\": "
                          "%s", self.task.target, e)

        log.info("Task #%d: reports generation completed (path=%s)", self.task.id, self.storage)

        return True

    def reduceCSV(self, csv):
        """remove duplicate lines from CSV"""
        ### JG: function added to remove duplicate lines from large CSVs
        import copy
        previousLine = ""
        log.info("working on csv file %s, trying to remove duplicate lines ..." % (csv))
        try:
            with open(csv, 'r') as f, open(csv+'.red', 'w') as o:
                for line in f:
                    if line != previousLine:
                        o.write(line)
                        previousLine = copy.copy(line)
            if os.stat(csv+'.red').st_size > self.cfg.processing.analysis_size_limit:
                log.warning("Analysis file %s is too big to be processed. Analysis aborted. You can process it manually", csv)
                return False
            else:
                os.rename(csv, csv+'.original')
                os.rename(csv+'.red', csv)
                log.info("csv log successfully reduced in size (%s)" % (csv))
                return True
        except StandardError as e:
            log.error('failed reducing CSV: %s', e)
            return False
        return False

    def run(self):
        """Run manager thread."""
        success = self.launch_analysis()
        Database().complete(self.task.id, success)

        self.process_results()

        log.debug("Released database task #%d with status %s", self.task.id, success)
        log.info("Task #%d: analysis procedure completed", self.task.id)

class Scheduler:
    """Tasks Scheduler.

    This class is responsible for the main execution loop of the tool. It
    prepares the analysis machines and keep waiting and loading for new
    analysis tasks.
    Whenever a new task is available, it launches AnalysisManager which will
    take care of running the full analysis process and operating with the
    assigned analysis machine.
    """

    def __init__(self):
        self.running = True
        self.cfg = Config()
        self.db = Database()

    def initialize(self):
        """Initialize the machine manager."""
        global mmanager

        mmanager_name = self.cfg.cuckoo.machine_manager

        log.info("Using \"%s\" machine manager", mmanager_name)

        # Get registered class name. Only one machine manager is imported,
        # therefore there should be only one class in the list.
        plugin = list_plugins("machinemanagers")[0]
        # Initialize the machine manager.
        mmanager = plugin()

        # Find its configuration file.
        conf = os.path.join(CUCKOO_ROOT, "conf", "%s.conf" % mmanager_name)

        if not os.path.exists(conf):
            raise CuckooCriticalError("The configuration file for machine "
                                      "manager \"{0}\" does not exist at path: "
                                      "{1}".format(mmanager_name, conf))

        # Provide a dictionary with the configuration options to the
        # machine manager instance.
        mmanager.set_options(Config(conf))
        # Initialize the machine manager.
        mmanager.initialize(mmanager_name)

        # At this point all the available machines should have been identified
        # and added to the list. If none were found, Cuckoo needs to abort the
        # execution.
        if len(mmanager.machines()) == 0:
            raise CuckooCriticalError("No machines available")
        else:
            log.info("Loaded %s machine/s", len(mmanager.machines()))

        ### JG: restore snapshots of all virtual machines
        virtualMachinesList = mmanager.machines()
        for vm in virtualMachinesList:
            mmanager.restore_snapshot(vm.label)

    def stop(self):
        """Stop scheduler."""
        self.running = False
        # Shutdown machine manager (used to kill machines that still alive).
        mmanager.shutdown()

    def start(self):
        """Start scheduler."""
        self.initialize()

        log.info("Waiting for analysis tasks...")

        # Message queue with threads to transmit exceptions (used as IPC).
        errors = Queue.Queue()

        # This loop runs forever.
        while self.running:
            ### JG: added try except to catch keyboard interrrupt and restore VMs
            try:
                time.sleep(1)

                # If no machines are available, it's pointless to fetch for
                # pending tasks. Loop over.
                if mmanager.availables() == 0:
                    continue

                # Fetch a pending analysis task.
                task = self.db.fetch_and_process()

                if task:
                    log.debug("Processing task #%s", task.id)

                    # Initialize the analysis manager.
                    analysis = AnalysisManager(task, errors)
                    # Start.
                    analysis.start()

                # Deal with errors.
                try:
                    exc = errors.get(block=False)
                except Queue.Empty:
                    pass
                else:
                    raise exc
            except KeyboardInterrupt:
                log.info("keyboard interrupt")
                break
        ### JG: restore snapshots of all virtual machines
        virtualMachinesList = mmanager.machines()
        for vm in virtualMachinesList:
            mmanager.restore_snapshot(vm.label)
        log.info("back for good ...")
