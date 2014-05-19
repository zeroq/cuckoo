#!/usr/bin/python2.7

import csv
import sys
import json
import os
import logging

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.utils import convert_to_printable

log = logging.getLogger(__name__)

class CreateNicerSummary(Processing):
    order = 3

    def __init__(self):
        self.ERROR_MAPPING = {
            "0": "STATUS_SUCCESS",
            "0x00000000": "STATUS_SUCCESS",
            "1": "STATUS_WAIT_1",
            "0x00000001": "STATUS_WAIT_1",
            "3221225524": "STATUS_OBJECT_NAME_NOT_FOUND",
            "0xc0000034": "STATUS_OBJECT_NAME_NOT_FOUND",
            "3221225530": "STATUS_OBJECT_PATH_NOT_FOUND",
            "0xc000003a": "STATUS_OBJECT_PATH_NOT_FOUND"
        }

        self.DIRECT_ACCESS_MAPPING = {
            "0x001f01ff": "FILE_ALL_ACCESS",
            "0x80000000": "GENERIC_READ",
            "0x40000000": "GENERIC_WRITE",
            "0x20000000": "GENERIC_EXECUTE",
            "0x10000000": "GENERIC_ALL"
        }

        self.REG_ACCESS_MAPPING = {
            "33554432": "MAXIMUM_ALLOWED",
            "0x2000000": "MAXIMUM_ALLOWED",
            "983103": "ALL_ACCESS",
            "131097": "READ_EXECUTE",
            "131078": "WRITE",
            "131103": "ALL_ACCESS"
        }

        self.REGISTRY_MAPPING = {
            "0x80000000": "HKEY_CLASSES_ROOT",
            "0x80000001": "HKEY_CURRENT_USER",
            "0x80000002": "HKEY_LOCAL_MACHINE",
            "0x80000003": "HKEY_USERS",
            "0x80000004": "HKEY_PERFORMANCE_DATA",
            "0x80000005": "HKEY_CURRENT_CONFIG"
        }

        self.REG_TYPE_MAPPING = {
            "1": "REG_SZ",
            "2": "EXPAND_SZ",
            "3": "REG_BINARY",
            "4": "REG_DWORD",
            "5": "DWORD_BIG_ENDIAN",
            "6": "LINK"
        }

        self.REG_STATUS_MAPPING = {
            "0": "REG_SUCCESS",
            "2": "REG_NOT_FOUND",
            "5": "REG_ACCESS_DENIED",
            "259": "ERROR_NO_MORE_ITEMS"
        }

        self.SERVICE_SC_MAPPING = {
            "1": "SC_MANAGER_CONNECT",
            "2": "SC_MANAGER_CREATE_SERVICE",
            "4": "SC_MANAGER_ENUMERATE_SERVICE",
            "983103": "SC_MANAGER_ALL_ACCESS",
            "2147483648": "GENERIC_READ"
        }

        self.SERVICE_OPEN_MAPPING = {
            "4": "SERVICE_QUERY_STATUS",
            "5": "ACCESS_DENIED",
            "983551": "SERVICE_ALL_ACCESS"
        }

        self.SERVICE_CONTROL_MAPPING = {
            "1": "SERVICE_CONTROL_STOP",
            "2": "SERVICE_CONTROL_PAUSE"
        }

        self.SERVICE_STATUS_MAPPING = {
            "0": "FAILED",
            "1": "SUCCESS"
        }


    def convertAccessMode(self, accessmode, ftype):
        modes = []
        bitVector = bin(int(accessmode, 16))[2:].zfill(32)[::-1]

        ### debug
        value = 0
        positions = []
        for index in range(0, 32):
            bit = bitVector[index]
            if int(bit) == 1:
                positions.append(index)
                value += 2**index

        if bitVector[31] == '1':
            modes.append("GENERIC_READ")
        if bitVector[30] == '1':
            modes.append("GENERIC_WRITE")
        if bitVector[29] == '1':
            modes.append("GENERIC_EXECUTE")
        if bitVector[28] == '1':
            modes.append("GENERIC_ALL")

        if bitVector[25] == '1':
            modes.append("MAXIMUM_ALLOWED")
        if bitVector[24] == '1':
            modes.append("SACL")

        if bitVector[20] == '1':
            modes.append("SYNCHRONIZE")
        if bitVector[19] == '1':
            modes.append("WRITE_OWNER")
        if bitVector[18] == '1':
            modes.append("WRITE_DAC")
        if bitVector[17] == '1':
            modes.append("READ_CONTROL")
        if bitVector[16] == '1':
            modes.append("DELETE")

        if bitVector[8] == '1':
            modes.append("WRITE_ATTRIBUTES")
        if bitVector[7] == '1':
            modes.append("READ_ATTRIBUTES")
        if bitVector[6] == '1':
            modes.append("DELETE_CHILD")
        if bitVector[5] == '1':
            modes.append("EXECUTE")
        if bitVector[4] == '1':
            modes.append("FILE_WRITE_EXTENDED_ATTRIBUTES")
        if bitVector[3] == '1':
            modes.append("FILE_READ_EXTENDED_ATTRIBUTES")
        if bitVector[2] == '1':
            modes.append("FILE_APPEND")
        if bitVector[1] == '1':
            modes.append("FILE_WRITE")
        if bitVector[0] == '1':
            modes.append("FILE_READ")

        if bitVector[2] == '1' and ftype == 'pipe':
            modes.append("FILE_CREATE_PIPE_INSTANCE")

        return "%s - %s - %s" % (bitVector,accessmode, positions), modes

    def getRegValues(self, parts):
        regpath = None
        registry = None
        access = None
        handle = None
        for item in parts:
            if item.lower().startswith("registry->"):
                registry = item.split('->')[1].lower()
            elif item.lower().startswith("subkey->"):
                regpath = item.split('->')[1].replace('\\\\', '\\')
            elif item.lower().startswith("access->"):
                access = item.split('->')[1]
            elif item.lower().startswith("handle->"):
                handle = item.split('->')[1]
        return regpath, registry, access, handle

    def getKeyAndValue(self, parts):
        regkey = None
        regtype = None
        regbuffer = None
        for item in parts:
            if item.lower().startswith("valuename->"):
                regkey = item.split('->')[1]
            elif item.lower().startswith("type->"):
                regtype = item.split('->')[1]
            elif item.lower().startswith("buffer->"):
                regbuffer = item.split('->')[1]
        return regkey, regtype, regbuffer


    def handleRegistry(self, row, registryDict):
        item = None
        if (row[6].lower() == 'regcreatekeyexa' or row[6].lower() == 'regcreatekeyexw') and len(row) >= 13:
            """
            check for registry create key
            """
            api = row[6]
            status = row[7]
            failurecode = row[8].strip()
            regpath, registry, access, handle = self.getRegValues(row[9:])
            try:
                failuremessage = self.REG_STATUS_MAPPING[failurecode]
            except:
                failuremessage = failurecode
            try:
                hive = self.REGISTRY_MAPPING[registry]
            except StandardError as e:
                hive = registry
                if hive in registryDict['inProgress']:
                    oitem = registryDict['inProgress'][hive]
                    hive = oitem['hive']
                    regpath = "%s\\%s" % (oitem['path'], regpath)
            try:
                accessmode = self.REG_ACCESS_MAPPING[access.lower()]
            except:
                accessmode = access.lower()
            item = {"api": [api], "method": "read", "hive": hive, "status": [status], "statusmessage": [failuremessage], "path": regpath, "handle": handle, "access": accessmode, "key": [''], "type": [''], "value": [''], "data": ['']}
            if int(failurecode) == 0:
                registryDict['inProgress'][handle] = item
                item = None
        elif row[6].lower() == 'regclosekey' and len(row) >= 10:
            """
            check for registry close key
            """
            api = row[6]
            regpath, registry, access, handle = self.getRegValues(row[9:])
            item = registryDict['inProgress'].pop(handle, None)
            if item:
                item['api'].append(api)
                if not item.has_key("method"):
                    item['method'] = 'read'
        elif (row[6].lower() == 'regsetvalueexw' or row[6].lower() == 'regsetvalueexa') and len(row) >= 12:
            """
            check for registry set value
            """
            api = row[6]
            status = row[7]
            failurecode = row[8].strip()
            try:
                failuremessage = self.REG_STATUS_MAPPING[failurecode]
            except:
                failuremessage = failurecode
            regpath, registry, access, handle = self.getRegValues(row[9:])
            try:
                item = registryDict['inProgress'][handle]
            except:
                return
            item['api'].append(api)
            item['method'] = 'write'
            regkey, regtype, regvalue = self.getKeyAndValue(row[10:])
            if not 'key' in item:
                item['key'] = [regkey]
            else:
                item['key'].append(regkey)
            if not 'value' in item:
                item['value'] = [regvalue]
            else:
                item['value'].append(regvalue)
            try:
                if not 'type' in item:
                    item['type'] = [self.REG_TYPE_MAPPING[regtype]]
                else:
                    item['type'].append(self.REG_TYPE_MAPPING[regtype])
            except:
                item['type'] = regtype
            item['status'].append(status)
            item['statusmessage'].append(failuremessage)
            registryDict['inProgress'][handle] = item
            item = None
        elif (row[6].lower() == 'regqueryvalueexa' or row[6].lower() == 'regqueryvalueexw') and len(row) >= 11:
            """
            check for registry query value
            """
            api = row[6]
            status = row[7]
            failurecode = row[8].strip()
            try:
                failuremessage = self.REG_STATUS_MAPPING[failurecode]
            except:
                failuremessage = failurecode
            regpath, registry, access, handle = self.getRegValues(row[9:])
            try:
                item = registryDict['inProgress'][handle]
            except:
                return
            item['api'].append(api)
            item['method'] = 'read'
            item['status'].append(status)
            item['statusmessage'].append(failuremessage)
            regkey, regdata, regbuffer = self.getKeyAndValue(row[10:])
            if not 'key' in item:
                item['key'] = [regkey]
            else:
                item['key'].append(regkey)
            if not 'data' in item:
                item['data'] = [regdata]
            else:
                item['data'].append(regdata)
            registryDict['inProgress'][handle] = item
            item = None
        elif (row[6].lower() == 'regopenkeyexa' or row[6].lower() == 'regopenkeyexw') and len(row) >= 12:
            """
            check for registry open key
            """
            api = row[6]
            status = row[7]
            failurecode = row[8].strip()
            regpath, registry, access, handle = self.getRegValues(row[9:])
            try:
                failuremessage = self.REG_STATUS_MAPPING[failurecode]
            except:
                failuremessage = failurecode
            try:
                hive = self.REGISTRY_MAPPING[registry]
            except StandardError as e:
                hive = registry
                if hive in registryDict['inProgress']:
                    oitem = registryDict['inProgress'][hive]
                    hive = oitem['hive']
                    regpath = "%s\\%s" % (oitem['path'], regpath)
            item = {"api": [api], "method": "read", "hive": hive, "status": [status], "statusmessage": [failuremessage], "path": regpath, "handle": handle, "access": "", "key": [''], "type": [''], "value": [''], "data": ['']}
            if int(failurecode) == 0:
                registryDict['inProgress'][handle] = item
                item = None
        elif (row[6].lower() == 'regenumkeyexa' or row[6].lower() == 'regenumkeyexw') and len(row) >= 13:
            """
            check for key enumeration
            """
            api = row[6]
            status = row[7]
            failurecode = row[8].strip()
            try:
                failuremessage = self.REG_STATUS_MAPPING[failurecode]
            except:
                failuremessage = failurecode
            regpath, registry, access, handle = self.getRegValues(row[9:])
            try:
                item = registryDict['inProgress'][handle]
            except:
                return
            item['api'].append(api)
            item['method'] = 'enumerate'
            item['status'].append(status)
            item['statusmessage'].append(failuremessage)
            regkey, regdata, regbuffer = self.getKeyAndValue(row[10:])
            if not 'data' in item:
                item['data'] = [regdata]
            else:
                item['data'].append(regdata)
            registryDict['inProgress'][handle] = item
            item = None
        else:
            #print row
            return
        if item:
            if registryDict.has_key(item['method']):
                registryDict[item['method']].append( item )
            else:
                registryDict[item['method']] = [ item ]
        return

    def getValues(self, parts):
        accessmode = None
        filename = None
        for item in parts:
            if item.lower().startswith("desiredaccess->"):
                accessmode = item.split('->')[1]
            elif item.lower().startswith("filename->"):
                filename = item.split('->')[1].replace('\\\\', '\\')
        return accessmode, filename

    def getSourceDestination(self, parts):
        src = None
        dst = None
        for item in parts:
            if item.lower().startswith("existingfilename->"):
                src = item.split('->')[1].replace('\\\\', '\\')
            elif item.lower().startswith("newfilename->"):
                dst = item.split('->')[1].replace('\\\\', '\\')
        return src, dst

    def handleFilesystem(self, row, filesysDict):
        filename = None
        modes = None
        srcFile = None
        dstFile = None
        if (row[6].lower() == 'ntcreatefile' or row[6].lower() == 'ntopenfile') and len(row) >= 13:
            api = row[6]
            status = row[7]
            failurecode = row[8].strip()
            try:
                failurereason = self.ERROR_MAPPING[failurecode.lower()]
            except:
                failurereason = "Unknown"
            accessmode, filename = self.getValues(row[9:])
            try:
                modes = [self.DIRECT_ACCESS_MAPPING[accessmode.lower()]]
            except:
                pass
        elif (row[6].lower() == 'deletefilew' or row[6].lower() == 'deletefilea') and len(row) == 10:
            api = row[6]
            status = row[7]
            failurecode = row[8].strip()
            try:
                failurereason = self.ERROR_MAPPING[failurecode.lower()]
            except:
                failurereason = "Unknown"
            accessmode, filename = self.getValues(row[9:])
            if filename.startswith('\\??\\'):
                filename = filename[4:]
            accessmode = api
            modes = ["FILE_DELETE"]
        elif (row[6].lower() == 'copyfilea' or row[6].lower() == 'copyfilew') and len(row) == 11:
            api = row[6]
            status = row[7]
            failurecode = row[8].strip()
            try:
                failurereason = self.ERROR_MAPPING[failurecode.lower()]
            except:
                failurereason = "Unknown"
            srcFile, dstFile = self.getSourceDestination(row[9:])
            if srcFile.startswith('\\??\\'):
                srcFile = srcFile[4:]
            if dstFile.startswith('\\??\\'):
                dstFile = dstFile[4:]
            accessmode = api
            modes = ["FILE_COPY"]
        else:
            #print row
            return

        if filename:
            if filename.startswith('\\??\\'):
                filename = filename[4:]
            if filename.lower().count('\\pipe')>0 or filename.lower().count('pipe\\')>0:
                ftype = 'pipe'
            elif filename.lower().count('\\device')>0:
                ftype = 'device'
            else:
                ftype = 'file'
            if not modes:
                accessmode, modes = self.convertAccessMode(accessmode, ftype)
            item = {"filename": filename, "status": status, "accessmodes": modes, "statusmessage": failurereason, "debug": accessmode, "type": ftype}
            if filesysDict.has_key(api) and filesysDict[api].has_key(accessmode):
                if item not in filesysDict[api][accessmode]:
                    filesysDict[api][accessmode].append( item )
            elif filesysDict.has_key(api):
                filesysDict[api][accessmode] = [ item ]
            else:
                filesysDict[api] = {}
                filesysDict[api][accessmode] = [ item ]
        elif srcFile and dstFile:
            ftype = 'file'
            item = {"source_filename": srcFile, "destination_filename": dstFile, "status": status, "accessmodes": modes, "statusmessage": failurereason, "debug": accessmode, "type": ftype}
            if filesysDict.has_key(api) and filesysDict[api].has_key(accessmode):
                if item not in filesysDict[api][accessmode]:
                    filesysDict[api][accessmode].append( item )
            elif filesysDict.has_key(api):
                filesysDict[api][accessmode] = [ item ]
            else:
                filesysDict[api] = {}
                filesysDict[api][accessmode] = [ item ]
        return

    def unicode_reader(self, data, dialect=csv.excel, **kwargs):
        csv_reader = csv.reader(data, dialect=dialect, **kwargs)
        for row in csv_reader:
            yield [cell.decode('utf-8', errors='ignore') for cell in row]

    def run(self):
        self.key = "newsummary"
        BLOCKSIZE = 1048576

        if not os.path.exists(self.logs_path):
            log.error("Analysis results folder does not exist at path \"%s\"." % self.logs_path)
            return {}

        if len(os.listdir(self.logs_path)) == 0:
            log.error("Analysis results folder does not contain any file.")
            return {}

        filesysDict = {}
        registryDict = {}
        registryDict['inProgress'] = {}
        registryDict['read'] = []
        registryDict['write'] = []
        registryDict['enumerate'] = []
        for file_name in os.listdir(self.logs_path):
            file_path = os.path.join(self.logs_path, file_name)

            if os.path.isdir(file_path):
                continue

            if not file_path.endswith(".csv"):
                continue

            ### test for NULL bytes
            fp = open(file_path, 'rb')
            content = fp.read()
            fp.close()
            fp = open(file_path, 'wb')
            fp.write(content.replace('\x00', ''))
            fp.close()

            with open(file_path, 'rU') as csvfile:
                #behaviorReader = csv.reader(csvfile, delimiter=',', quotechar='"')
                behaviorReader = self.unicode_reader(csvfile, delimiter=',', quotechar='"')
                while True:
                    try:
                        row = behaviorReader.next()
                        if row and len(row)>5 and row[5] == 'filesystem':
                            self.handleFilesystem(row, filesysDict)
                        elif row and len(row)>5 and row[5] == 'registry':
                            self.handleRegistry(row, registryDict)
                    except csv.Error:
                        continue
                    except StopIteration:
                        break

        resultDict = {}
        resultDict['filesystem'] = {}
        resultDict['filesystem']['read'] = []
        resultDict['filesystem']['write'] = []
        resultDict['filesystem']['execute'] = []
        resultDict['filesystem']['delete'] = []
        resultDict['filesystem']['copy'] = []
        resultDict['filesystem']['read_attributes'] = []

        resultDict['registry'] = {}
        resultDict['registry']['write'] = registryDict['write']
        resultDict['registry']['read'] = registryDict['read']
        resultDict['registry']['enumerate'] = registryDict['enumerate']
        resultDict['mutex'] = {}

        for api in filesysDict:
            for access in filesysDict[api]:
                files = filesysDict[api][access]
                for f in files:
                    found = False
                    for access in f['accessmodes']:
                        if access.count('FILE_READ')>0 or access.count('GENERIC_READ')>0 or access.count('FILE_ALL_ACCESS')>0:
                            resultDict['filesystem']['read'].append(f)
                            found = True
                        if access.count('FILE_WRITE')>0 or access.count('GENERIC_WRITE')>0 or access.count('FILE_ALL_ACCESS')>0:
                            resultDict['filesystem']['write'].append(f)
                            found = True
                        if access.count('EXECUTE')>0 or access.count('FILE_ALL_ACCESS')>0:
                            resultDict['filesystem']['execute'].append(f)
                            found = True
                        if access.count('FILE_DELETE')>0:
                            resultDict['filesystem']['delete'].append(f)
                            found = True
                        if access.count('READ_ATTRIBUTES')>0:
                            resultDict['filesystem']['read_attributes'].append(f)
                            found = True
                        if access.count('FILE_COPY')>0:
                            resultDict['filesystem']['copy'].append(f)
                            found = True
                    if not found:
                        #print found, f
                        pass

        return resultDict
