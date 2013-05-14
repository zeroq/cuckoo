#!/usr/bin/python2.7

import csv
import sys
import json
import os
import logging

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.utils import convert_to_printable

log = logging.getLogger(__name__)

class CreateNicerSummery(Processing):

	def __init__(self):
		self.ERROR_MAPPING = {
			"0x00000000": "STATUS_SUCCESS",
			"0x00000001": "STATUS_WAIT_1",
			"0xc0000034": "STATUS_OBJECT_NAME_NOT_FOUND"
			}

		self.DIRECT_ACCESS_MAPPING = {
			"0x001f01ff": "FILE_ALL_ACCESS",
			"0x80000000": "GENERIC_READ",
			"0x40000000": "GENERIC_WRITE",
			"0x20000000": "GENERIC_EXECUTE",
			"0x10000000": "GENERIC_ALL"
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

	def handleFilesystem(self, row, filesysDict):
		filename = None
		srcFile = None
		dstFile = None
		if row[6].lower() == 'ntcreatefile' and len(row) >= 13:
			api = row[6]
			status = row[7]

			failurecode = row[8]
			try:
				failurereason = self.ERROR_MAPPING[failurecode.lower()]
			except:
				failurereason = "Unknown"

			filehandle = row[9]
			accessmode = row[10].split('->')[1]

			filename = row[11].split('->')[1]
			if filename.startswith('\\??\\'):
				filename = filename[4:]

			createdisposition = row[12]

			if filename.lower().count('\\pipe')>0:
				ftype = 'pipe'
			elif filename.lower().count('\\device')>0:
				ftype = 'device'
			else:
				ftype = 'file'

			try:
				modes = [self.DIRECT_ACCESS_MAPPING[accessmode.lower()]]
			except:
				accessmode, modes = self.convertAccessMode(accessmode, ftype)
		elif (row[6].lower() == 'deletefilew' or row[6].lower() == 'deletefilea') and len(row) == 10:
			api = row[6]
			status = row[7]

			failurecode = row[8]
			try:
				failurereason = self.ERROR_MAPPING[failurecode.lower()]
			except:
				failurereason = "Unknown"

			filename = row[9].split('->')[1]
			if filename.startswith('\\??\\'):
				filename = filename[4:]

			if filename.lower().count('\\pipe')>0:
				ftype = 'pipe'
			elif filename.lower().count('\\device')>0:
				ftype = 'device'
			else:
				ftype = 'file'

			accessmode = api
			modes = ["FILE_DELETE"]
		elif (row[6].lower() == 'copyfilea' or row[6].lower() == 'copyfilew') and len(row) == 11:
			api = row[6]
			status = row[7]
			failurecode = row[8]
			try:
				failurereason = self.ERROR_MAPPING[failurecode.lower()]
			except:
				failurereason = "Unknown"

			srcFile = row[9].split('->')[1]
			if srcFile.startswith('\\??\\'):
				srcFile = srcFile[4:]
			dstFile = row[10].split('->')[1]
			if dstFile.startswith('\\??\\'):
				dstFile = dstFile[4:]

			accessmode = api
			modes = ["FILE_COPY"]
			ftype = 'file'

		else:
			return

		if filename:
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
		for file_name in os.listdir(self.logs_path):
			file_path = os.path.join(self.logs_path, file_name)

			if os.path.isdir(file_path):
				continue

			if not file_path.endswith(".csv"):
				continue

			with open(file_path+".converted", 'rb') as csvfile:
				behaviorReader = csv.reader(csvfile, delimiter=',', quotechar='"')
				while True:
					try:
						row = behaviorReader.next()
						if row and len(row)>5 and row[5] == 'filesystem':
							self.handleFilesystem(row, filesysDict)
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

		#print json.dumps(resultDict, sort_keys=True, indent=4, separators=(',', ': '))
		return resultDict
