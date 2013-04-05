import matplotlib
matplotlib.use('Agg', warn=False)
import matplotlib.pyplot as plt

import os.path
import sys
import struct
import binascii
import logging
import pefile
import pydasm


from lib.cuckoo.common.objects import File
from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

class visopcode(Processing):
    """ draw plot of opcode distribution of different pe sections """

    def run(self):
        """
        create plot and store as PNG
        @return: path to png
        """
        self.key = "visopcode"
        visopcode = {}

        if not os.path.exists(self.file_path):
            return {}
        if not os.path.isfile(self.file_path):
            return {}

        try:
            pe = pefile.PE(self.file_path)
        except StandardError as e:
            log.warning("no PE file, cannot create opcode graph: %s" % (e))
            return {}

        dbytes = 8
        try:
            for section in pe.sections:
                data = section.get_data()
                bucket = {}
                if len(data)==0:
                    continue
                offset = 0
                while offset < len(data):
                    instruction = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
                    str = ''
                    if not instruction or instruction.length+offset>len(data):
                        str += '%.2x  ' % ord(data[offset]) + ' '*(dbytes-1)*2
                        offset += 1
                    else:
                        ilen = instruction.length
                        for i in range(min(dbytes, ilen)):
                            str += '%.2x' % ord(data[offset+i])
                        offset += ilen
                        opcode = struct.unpack('B', binascii.a2b_hex(str[:2]))[0]
                        try:
                            bucket[opcode] += 1
                        except:
                            bucket[opcode] = 1
                #plt.plot(range(1, len(bucket)-1), bucket.values()[1:-1], label=section.Name.replace('\x00',''))
                plt.plot(range(0, len(bucket)), bucket.values(), label=section.Name.replace('\x00',''))
            plt.yscale('log')
            plt.title('Opcode Distribution of Sections')
            plt.xlabel('Opcode')
            plt.ylabel('Frequency')
            plt.xlim(1, 254)
            plt.grid(True)
            plt.legend()
            pngPath = os.path.join(self.analysis_path, 'opcodedistr.png')
            plt.savefig(pngPath)
        except StandardError as e:
            log.warning("failed to create opcode visualization: %s" % (e))
            return {}
        visopcode['path'] = pngPath
        return visopcode
