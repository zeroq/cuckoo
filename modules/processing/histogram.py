import matplotlib
matplotlib.use('Agg', warn=False)
import matplotlib.pyplot as plt

from lib.cuckoo.common.objects import File
from lib.cuckoo.common.abstracts import Processing
import os
import sys
import struct
import logging


log = logging.getLogger(__name__)

class Histogram(Processing):
    """ Draw histogram of byte distribution """

    def run(self):
        """
        Create histogram and store as PNG.
        @return: path to png.
        """
        self.key = "histogram"
        histogram = {}

        if not os.path.exists(self.file_path):
            return {}
        if not os.path.isfile(self.file_path):
            return {}

        try:
            fp = open(self.file_path)
            content = fp.read()
            fp.close()
            bucket = []
            for byte in content:
                num = struct.unpack('B', byte)[0]
                bucket.append(num)

            fig = plt.figure()
            ax = fig.add_subplot(111)

            ax.hist(bucket, bins=range(0, 256), normed=0, facecolor='blue', edgecolor='black', alpha=0.8, log=True)
            ax.set_title('Byte Histogram')
            ax.set_xlabel('Byte Values')
            ax.set_ylabel('Frequency')
            ax.set_xlim(0, 255)
            ax.grid(True)
            pngPath = os.path.join(self.analysis_path, 'histogram.png')
            fig.savefig(pngPath)
        except StandardError as e:
            log.warning("failed to create histogram: %s" % (e))
            return {}

        histogram["path"] = pngPath
        return histogram
