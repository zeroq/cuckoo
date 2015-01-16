#!/usr/bin/python

# Original Code from: http://code.activestate.com/recipes/491264-mini-fake-dns-server/
# By Francisco Santos

import sys
import socket

class DNSQuery:
  def __init__(self, data):
    self.data=data
    self.domain=''

    typ = (ord(data[2]) >> 3) & 15   # Opcode bits
    if typ == 0:                     # Standard query
      ini=12
      lon=ord(data[ini])
      while lon != 0:
        self.domain+=data[ini+1:ini+lon+1]+'.'
        ini+=lon+1
        lon=ord(data[ini])

  def request(self, ip):
    packet=''
    if self.domain:
      packet+=self.data[:2] + "\x81\x80"
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
      packet+=self.data[12:]                                         # Original Domain Name Question
      packet+='\xc0\x0c'                                             # Pointer to domain name
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
    return packet

if __name__ == '__main__':
  try:
    ip = sys.argv[1]
  except:
    ip='192.168.56.1'
  try:
    withInternet = int(sys.argv[2])
  except:
    withInternet = 0
  try:
    debug = int(sys.argv[3])
  except:
    debug = 0

  if debug:
    print 'IP: %s withInternet: %s' % (ip, withInternet)
    print 'pyminifakeDNS:: dom.query. 60 IN A %s' % ip

  udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udps.bind((ip,53))

  try:
    while 1:
      data, addr = udps.recvfrom(1024)
      p=DNSQuery(data)
      if withInternet == 1:
        try:
          realip = socket.gethostbyname(p.domain)
        except:
          realip = ip
        udps.sendto(p.request(realip), addr)
      else:
        udps.sendto(p.request(ip), addr)
      if debug:
        if withInternet == 1:
          print 'Request: %s -> %s' % (p.domain, realip)
        else:
          print 'Request: %s -> %s' % (p.domain, ip)
  except KeyboardInterrupt:
    if debug:
      print 'Done'
    udps.close()
