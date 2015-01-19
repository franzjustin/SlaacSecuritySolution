import pcapy
from pcapy import findalldevs

from impacket.ImpactDecoder import *

from ClassS3 import  DataParse


def getInterface():
    ifs = findalldevs()
    if 0 == len(ifs):
        print "You don't have enough permissions to open any interface on this system."
        sys.exit(1)

    # Only one interface available, use it.
    elif 1 == len(ifs):
        print 'Only one interface present, defaulting to it.'
        return ifs[0]

    # Ask the user to choose an interface from the list.
    count = 0
    for iface in ifs:
        print '%i - %s' % (count, iface)
        count += 1
    idx = int(raw_input('Please select an interface: '))

    return ifs[idx]




    #list all the network devices

pcapy.findalldevs()
max_bytes = 1024
promiscuous = False
read_timeout = 100 # in milliseconds
pc = pcapy.open_live(getInterface(), max_bytes, promiscuous, read_timeout)
pc.setfilter('tcp')
parser = DataParse.Dataparse()
    # callback for received packets

def recv_pkts(hdr, data):
    try:
        mode = False
        parser.sniffSlaac(data,mode)
        #print "Hello"

    except:
        x = 1

packet_limit = -1 # infinite
pc.loop(packet_limit, recv_pkts) # capture packets

