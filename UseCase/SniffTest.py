import pcapy
from pcapy import findalldevs

from impacket.ImpactDecoder import *

from ClassS3 import DataRead, Detection


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
     
    # callback for received packets
     
def recv_pkts(hdr, data):
    try:
        packet = EthDecoder().decode(data)
        print data
        readPacket = DataRead.DataRead('../Packets/RouterAdvertismentAttack-Test2.s0i1.pcap',data)
        detectRA = Detection()
        packetRed = readPacket.getSlaacSinglePacket()
        print readPacket.ndp_message_number
        detectRA.detect_rogue_advertisement(packetRed)
        print "RA Attack Detected"
    except:
        x = 1
    #print packet.get_ether_type()
    #print packet.get_header_size()
    #print packet.get_ether_dhost()
    #print packet.get_ether_dhost()
    #print packet.get_size()
    #print packet.get_data_as_string()
    #print packet.get_buffer_as_string()
    #print packet.get_bytes()
    #print packet.child()
    #packetChild = packet.child().child().child()
    #packet21 = ICMP6Decoder().decode(packetChild)
    #filename = "lol"
    #dumper = pc.dump_open(filename)
    #dumper.dump(hdr, data)
    #print dumper
      
packet_limit = -1 # infinite
pc.loop(packet_limit, recv_pkts) # capture packets

