import pcapy
import __builtin__
from pcapy import findalldevs
import impacket
from impacket.ImpactDecoder import *
import os.path
import dpkt


def getInterface():
    # Grab a list of interfaces that pcap is able to listen on.
    # The current user will be able to listen from all returned interfaces,
    # using open_live to open them.


    f = open('MyNigga.s0i0.pcap')
    pcap = dpkt.pcap.Reader(f)
    checker = ICMP6.ICMP6.protocol
    # print checker
    i = 1
    for ts, buf in pcap:
        eth = EthDecoder().decode(buf)
        icmp6 = ICMP6Decoder().decode(buf)
        ethchild = eth.child()
        ethChild2 = ethchild.child()
        icmp6Child = icmp6.child()
        #dpkt.ethernet.Ethernet()
        try:
            if ethChild2.get_ip_protocol_number() is not None:
                assert isinstance(icmp6Child, object)
                print icmp6Child
                packetData = (ethChild2.get_originating_packet_data())
                packetHex = []
                for data in packetData:
                    packetHex.append(hex(data))
                #convert to hex
        except:
            print "Error"

        ifs = findalldevs()




    # No interfaces available, abort.
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


# list all the network devices

pcapy.findalldevs()
max_bytes = 1024
promiscuous = False
read_timeout = 100  # in milliseconds
pc = pcapy.open_live(getInterface(), max_bytes, promiscuous, read_timeout)
pc.setfilter('')

# callback for received packets

def recv_pkts(hdr, data):
    print os.path.abspath(impacket.__file__)
    packet = EthDecoder().decode(data)
    print packet
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


packet_limit = -1  # infinite
pc.loop(packet_limit, recv_pkts)  # capture packets


