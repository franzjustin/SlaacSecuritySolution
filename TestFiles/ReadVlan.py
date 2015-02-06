
import pcapy
import __builtin__
from pcapy import findalldevs
import impacket
from impacket.ImpactDecoder import *
from impacket.ImpactPacket import *
import os.path
import dpkt


f = open('../Packets/VLANS[Legit-1].s0i0.pcap')
pcap = dpkt.pcap.Reader(f)
i = 1

for ts, buf in pcap:
    eth = EthDecoder().decode(buf)
    icmp6 = ICMP6Decoder().decode(buf)
    ethchild = eth.child()
    ethChild2 = ethchild.child()
    icmp6Child = icmp6.child()

    frame = '\x54\xab\xa3\xb9\x38\x3d\xe2\xef\x8d\xc7\xa8\x5e\x81\x00\xac\xf3\x08\x00'
    eth1 = Ethernet(buf)

    ether = ImpactPacket.Ethernet(buf)
    print ether.get_tag(-1)


    #buffer = ImpactPacket.PacketBuffer()

    #register = ImpactPacket.EthernetTag(buf)

    #print register.get_vid()
    #packetData = (ethChild2.get_originating_packet_data())
    #packetHex = []
    #for data in packetData:
    #    packetHex.append(hex(data))
        #convert to hex