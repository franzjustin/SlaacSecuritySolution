
import pcapy
import __builtin__
from pcapy import findalldevs
import impacket
from impacket.ImpactDecoder import *
from impacket.ImpactPacket import *
import os.path
import dpkt
from ClassS3 import DataParse


def check_ipv6_options(buf):
    ether = ImpactPacket.Ethernet(buf)
    vlanId = 0
    try:
        vlanId = ether.get_tag(-1).get_vid()
    except:
        trash = 0
    return vlanId

f = open('../Packets/VLANS[Legit-1]-NS With VLANS.s0i0.pcap')
pcap = dpkt.pcap.Reader(f)
i = 1

for ts, buf in pcap:
    eth = EthDecoder().decode(buf)
    icmp6 = ICMP6Decoder().decode(buf)
    ethchild = eth.child()
    ethChild2 = ethchild.child()
    icmp6Child = icmp6.child()
    data = DataParse.Dataparse("true")
    print data.sniffSlaac(buf)






    #buffer = ImpactPacket.PacketBuffer()

    #register = ImpactPacket.EthernetTag(buf)

    #print register.get_vid()
    #packetData = (ethChild2.get_originating_packet_data())
    #packetHex = []
    #for data in packetData:
    #    packetHex.append(hex(data))
        #convert to hex