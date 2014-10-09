import time
import dpkt
from impacket import ICMP6, version
from impacket.ImpactDecoder import EthDecoder, ICMP6Decoder

from TestFiles import SLAAC_Message


print version.BANNER

f = open('../Packets/LastHopRouter.s0i1.pcap')
pcap = dpkt.pcap.Reader(f)
checker = ICMP6.ICMP6.protocol
#print "*****************"

#print checker
i = 1
for ts, buf in pcap:
    eth = EthDecoder().decode(buf)
    icmp6 = ICMP6Decoder().decode(buf)
    ethChild = eth.child() #contains layer 3 information on the packet
    ethChild2 = ethChild.child()
    icmp6Child = icmp6.child()

    #print ethChild2.child()
    #dpkt.ethernet.Ethernet()
    try:
            if ethChild2.get_ip_protocol_number() == 58:
               destination_MAC_address = []
               source_MAC_address = []
               destination_MAC_address = eth.get_ether_dhost()
               source_MAC_address = eth.get_ether_shost()
               source_MAC_address_final=""
               destination_MAC_address_final = ""
               x = 0

               for x in range(6):
                temp_decimal = source_MAC_address[x]
                temp_hex = hex(temp_decimal)
                source_MAC_address_final = source_MAC_address_final + temp_hex[2:]+":"
                temp_decimal = destination_MAC_address[x]
                temp_hex = hex(temp_decimal)
                destination_MAC_address_final = destination_MAC_address_final + temp_hex[2:]+":"

               source_MAC_address_final = source_MAC_address_final[:-1]
               destination_MAC_address_final = destination_MAC_address_final[:-1]

               packetData = (ethChild2.get_originating_packet_data())
               packetHex = []
               for data in packetData:
                packetHex.append(hex(data))

               source_link_layer_address = ""
               ip_source_address = ethChild.get_source_address()
               ip_destination_address = ethChild.get_destination_address()
               ndp_message_number = ethChild2.get_type()

               source_link_layer_address = source_link_layer_address[:-1]
                   #print source_link_layer_address

               message_details =  SLAAC_Message.SLAAC_Message(ndp_message_number,source_link_layer_address, ip_source_address, ip_destination_address, source_MAC_address_final, destination_MAC_address_final)
               #detection_module = Detection.Detection()
               #detection_module.detect_neighbor_spoofing(message_details)

               print "-----------Packet Details----------"
               print "NDP Message Type %s" %message_details.get_ndp_message_number()
               print "Source Link Layer Address: %s" %message_details.get_source_link_layer_address()
               print "Source IPv6 Address %s " %message_details.get_ip_source_address()
               print "Destination IPv6 Address %s" %message_details.get_ip_destination_address()
               print "Source MAC Address %s" %message_details.get_source_MAC_address()
               print "Destination MAC Address %s" %message_details.get_destination_MAC_address()
               print "----------------END----------------"
    except:
            print "Packet Discarded"




time.sleep(1)

