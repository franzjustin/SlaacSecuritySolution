# Creates a class called SLAAC_Message
from collections import deque
from impacket import ICMP6
from impacket.ImpactDecoder import EthDecoder, ICMP6Decoder
from TestFiles import SLAAC_Message
from TestFiles.Detection import Detection
import dpkt


class DataRead:
    # Initialize when created. Self tells its from this class and the others are your created attributes
    def __init__(self, location):
        # Self is the new object
        self.location = location

    def check_ipv6_options(self,packetHex):

        check_one = "false"
        found = "false"
        x=0
        y=0
        for entry in packetHex:
            #print entry[2:].zfill(2)
            if str(entry[2:].zfill(2)) == "02":
                #print "02 detected"
                check_one = "true"
            if str(check_one)=="true":
                found = "true"
                check_one="false"
                y = x
            x += 1
        checkflag = found
        return checkflag,y +1
    def getSlaac(self):
        f = open(self.location)
        pcap = dpkt.pcap.Reader(f)
        checker = ICMP6.ICMP6.protocol
        listOfMessages = []
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
                       print "****  **********start of packet***************"
                       #print ethChild2.child()

                       for x in range(6):
                        temp_decimal = source_MAC_address[x]
                        temp_hex = hex(temp_decimal)
                        source_MAC_address_final = source_MAC_address_final + temp_hex[2:]+":"
                        temp_decimal = destination_MAC_address[x]
                        temp_hex = hex(temp_decimal)
                        destination_MAC_address_final = destination_MAC_address_final + temp_hex[2:]+":"

                       source_MAC_address_final = source_MAC_address_final[:-1]
                       destination_MAC_address_final = destination_MAC_address_final[:-1]
                       target_link_layer_address=""

                       packetData = (ethChild2.get_originating_packet_data())
                       packetHex = []
                       for data in packetData:
                        packetHex.append(hex(data))
                       #print packetHex
                       source_link_layer_address = ""
                       target_address=""
                       ip_source_address = ethChild.get_source_address()
                       ip_destination_address = ethChild.get_destination_address()
                       ndp_message_number = ethChild2.get_type()
                       x=0
                       #print packetHex
                       contains_source,offset  = self.check_ipv6_options(packetHex)

                       if str(ndp_message_number) == "134": #Router Advertisement
                           for x in range(6):
                                source_link_layer_address = source_link_layer_address + packetHex[50 + x][2:]+":"
                           target_address ="n/a"
                           source_link_layer_address = source_link_layer_address[:-1]
                           target_link_layer_address="n/a"

                       elif str(ndp_message_number) == "135": #Neighbor Solicitation
                           for x in range(16):
                                target_address = target_address + packetHex[x][2:].zfill(2)

                                if (x > 0):
                                    if x% 2 != 0:
                                        target_address = target_address +":"

                           target_address = target_address[:-1]
                           target_link_layer_address="n/a"
                           source_link_layer_address="n/a"
                       elif str(ndp_message_number)== "136":
                           if str(contains_source)=="true":
                                for x in range(6):
                                    target_link_layer_address = target_link_layer_address + packetHex[1+offset+x][2:].zfill(2) + ":"
                           target_link_layer_address=target_link_layer_address[:-1]
                           source_link_layer_address="n/a"
                           target_address="n/a"
                           print target_link_layer_address




                       message_details =  SLAAC_Message.SLAAC_Message(ndp_message_number,source_link_layer_address, ip_source_address, ip_destination_address, source_MAC_address_final, destination_MAC_address_final,target_address,target_link_layer_address)

                       #detection_module.detect_rogue_advertisement(message_details)
                       print "-----------Packet Details----------"
                       print "NDP Message Type %s" %message_details.get_ndp_message_number()
                       print "Source Link Layer Address: %s" %message_details.get_source_link_layer_address()
                       print "Source IPv6 Address %s " %message_details.get_ip_source_address()
                       print "Destination IPv6 Address %s" %message_details.get_ip_destination_address()
                       print "Source MAC Address %s" %message_details.get_source_MAC_address()
                       print "Destination MAC Address %s" %message_details.get_destination_MAC_address()
                       print "Target Address %s" %message_details.get_target_address()
                       print "Target Link Layer Address %s" %message_details.get_target_link_layer_address()
                       print "----------------END----------------"
            except:
                    print "Packet Discarded"
            listOfMessages.append(message_details)

        return listOfMessages


