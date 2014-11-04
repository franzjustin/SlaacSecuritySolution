# Creates a class called SLAAC_Message
from collections import deque
from impacket import ICMP6
from impacket.ImpactDecoder import EthDecoder, ICMP6Decoder, LinuxSLLDecoder
from TestFiles import SLAAC_Message
from datetime import datetime
from decimal import *
from TestFiles.Detection import Detection
import dpkt

#  print  LinuxSLLDecoder().decode(buf).child().child().child()
class DataRead:
    # Initialize when created. Self tells its from this class and the others are your created attributes
    def __init__(self, location, datapacket = ''):
        # Self is the new object
        self.location = location
        self.datapacket = datapacket
    def check_ipv6_options(self, packetHex):
        check_one = "false"
        found = "false"
        x = 0
        y = 0
        #print packetHex
        for entry in packetHex:
            # print entry[2:].zfill(2)
            if str(entry[2:].zfill(2)) == "02":
                if str(packetHex[x + 1][2:].zfill(2)) == "01":
                    y = x
                    # print "*****************************************************************************************"
                    # print str(packetHex[x+0][2:].zfill(2)) +str(packetHex[x+1][2:].zfill(2)) +" - "+ str(packetHex[x+2][2:].zfill(2)) + str(packetHex[x+3][2:].zfill(2)) + str(packetHex[x+4][2:].zfill(2)) + str(packetHex[x+5][2:].zfill(2)) + str(packetHex[x+6][2:].zfill(2)) + str(packetHex[x+7][2:].zfill(2))
                    # print "*****************************************************************1************************"
                    found = "true-target"
                    return found, y + 1
            if str(entry[2:].zfill(2)) == "01":
                if str(packetHex[x + 1][2:].zfill(2)) == "01":
                    y = x
                    # print "*****************************************************************************************"
                    # print str(packetHex[x+0][2:].zfill(2)) +str(packetHex[x+1][2:].zfill(2)) +" - "+ str(packetHex[x+2][2:].zfill(2)) + str(packetHex[x+3][2:].zfill(2)) + str(packetHex[x+4][2:].zfill(2)) + str(packetHex[x+5][2:].zfill(2)) + str(packetHex[x+6][2:].zfill(2)) + str(packetHex[x+7][2:].zfill(2))
                    # print "*****************************************************************1************************"
                    found = "true-source"
                    return found, y + 1
            x += 1
        checkflag = found
        return checkflag, y + 1



    @property
    def getSlaac(self):
        f = open(self.location)
        pcap = dpkt.pcap.Reader(f)
        checker = ICMP6.ICMP6.protocol
        listOfMessages = []
        i = 1
        for ts, buf in pcap:
            eth = EthDecoder().decode(buf)
            ethChild = eth.child()
            ethChild2 = ethChild.child()

            try:
                #print ethChild2
                if ethChild2.get_ip_protocol_number() == 58:
                    destination_MAC_address = []
                    source_MAC_address = []
                    destination_MAC_address = eth.get_ether_dhost()
                    source_MAC_address = eth.get_ether_shost()
                    source_MAC_address_final = ""
                    destination_MAC_address_final = ""
                    x = 0
                    #print "****  **********start of packet***************"
                    # print ethChild2.child()

                    for x in range(6):
                        temp_decimal = source_MAC_address[x]
                        temp_hex = hex(temp_decimal)
                        source_MAC_address_final = source_MAC_address_final + temp_hex[2:] + ":"
                        temp_decimal = destination_MAC_address[x]
                        temp_hex = hex(temp_decimal)
                        destination_MAC_address_final = destination_MAC_address_final + temp_hex[2:] + ":"

                    source_MAC_address_final = source_MAC_address_final[:-1].zfill(2)
                    destination_MAC_address_final = destination_MAC_address_final[:-1]
                    target_link_layer_address = ""

                    packetData = (ethChild2.get_originating_packet_data())
                    packetHex = []
                    for data in packetData:
                        packetHex.append(hex(data))
                    # print packetHex
                    source_link_layer_address = ""
                    target_address = ""
                    ip_source_address = ethChild.get_source_address()
                    ip_destination_address = ethChild.get_destination_address()
                    ndp_message_number = ethChild2.get_type()
                    x = 0
                    #print packetHex
                    contains_source, offset = self.check_ipv6_options(packetHex)

                    if str(ndp_message_number) == "134":  #Router Advertisement
                        if str(contains_source) == "true-source":
                            for x in range(6):
                                source_link_layer_address = source_link_layer_address + packetHex[x + offset + 1][
                                                                                        2:].zfill(2) + ":"
                            target_address = "n/a"
                            source_link_layer_address = source_link_layer_address[:-1]
                            target_link_layer_address = "n/a"
                            #print "*****************************************************************************************"
                            #print source_link_layer_address
                            #print "*****************************************************************************************"
                        else:
                            source_link_layer_address = "n/a"

                    elif str(ndp_message_number) == "135":  #Neighbor Solicitation
                        for x in range(16):
                            target_address = target_address + packetHex[x][2:].zfill(2)
                            if (x > 0):
                                if x % 2 != 0:
                                    target_address = target_address + ":"
                        target_address = target_address[:-1]
                        target_link_layer_address = "n/a"
                        if str(contains_source) == "true-source":
                            for x in range(6):
                                source_link_layer_address = source_link_layer_address + packetHex[x + offset + 1][
                                                                                        2:].zfill(2) + ":"
                            source_link_layer_address = source_link_layer_address[:-1]
                            #print "*****************************************************************************************"
                            #print source_link_layer_address
                            #print "*****************************************************************************************"
                        else:
                            source_link_layer_address = "n/a"

                    elif str(ndp_message_number) == "136":  #Neighbor Advertisement
                        if str(contains_source) == "true-target":
                            for x in range(6):
                                target_link_layer_address = target_link_layer_address + packetHex[1 + offset + x][
                                                                                        2:].zfill(2) + ":"
                            target_link_layer_address = target_link_layer_address[:-1]

                        else:
                            target_link_layer_address = "n/a"


                        for x in range(16):
                            target_address = target_address + packetHex[x][2:].zfill(2)
                            if (x > 0):
                                if x % 2 != 0:
                                    target_address = target_address + ":"
                        target_address = target_address[:-1]

                    message_details = SLAAC_Message.SLAAC_Message(ndp_message_number, source_link_layer_address,
                                                                  ip_source_address, ip_destination_address,
                                                                  source_MAC_address_final,
                                                                  destination_MAC_address_final, target_address,
                                                                  target_link_layer_address)

                    #detection_module.detect_rogue_advertisement(message_details)
                    #print "-----------Packet Details----------"
                    #print "NDP Message Type %s" % message_details.get_ndp_message_number()
                    #print "Source Link Layer Address: %s" % message_details.get_source_link_layer_address()
                    #print "Source IPv6 Address %s " % message_details.get_ip_source_address()
                    #print "Destination IPv6 Address %s" % message_details.get_ip_destination_address()
                    #print "Source MAC Address %s" % message_details.get_source_MAC_address()
                    #print "Destination MAC Address %s" % message_details.get_destination_MAC_address()
                    #print "Target Address %s" % message_details.get_target_address()
                    #print "Target Link Layer Address %s" % message_details.get_target_link_layer_address()
                    #print "----------------END----------------"
                    listOfMessages.append(message_details)
                    #print "sucess"
            except:
                x = 1
                 #print "Packet Discarded"
                #print "fail"

        return listOfMessages



    @property
    def getSlaacSinglePacket(self):
        eth = EthDecoder().decode(self.datapacket)
        ethChild = eth.child()
        ethChild2 = ethChild.child()
        try:
            if ethChild2.get_ip_protocol_number() == 58:
                destination_MAC_address = []
                source_MAC_address = []
                destination_MAC_address = eth.get_ether_dhost()
                source_MAC_address = eth.get_ether_shost()
                source_MAC_address_final = ""
                destination_MAC_address_final = ""
                x = 0
                #print "****  **********start of packet***************"
                # print ethChild2.child()

                for x in range(6):
                    temp_decimal = source_MAC_address[x]
                    temp_hex = hex(temp_decimal)
                    source_MAC_address_final = source_MAC_address_final + temp_hex[2:] + ":"
                    temp_decimal = destination_MAC_address[x]
                    temp_hex = hex(temp_decimal)
                    destination_MAC_address_final = destination_MAC_address_final + temp_hex[2:] + ":"

                source_MAC_address_final = source_MAC_address_final[:-1].zfill(2)
                destination_MAC_address_final = destination_MAC_address_final[:-1]
                target_link_layer_address = ""

                packetData = (ethChild2.get_originating_packet_data())
                packetHex = []
                for data in packetData:
                    packetHex.append(hex(data))
                # print packetHex
                source_link_layer_address = ""
                target_address = ""
                ip_source_address = ethChild.get_source_address()
                ip_destination_address = ethChild.get_destination_address()
                ndp_message_number = ethChild2.get_type()
                x = 0
                #print packetHex
                contains_source, offset = self.check_ipv6_options(packetHex)

                if str(ndp_message_number) == "134":  #Router Advertisement
                    if str(contains_source) == "true-source":
                        for x in range(6):
                            source_link_layer_address = source_link_layer_address + packetHex[x + offset + 1][
                                                                                    2:].zfill(2) + ":"
                        target_address = "n/a"
                        source_link_layer_address = source_link_layer_address[:-1]
                        target_link_layer_address = "n/a"
                        #print "*****************************************************************************************"
                        #print source_link_layer_address
                        #print "*****************************************************************************************"
                    else:
                        source_link_layer_address = "n/a"

                elif str(ndp_message_number) == "135":  #Neighbor Solicitation
                    for x in range(16):
                        target_address = target_address + packetHex[x][2:].zfill(2)
                        if (x > 0):
                            if x % 2 != 0:
                                target_address = target_address + ":"
                    target_address = target_address[:-1]
                    target_link_layer_address = "n/a"
                    if str(contains_source) == "true-source":
                        for x in range(6):
                            source_link_layer_address = source_link_layer_address + packetHex[x + offset + 1][
                                                                                    2:].zfill(2) + ":"
                        source_link_layer_address = source_link_layer_address[:-1]
                        #print "*****************************************************************************************"
                        #print source_link_layer_address
                        #print "*****************************************************************************************"
                    else:
                        source_link_layer_address = "n/a"

                elif str(ndp_message_number) == "136":  #Neighbor Advertisement
                    if str(contains_source) == "true-target":
                        for x in range(6):
                            target_link_layer_address = target_link_layer_address + packetHex[1 + offset + x][
                                                                                    2:].zfill(2) + ":"
                        target_link_layer_address = target_link_layer_address[:-1]
                        #print "*****************************************************************************************"
                        #print target_link_layer_address
                        #print "*****************************************************************************************"
                    else:
                        target_link_layer_address = "n/a"


                    for x in range(16):
                        target_address = target_address + packetHex[x][2:].zfill(2)
                        if (x > 0):
                            if x % 2 != 0:
                                target_address = target_address + ":"
                    target_address = target_address[:-1]

                message_details = SLAAC_Message.SLAAC_Message(ndp_message_number, source_link_layer_address,
                                                              ip_source_address, ip_destination_address,
                                                              source_MAC_address_final,
                                                              destination_MAC_address_final, target_address,
                                                              target_link_layer_address)

                #detection_module.detect_rogue_advertisement(message_details)
                #print "-----------Packet Details----------"
                #print "NDP Message Type %s" % message_details.get_ndp_message_number()
                #print "Source Link Layer Address: %s" % message_details.get_source_link_layer_address()
                #print "Source IPv6 Address %s " % message_details.get_ip_source_address()
                #print "Destination IPv6 Address %s" % message_details.get_ip_destination_address()
                #print "Source MAC Address %s" % message_details.get_source_MAC_address()
                #print "Destination MAC Address %s" % message_details.get_destination_MAC_address()
                #print "Target Address %s" % message_details.get_target_address()
                #print "Target Link Layer Address %s" % message_details.get_target_link_layer_address()
                #print "----------------END----------------"
                return message_details
        except:
            x = 1
            #print "Packet Discarded"
