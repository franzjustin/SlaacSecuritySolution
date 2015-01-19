import pcapy
from impacket.ImpactDecoder import *
from ClassS3 import DataRead, Detection, SLAAC_Message, LearningMode

class Dataparse:

    def __init__(self, learn_mode):
        self.learn_mode = learn_mode

    def sniffSlaac(self, buf):

            #print "NAKAPASOK NA "
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
                        override_flag= False
                        router_flag = False

                        x = 0

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

                            #print ethChild2.get_router_flag() #sample code to get router flag of NA
                            #print ethChild2.get_override_flag()
                            #router_flag = ethChild2.get_router_flag()
                            #if router_flag == False:
                            #   print "if else of flag worked"
                            if str(contains_source) == "true-target" and hex(ethChild2.child().get_bytes()[0:1][0]) == "0xa0":
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
                            override_flag = ethChild2.get_override_flag()
                            router_flag = ethChild2.get_router_flag()

                        message_details = SLAAC_Message.SLAAC_Message(ndp_message_number, source_link_layer_address,
                                                                      ip_source_address, ip_destination_address,
                                                                      source_MAC_address_final,
                                                                      destination_MAC_address_final, target_address,
                                                                      target_link_layer_address,override_flag,router_flag)

                        #detection_module.detect_rogue_advertisement(message_details)
                        print "-----------Packet Details----------"
                        print "NDP Message Type %s" % message_details.get_ndp_message_number()
                        print "Source Link Layer Address: %s" % message_details.get_source_link_layer_address()
                        print "Source IPv6 Address %s " % message_details.get_ip_source_address()
                        print "Destination IPv6 Address %s" % message_details.get_ip_destination_address()
                        print "Source MAC Address %s" % message_details.get_source_MAC_address()
                        print "Destination MAC Address %s" % message_details.get_destination_MAC_address()
                        print "Target Address %s" % message_details.get_target_address()
                        print "Target Link Layer Address %s" % message_details.get_target_link_layer_address()
                        print "Override Flag %s" %message_details.get_override_flag()
                        print "Router Flag %s" %message_details.get_router_flag()
                        print "----------------END----------------"

                        if self.learn_mode == False:
                            detect_module = Detection()
                            if message_details.get_ndp_message_number()=="134": #Last Hop Router Attack
                                detect_module.detect_rogue_advertisement(message_details)
                            elif message_details.get_ndp_message_number()=="135":#Dos in DAD
                                detect_module.detect_dos_dad(message_details)
                            elif message_details.get_ndp_message_number()=="136": #Neigbor Spoofing
                                if ethChild2.get_router_flag()=="false":
                                    detect_module.detect_neighbor_spoofing((message_details))
                        else:
                            learningmode = LearningMode.LearningMode()
                            learningmode.learn(message_details)





            except:
               # x = 1
                 print "Packet Discarded"
                #print "fail"


    def activateLearningMode(self,  buf):
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
                        override_flag = False
                        router_flag = False
                        x = 0

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



                        message_details = SLAAC_Message.SLAAC_Message(ndp_message_number, source_link_layer_address,
                                                                      ip_source_address, ip_destination_address,
                                                                      source_MAC_address_final,
                                                                      destination_MAC_address_final, target_address,
                                                                      target_link_layer_address,override_flag,router_flag)


                        print "-----------Packet Details----------"
                        print "NDP Message Type %s" % message_details.get_ndp_message_number()
                        print "Source Link Layer Address: %s" % message_details.get_source_link_layer_address()
                        print "Source IPv6 Address %s " % message_details.get_ip_source_address()
                        print "Destination IPv6 Address %s" % message_details.get_ip_destination_address()
                        print "Source MAC Address %s" % message_details.get_source_MAC_address()
                        print "Destination MAC Address %s" % message_details.get_destination_MAC_address()
                        print "Target Address %s" % message_details.get_target_address()
                        print "Target Link Layer Address %s" % message_details.get_target_link_layer_address()
                        print "Override Flag %s" %message_details.get_override_flag()
                        print "Router Flag %s" %message_details.get_router_flag()
                        print "----------------END----------------"




                except:
                    x = 1


