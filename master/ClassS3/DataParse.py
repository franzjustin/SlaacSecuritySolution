from impacket.ImpactDecoder import *
import Detection
import SLAAC_Message
import LearningMode


class Dataparse:

    def __init__(self, learn_mode):
        self.learn_mode = learn_mode

    def check_vlanId(self,buf):
        ether = ImpactPacket.Ethernet(buf)
        vlanId = 0
        try:
            vlanId = ether.get_tag(-1).get_vid()
        except:
            pass
        return vlanId

    def check_ipv6_options(self, packetHex):
        found = "false"
        x = 0
        y = 0
        for entry in packetHex:
            if str(entry[2:].zfill(2)) == "02":
                if str(packetHex[x + 1][2:].zfill(2)) == "01":
                    found = "true-target"
                    return found, y + 1
            if str(entry[2:].zfill(2)) == "01":
                if str(packetHex[x + 1][2:].zfill(2)) == "01":
                    y = x
                    found = "true-source"
                    return found, y + 1
            x += 1
        checkflag = found
        return checkflag, y + 1

    def sniffSlaac(self, buf,getInterface):
            eth = EthDecoder().decode(buf)
            ethChild = eth.child()
            ethChild2 = ethChild.child()
            try:
                    if ethChild2.get_ip_protocol_number() == 58:
                        destination_MAC_address = eth.get_ether_dhost()
                        source_MAC_address = eth.get_ether_shost()
                        source_MAC_address_final = ""
                        destination_MAC_address_final = ""
                        override_flag= False
                        router_flag = False
                        router_lifetime = "False"
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
                        payloadHex = []
                        for data in packetData:
                            packetHex.append(hex(data))
                        source_link_layer_address = ""
                        target_address = ""
                        ip_source_address = ethChild.get_source_address()
                        ip_destination_address = ethChild.get_destination_address()
                        ndp_message_number = ethChild2.get_type()
                        contains_source, offset = self.check_ipv6_options(packetHex)

                        if str(ndp_message_number) == "134":  #Router Advertisement
                            if str(contains_source) == "true-source":
                                for x in range(6):
                                    source_link_layer_address = source_link_layer_address + packetHex[x + offset + 1][
                                                                                            2:].zfill(2) + ":"
                                target_address = "n/a"
                                source_link_layer_address = source_link_layer_address[:-1]
                                target_link_layer_address = "n/a"
                            else:
                                source_link_layer_address = "n/a"

                            payload_byte = ethChild2.child().get_bytes()
                            for payload_data in payload_byte:
                                payloadHex.append(hex(payload_data))
                            router_lifetime = payloadHex[2][2:] + payloadHex[3][2:]

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
                            else:
                                source_link_layer_address = "n/a"

                        elif str(ndp_message_number) == "136":  #Neighbor Advertisement
                            flags = hex(ethChild2.child().get_bytes()[0:1][0])
                            if flags == "0xa0":
                                override_flag = True
                                router_flag = True

                            if str(contains_source) == "true-source" and flags == "0xa0":
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
                        vlanId = self.check_vlanId(buf)

                        message_details = SLAAC_Message.SLAAC_Message(vlanId,ndp_message_number, source_link_layer_address,
                                                                      ip_source_address, ip_destination_address,
                                                                      source_MAC_address_final,
                                                                      destination_MAC_address_final, target_address,
                                                                      target_link_layer_address,override_flag,router_flag,router_lifetime,getInterface)

                        detect_module = Detection.Detection()
                        if str(message_details.get_ndp_message_number())=="134": #Last Hop Router Attack
                            detect_module.detect_rogue_advertisement(message_details)

                        elif str(message_details.get_ndp_message_number())=="135" :#Dos in DAD
                            if str(message_details.get_ip_source_address()) == "::":
                                detect_module.detect_dos_dad(message_details)

                        elif str(message_details.get_ndp_message_number())=="136": #Neigbor Spoofing
                            detect_module.detect_neighbor_spoofing((message_details))

            except Exception,e: pass
            return message_details


    def activateLearningMode(self,  buf):
            eth = EthDecoder().decode(buf)
            ethChild = eth.child()
            ethChild2 = ethChild.child()
            try:
                    if ethChild2.get_ip_protocol_number() == 58:
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
                        payloadHex = []
                        for data in packetData:
                            packetHex.append(hex(data))
                        source_link_layer_address = ""
                        target_address = ""
                        ip_source_address = ethChild.get_source_address()
                        ip_destination_address = ethChild.get_destination_address()
                        ndp_message_number = ethChild2.get_type()
                        x = 0
                        contains_source, offset = self.check_ipv6_options(packetHex)

                        if str(ndp_message_number) == "134":  #Router Advertisement
                            if str(contains_source) == "true-source":
                                for x in range(6):
                                    source_link_layer_address = source_link_layer_address + packetHex[x + offset + 1][
                                                                                            2:].zfill(2) + ":"
                                target_address = "n/a"
                                source_link_layer_address = source_link_layer_address[:-1]
                                target_link_layer_address = "n/a"
                            else:
                                source_link_layer_address = "n/a"

                            payload_byte = ethChild2.child().get_bytes()
                            for payload_data in payload_byte:
                                payloadHex.append(hex(payload_data))
                            router_lifetime = payloadHex[2][2:] + payloadHex[3][2:]
                            vlanId = self.check_vlanId(buf)
                            message_details = SLAAC_Message.SLAAC_Message(vlanId,ndp_message_number, source_link_layer_address,
                                                                      ip_source_address, ip_destination_address,
                                                                      source_MAC_address_final,
                                                                      destination_MAC_address_final, target_address,
                                                                      target_link_layer_address,override_flag,router_flag,router_lifetime)
                            learning_sub_module = LearningMode.LearningMode()
                            learning_sub_module.learn(message_details)
            except:
                pass

