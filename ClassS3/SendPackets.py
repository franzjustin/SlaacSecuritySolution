import select
from socket import *
import time
from impacket import ImpactDecoder, ImpactPacket, IP6, ICMP6, version
from impacket import ImpactPacket
from netaddr import *

class SendPacket:
    def __init__(self, source_address, target_address,network_card):
        self.source_address = source_address
        self.target_address = target_address
        self.network_card = network_card
    def get_source_address(self):
        return self.source_address

    def get_target_address(self):
        return self.target_address

    def send_ra_packet(self,source_link_layer, send_frequency,vlan_id = 0):
        ip = IP6.IP6()
        ip.set_source_address(self.get_source_address())
        ip.set_destination_address(self.get_target_address())
        ip.set_traffic_class(224)
        ip.set_flow_label(0)
        ip.set_hop_limit(255)
        #s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        s = socket(AF_PACKET, SOCK_RAW, IPPROTO_ICMPV6)
        s.bind((self.network_card, N))
        #s.sendto(ethh.get_packet(), (self.get_target_address(), 0))
        payload = self.create_ra_message(source_link_layer)
        print send_frequency
        for i in range(0, send_frequency):
            icmp = ICMP6.ICMP6()
            icmp.set_byte(0, 134) # Put Type?
            icmp.set_byte(1, 00)  # Put Code?
            payloadObject = ImpactPacket.Data()
            payloadObject.set_data(payload)
            icmp.contains(payloadObject)
            # Have the IP packet contain the ICMP packet (along with its payload).
            ip.contains(icmp)
            ip.set_next_header(ip.child().get_ip_protocol_number())
            ip.set_payload_length(ip.child().get_size())
            #Destination - 54:ab:a3:b9:38:3d
            #Source - e2:ed:8d:c7:a8:5e
            #00:0c:29:23:84:50
            #33:33:00:00:00:01
            eth = ImpactPacket.Ethernet('\x33\x33\x00\x00\x00\x01\x00\x0c\x29\x23\x84\x50\x81\x00')
            print eth
            eth.pop_tag()
            if vlan_id != 0:
                vlan = ImpactPacket.EthernetTag()
                vlan.set_vid(vlan_id)
                eth.push_tag(vlan)
            icmp.calculate_checksum()
            eth.contains(ip)
            s.send(eth.get_packet())

            # Send it to the target host.
            #s.sendto(ethh.get_packet(), (self.get_target_address(), 0))
            print "Success Sending Packet - %d " % (i)


    def send_ns_packet(self,source_link, send_frequency,target_address,vlan_id):
        ip = IP6.IP6()
        ip.set_source_address(self.get_source_address())
        ip.set_destination_address(self.get_target_address())
        ip.set_traffic_class(0)
        ip.set_flow_label(0)
        ip.set_hop_limit(255)
        s = socket(AF_PACKET, SOCK_RAW, IPPROTO_ICMPV6)
        s.bind((self.network_card, N))
        payload = self.create_ns_message(source_link,target_address)
        print send_frequency
        for i in range(0, send_frequency):
            icmp = ICMP6.ICMP6()
            icmp.set_byte(0, 135) # Put Type?
            icmp.set_byte(1, 00)  # Put Code?
            payloadObject = ImpactPacket.Data()
            payloadObject.set_data(payload)
            icmp.contains(payloadObject)
            ip.contains(icmp)
            ip.set_next_header(ip.child().get_ip_protocol_number())
            ip.set_payload_length(ip.child().get_size())
            eth = ImpactPacket.Ethernet('\x33\x33\x00\x00\x00\x01\x00\x0c\x29\x23\x84\x50\x81\x00')
            eth.pop_tag()
            if vlan_id != 0:
                vlan = ImpactPacket.EthernetTag()
                vlan.set_vid(vlan_id)
                eth.push_tag(vlan)
            icmp.calculate_checksum()
            eth.contains(ip)
            s.send(eth.get_packet())


    def send_na_packet(self,source_link, send_frequency,target_address,vlan_id):
        ip = IP6.IP6()
        ip.set_source_address(self.get_source_address())
        ip.set_destination_address(self.get_target_address())
        ip.set_traffic_class(0)
        ip.set_flow_label(0)
        ip.set_hop_limit(255)
        #s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        #Socket sending a raw packet
        s = socket(AF_PACKET, SOCK_RAW, IPPROTO_ICMPV6)
        s.bind((self.network_card, N))
        #s.sendto(ethh.get_packet(), (self.get_target_address(), 0))
        payload = self.create_na_message(source_link,target_address)
        print send_frequency
        for i in range(0, send_frequency):
            icmp = ICMP6.ICMP6()
            icmp.set_byte(0, 136) # Put Type?
            icmp.set_byte(1, 00)  # Put Code?
            payloadObject = ImpactPacket.Data()
            payloadObject.set_data(payload)
            icmp.contains(payloadObject)
            # Have the IP packet contain the ICMP packet (along with its payload).
            ip.contains(icmp)
            ip.set_next_header(ip.child().get_ip_protocol_number())
            ip.set_payload_length(ip.child().get_size())
            #Destination - 54:ab:a3:b9:38:3d
            #Source - e2:ed:8d:c7:a8:5e
            #00:0c:29:23:84:50
            #33:33:00:00:00:01
            eth = ImpactPacket.Ethernet('\x33\x33\x00\x00\x00\x01\x00\x0c\x29\x23\x84\x50\x81\x00')
            #eth = ImpactPacket.Ethernet('\x02\x0c\x29\xff\xfe\x23\x02\x0c\x29\xff\xfe\x23\x81\x00')
            eth.pop_tag()
            if vlan_id != 0:
                vlan = ImpactPacket.EthernetTag()
                vlan.set_vid(vlan_id)
                eth.push_tag(vlan)
            icmp.calculate_checksum()
            eth.contains(ip)
            s.send(eth.get_packet())


    def create_ns_message(self,source_link,target_address):
        #fe80000000000000019dd1689d3606dd0101000c29238450\
        firstPart = "00000000"
        ip = IPAddress(target_address)
        target_address = str(hex(ip))[2:]
        target_link_layer = u"0101"+ source_link
        ns_message = firstPart + target_address + target_link_layer
        #na_test = "00000000fe800000000000005d7f5d51cff942800101000c11111111" Windows
        #na_test = "00000000fe80000000000000019dd1689d3606dd0101000000000000" Windows 2
        print target_address
        return ns_message.decode('hex')

    def create_na_message(self,source_link,target_address):
        flag = u"a0000000"                                           #fe80            20c29fffe043796
        ip = IPAddress(target_address)
        target_address = str(hex(ip))[2:]
        target_link_layer = u"0101"+ source_link #10bf4896a190
        na_message = flag.replace(' ','') + target_address + target_link_layer
        print u""+str(na_message)
        #na_test = "00000000fe800000000000005d7f5d51cff942800101000c11111111" Windows
        #na_test = "00000000fe80000000000000019dd1689d3606dd0101000000000000" Windows 2
        na_test = "a0000000fe80000000000000020c29fffe2331230101000c291f53db" #"a0000000fe80000000000000019dd1689d3606dd0201000c29238450"
        print na_test
        return na_message.decode('hex')


    def create_ra_message(self,source_link_layer):
        FirstPart = u"ff08"
        routerLifeTime = u"0001"
        SecondPart = u"000000000000000005010000000005dc0101"
        RAmessage = FirstPart + routerLifeTime + SecondPart + source_link_layer
        #RAmessage = "ff080800000000000000000005010000000005dc0101000c29238450"
        return RAmessage.decode('hex')

