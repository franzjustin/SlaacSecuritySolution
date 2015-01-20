import select
import socket
import time
from impacket import ImpactDecoder, ImpactPacket, IP6, ICMP6, version
class SendPacket:
    def __init__(self, source_address, target_address):
        self.source_address = source_address
        self.target_address = target_address

    def get_source_address(self):
        return self.source_address

    def get_target_address(self):
        return self.target_address

    #todo - How can I send to eth0, it does not see the difference

    def send_ra_packet(self,source_link_layer, send_frequency):
        ip = IP6.IP6()
        ip.set_source_address(self.get_source_address())
        ip.set_destination_address(self.get_target_address())
        ip.set_traffic_class(0)
        ip.set_flow_label(0)
        ip.set_hop_limit(64)
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
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
            icmp.calculate_checksum()
            # Send it to the target host.
            s.sendto(icmp.get_packet(), (self.get_target_address(), 0))
            print "Success Sending Packet - %d " % (i)


    def send_na_packet(self,target_link, send_frequency):
        ip = IP6.IP6()
        ip.set_source_address(self.get_source_address())
        ip.set_destination_address(self.get_target_address())
        ip.set_traffic_class(0)
        ip.set_flow_label(0)
        ip.set_hop_limit(64)
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        payload = self.create_na_message(target_link)
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
            icmp.calculate_checksum()
            # Send it to the target host.
            s.sendto(icmp.get_packet(), (self.get_target_address(), 0))
            print "Success Sending Packet - %d " % (i)

    def send_ra_packet(self,source_link_layer, send_frequency):
        ip = IP6.IP6()
        ip.set_source_address(self.get_source_address())
        ip.set_destination_address(self.get_target_address())
        ip.set_traffic_class(0)
        ip.set_flow_label(0)
        ip.set_hop_limit(64)
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
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
            icmp.calculate_checksum()
            # Send it to the target host.
            s.sendto(icmp.get_packet(), (self.get_target_address(), 0))
            print "Success Sending Packet - %d " % (i)
#

    def create_na_message(self,target_link):
        flag = u"0a00000000"
        target_address = self.get_source_address().replace(":", "")#u"fe800000000000008af077fffea1d88c"
        target_link_layer = u"0201"+ target_link
        na_message = flag.replace(' ','').decode('hex') + target_address + target_link_layer
        print na_message
        return na_message


    def create_ra_message(self,source_link_layer):
        FirstPart = u"ff08070800000000000000000101"
        LastPart = u"05010000000005dc"
        RAmessage = FirstPart.replace(' ','').decode('hex') + source_link_layer + LastPart.replace(' ','').decode('hex')
        print RAmessage
        return RAmessage

