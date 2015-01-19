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
    def send_na_packet(self, message_type):
        ip = IP6.IP6()
        ip.set_source_address(src)
        ip.set_destination_address(dst)
        ip.set_traffic_class(0)
        ip.set_flow_label(0)
        ip.set_hop_limit(64)
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        rawHex = u"ff080800000000000000040005010000000005dc030440c0111111110404040400000000fe8000000000000000000000000000000101000c2911b7241803000800001111000000000000000000000000000000001803030800001111200000000000000000000000000000001803070800001111fc0000000000000000000000000000001903000001010101ff0200000000000000000000000000fb"
        payload = rawHex.replace(' ','').decode('hex')
        print payload
        #payload = ""
        print "PING %s %d data bytes" % (dst, len(rawHex))

    def create_ra_message(self,source_link_layer):
        FirstPart = u"ff08070800000000000000000101"
        LastPart = u"05010000000005dc"
        RAmessage = FirstPart + source_link_layer + LastPart
        return RAmessage.replace(' ','').decode('hex')

