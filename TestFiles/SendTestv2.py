import select
import socket
import time
import sys

from impacket import ImpactDecoder, ImpactPacket, IP6, ICMP6, version

print version.BANNER

if len(sys.argv) < 3:
	print "Use: %s <src ip> <dst ip>" % sys.argv[0]
	sys.exit(1)

src = sys.argv[1]
dst = sys.argv[2]

# Create a new IP packet and set its source and destination addresses.

#todo - How can I send to eth0, it does not see the difference

ip = IP6.IP6()
ip.set_source_address(src)
ip.set_destination_address(dst)
ip.set_traffic_class(0)
ip.set_flow_label(0)
ip.set_hop_limit(64)
    
# Open a raw socket. Special permissions are usually required.
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)

rawHex = u"ff080800000000000000040005010000000005dc030440c0111111110404040400000000fe8000000000000000000000000000000101000c2911b7241803000800001111000000000000000000000000000000001803030800001111200000000000000000000000000000001803070800001111fc0000000000000000000000000000001903000001010101ff0200000000000000000000000000fb"
payload = rawHex.replace(' ','').decode('hex')
print payload
#payload = ""
print "PING %s %d data bytes" % (dst, len(rawHex))
seq_id = 0
while 1:
	# Give the ICMP packet the next ID in the sequence.
	seq_id += 1
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
	s.sendto(icmp.get_packet(), (dst, 0))
	print "Send Sucess"
