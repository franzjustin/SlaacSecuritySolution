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

	def set_target_address(self,address):
		 self.target_address = address

	def getLegitRouter(self, vlanId):
		f = open('../Database/Router_Database', 'r')
		RouterTemp = f.read()
		f.close()
		RouterRawAddress = RouterTemp.split('\n')
		#print RouterRawAddress
		RouterIPs = []
		for x in RouterRawAddress:
			RouterIPs.append( x.split(' '))
		for x in range(len(RouterIPs)):
			if  RouterIPs[x][0] == str(vlanId):
				return RouterIPs[x]


	def mitigate_last_hop_router(self,IpSourceAdd,source_link, vlanId):
		vlanId = int(vlanId)
		self.send_ra_packet(source_link,1,vlanId)
		routerIp = self.getLegitRouter(vlanId)
		self.send_na_packet(source_link,1,str(IpSourceAdd),vlanId)
		self.source_address = routerIp[2][:-1].lower()
		self.send_ra_packet(routerIp[1].replace(':',''),1,vlanId, "Add")

	def mitigate_neighbor_advertisement_spoofing(self,IpSourceAdd,TargetLinkLayer,vlanId):
		vlanId = int(vlanId)
		self.send_na_packet(IpSourceAdd,1,str(TargetLinkLayer),vlanId)
		routerIp = self.getLegitRouter(vlanId)
		self.source_address = routerIp[2][:-1].lower()
		self.send_ra_packet(routerIp[1].replace(':',''),1,vlanId, "Add")
	def send_ra_packet(self,source_link_layer, send_frequency,vlan_id = 0, Type="Erase"):
		ip = IP6.IP6()
		ip.set_source_address(self.get_source_address())
		ip.set_destination_address(self.get_target_address())
		ip.set_traffic_class(224)
		ip.set_flow_label(0)
		ip.set_hop_limit(255)
		s = socket(AF_PACKET, SOCK_RAW, IPPROTO_ICMPV6)
		s.bind((self.network_card, N))
		payload = self.create_ra_message(source_link_layer, Type)
		for i in range(0, send_frequency):
			icmp = ICMP6.ICMP6()
			icmp.set_byte(0, 134) # Put Type?
			icmp.set_byte(1, 00)  # Put Code?
			payloadObject = ImpactPacket.Data()
			payloadObject.set_data(payload)
			icmp.contains(payloadObject)
			ip.contains(icmp)
			ip.set_next_header(ip.child().get_ip_protocol_number())
			ip.set_payload_length(ip.child().get_size())
			eth = ImpactPacket.Ethernet('\x33\x33\x00\x00\x00\x01\x00\x0c\x29\x23\x84\x51\x81\x00')
			eth.pop_tag()
			if vlan_id != 0:
				vlan = ImpactPacket.EthernetTag()
				vlan.set_vid(vlan_id)
				eth.push_tag(vlan)
			icmp.calculate_checksum()
			eth.contains(ip)
			s.send(eth.get_packet())



	def send_ns_packet(self,source_link, send_frequency,target_address,vlan_id = 0):
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
			eth = ImpactPacket.Ethernet('\x33\x33\x00\x00\x00\x01\xff\xff\xff\xff\xff\xff\x81\x00')
			eth.pop_tag()
			if vlan_id != 0:
				vlan = ImpactPacket.EthernetTag()
				vlan.set_vid(vlan_id)
				eth.push_tag(vlan)
			icmp.calculate_checksum()
			eth.contains(ip)
			s.send(eth.get_packet())


	def send_na_packet(self,source_link, send_frequency,target_address,vlan_id = 0):
		ip = IP6.IP6()
		ip.set_source_address(self.get_source_address())
		ip.set_destination_address(self.get_target_address())
		ip.set_traffic_class(0)
		ip.set_flow_label(0)
		ip.set_hop_limit(255)
		s = socket(AF_PACKET, SOCK_RAW, IPPROTO_ICMPV6)
		s.bind((self.network_card, N))
		payload = self.create_na_message(source_link,target_address)
		print send_frequency
		for i in range(0, send_frequency):
			icmp = ICMP6.ICMP6()
			icmp.set_byte(0, 136) # Put Type?
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


	def create_ns_message(self,source_link,target_address):
		firstPart = "00000000"
		ip = IPAddress(target_address)
		target_address = str(hex(ip))[2:]
		target_link_layer = u"0101"+ source_link
		ns_message = firstPart + target_address + target_link_layer
		return ns_message.decode('hex')

	def create_na_message(self,source_link,target_address):
		flag = u"20000000"
		ip = IPAddress(target_address)
		target_address = str(hex(ip))[2:]
		target_link_layer = u"0101"+ source_link #10bf4896a190
		na_message = flag.replace(' ','') + target_address + target_link_layer
		return na_message.decode('hex')


	def create_ra_message(self,source_link_layer, Type):
		FirstPart = u"ff08"
		routerLifeTime =u""
		if Type == "Erase":
			routerLifeTime = u"0000"
		else:
			routerLifeTime = u"ffff"
		SecondPart = u"000000000000000005010000000005dc0101"
		RAmessage = FirstPart + routerLifeTime + SecondPart + source_link_layer
		return RAmessage.decode('hex')

