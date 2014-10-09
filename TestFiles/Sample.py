import pcapy
import __builtin__
from pcapy import findalldevs
import impacket
from impacket.ImpactDecoder import *
import os.path
import dpkt
import SLAAC_Message
import Detection

def getInterface():
    # Grab a list of interfaces that pcap is able to listen on.
    # The current user will be able to listen from all returned interfaces,
    # using open_live to open them.
    
    
    #f = open('MyNigga.s0i0.pcap')
    f = open('MyNigga.s0i0.pcap')
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
                   #print packetHex

                   source_link_layer_address = ""
                   ip_source_address = ethChild.get_source_address()
                   ip_destination_address = ethChild.get_destination_address()
                   ndp_message_number = ethChild2.get_type()
                   x=0
                   if str(ndp_message_number) == "134": #Router Advertisement
                    for x in range(6):
                            source_link_layer_address = source_link_layer_address + packetHex[10 + x][2:]+":"
                          
                    source_link_layer_address = source_link_layer_address[:-1]
                   elif str(ndp_message_number) == "135": #Neighbor Solicitation
                       for x in range(24):
                            source_link_layer_address = source_link_layer_address + packetHex[x][2:].zfill(2)

                           

                       source_link_layer_address = source_link_layer_address[:-1]
                       #print source_link_layer_address
                   if str(message_details.get_ip_source_address()) == "::":
                      print "DAD attempt detected"
                      #detection_module.update_attempt_database(message_details)
                      #detection_module.check_old_attempt(1,"::")
                   else :
                      print " "
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
     
        ifs = findalldevs()
         
        #print detection_module.check_for_database()
        #print detection_module.get_router_database()
        #print message_details.get_ndp_message_number()
        #if (message_details.get_ndp_message_number() == 134  ):
         # rogue_router_advertisement = detection_module.detect_rogue_advertisement("1",message_details.get_source_link_layer_address())

        #rogue_neighbor_advertisement = detection_module.detect_neighbor_spoofing()
        #print os.path.isfile("Router_Database")
        #f = open('workfile', 'w')
        #f.write('This is a test\n')        attack_detect
        #detection_module.get_dad_attempt()
        #detection_module.detect_dos_dad()
        # No interfaces available, abort.
    if 0 == len(ifs):
        print "You don't have enough permissions to open any interface on this system."
        sys.exit(1)
     
    # Only one interface available, use it.
    elif 1 == len(ifs):
        print 'Only one interface present, defaulting to it.'
        return ifs[0]
 
    # Ask the user to choose an interface from the list.
    count = 0
    for iface in ifs:
        print '%i - %s' % (count, iface)
        count += 1
    idx = int(raw_input('Please select an interface: '))
 
    return ifs[idx]
     
     
     
     
    #list all the network devices
    
pcapy.findalldevs()
max_bytes = 1024
promiscuous = False
read_timeout = 100 # in milliseconds
pc = pcapy.open_live(getInterface(), max_bytes, promiscuous, read_timeout)
pc.setfilter('')
     
    # callback for received packets
     
def recv_pkts(hdr, data):
    print os.path.abspath(impacket.__file__)
    packet = EthDecoder().decode(data)
    print packet
    #print packet.get_ether_type()
    #print packet.get_header_size()
    #print packet.get_ether_dhost()
    #print packet.get_ether_dhost()
    #print packet.get_size()  
    #print packet.get_data_as_string()  
    #print packet.get_buffer_as_string()  
    #print packet.get_bytes()
    #print packet.child()
    #packetChild = packet.child().child().child()
    #packet21 = ICMP6Decoder().decode(packetChild)
    #filename = "lol"
    #dumper = pc.dump_open(filename)
    #dumper.dump(hdr, data)
    #print dumper
      
packet_limit = -1 # infinite
pc.loop(packet_limit, recv_pkts) # capture packets

