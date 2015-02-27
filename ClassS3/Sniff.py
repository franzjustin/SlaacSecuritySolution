import pcapy
from pcapy import findalldevs
from datetime import datetime
from decimal import *
from ClassS3 import *
from impacket.ImpactDecoder import *
from ClassS3 import  DataParse
from ClassS3 import  SendPackets
from ClassS3 import  SLAAC_Message


def getInterface():
    ifs = findalldevs()
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
pc.setfilter('icmp6')
mode = False
parser = DataParse.Dataparse(mode)
    # callback for received packets

def recv_pkts(hdr, data):
    try:
        mode = False
        eth = EthDecoder().decode(data)
        ethChild = eth.child()
        ethChild2 = ethChild.child()
        if  ethChild2.get_type() == 134:
            #------------Time Start------------
            test_open = open("../TestFiles/realtime_test1_sniff",'a')
            test_start = datetime.now()
            sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f")))/1000000
            test_open.write(str(sum))
            test_open.write('\n')
            test_open.close()
            #-----------------------------------
            parseMessage = parser.sniffSlaac(data)
            #------------Time Start------------
            test_open = open("../TestFiles/realtime_test1_detect",'a')
            test_start = datetime.now()
            sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f")))/1000000
            test_open.write(str(sum))
            test_open.write('\n')
            test_open.close()
            #-----------------------------------
            #print "Hello"
            #print parseMessage.get_ip_source_address()

        elif  ethChild2.get_type() == 1353:
            #------------Time Start------------
            test_open = open("../TestFiles/realtime_test1_sniff",'a')
            test_start = datetime.now()
            sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f")))/1000000
            test_open.write(str(sum))
            test_open.write('\n')
            test_open.close()
            #-----------------------------------
            parser.sniffSlaac(data)
            #------------Time Start------------
            test_open = open("../TestFiles/realtime_test1_detect",'a')
            test_start = datetime.now()
            sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f")))/1000000
            test_open.write(str(sum))
            test_open.write('\n')
            test_open.close()
            #-----------------------------------
            #print "Hello"
        elif  ethChild2.get_type() == 1336:
            #------------Time Start------------
            test_open = open("../TestFiles/realtime_test1_sniff",'a')
            test_start = datetime.now()
            sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f")))/1000000
            test_open.write(str(sum))
            test_open.write('\n')
            test_open.close()
            #----------0-------------------------
            parseMessage = parser.sniffSlaac(data)
            #------------Time Start------------
            test_open = open("../TestFiles/realtime_test1_detect",'a')
            test_start = datetime.now()
            sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f")))/1000000
            test_open.write(str(sum))
            test_open.write('\n')
            test_open.close()
            #-----------------------------------
            #print "Hello"

            parseTargetLinkLayer = parseMessage.get_target_link_layer_address().replace(':','')
            parseIpSourceAdd =  str(parseMessage.get_ip_source_address()).lower()

            mitigateMessage = SendPackets.SendPacket(parseIpSourceAdd,"ff02::1", "eth0")
            mitigateMessage.mitigate_neighbor_advertisement_spoofing(parseIpSourceAdd,parseTargetLinkLayer,parseMessage.get_vlan_id())

    except:
        x = 1
        print "error"
packet_limit = -1 # infinite
pc.loop(packet_limit, recv_pkts) # capture packets
