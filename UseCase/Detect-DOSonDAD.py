from datetime import datetime
from decimal import Decimal

from impacket import version

from ClassS3 import DataRead, Detection


print version.BANNER
#DosOnDATA-Test01.s0i0.pcap
dataRead = DataRead.DataRead('../Packets/DosOnDad-Test2v2.s0i0.pcap').getSlaac
detectRA = Detection()
for message_details in dataRead:
   # print "Entry Time of Packet: "+str(datetime.now())
    if message_details.get_ndp_message_number() == 135:
        test_open = open("../TestFiles/BeforeDetectionLastHop",'a')
        test_start = datetime.now()
        sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f")))/1000000
        test_open.write(str(sum))
        test_open.write('\n')
        test_open.close()
    detectRA.detect_dos_dad(message_details)
   # print "End"
    #print str(item.get_source_link_layer_address()) +"  "+ str(item.get_ndp_message_number())
