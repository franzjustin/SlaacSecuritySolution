from impacket import version
from ClassS3 import DataRead
from TestFiles.Detection import Detection
from datetime import datetime
from decimal import *

print version.BANNER

dataRead = DataRead.DataRead('../Packets/NeighborSpoofing-Test1.s0i0.pcap').getSlaac
detectRA = Detection()
for message_details in dataRead:
    if message_details.get_ndp_message_number() == 136:
        test_open = open("../TestFiles/test2",'a')
        test_start = datetime.now()
        sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f")))/1000000
        test_open.write(str(sum))
        test_open.write('\n')
        test_open.close()
        detectRA.detect_neighbor_spoofing(message_details)
