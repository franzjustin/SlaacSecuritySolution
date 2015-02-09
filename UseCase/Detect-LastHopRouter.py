from datetime import datetime
from decimal import Decimal

from impacket import version

from ClassS3 import DataRead, Detection


print version.BANNER

dataRead = DataRead.DataRead('../Packets/RouterAdvertismentAttack-Test2.s0i1.pcap').getSlaac
detectRA = Detection.Detection()
for message_details in dataRead:
    if message_details.get_ndp_message_number() == 134:
        test_open = open("../TestFiles/BeforeDetectionLastHop",'a')
        test_start = datetime.now()
        sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f")))/1000000
        test_open.write(str(sum))
        test_open.write('\n')
        test_open.close()
    detectRA.detect_rogue_advertisement(message_details)
