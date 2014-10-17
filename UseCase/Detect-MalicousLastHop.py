from impacket import version
from ClassS3 import DataRead
from TestFiles.Detection import Detection

print version.BANNER

dataRead = DataRead.DataRead('../Packets/LastHopRouter.s0i1.pcap').getSlaac
detectRA = Detection()
for message_details in dataRead:
    detectRA.detect_rogue_advertisement(message_details)