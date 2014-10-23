from datetime import datetime
from impacket import version
from ClassS3 import DataRead
from TestFiles.Detection import Detection

print version.BANNER

dataRead = DataRead.DataRead('../Packets/NeighborSpoofing-Test1.s0i0.pcap').getSlaac
detectRA = Detection()
for message_details in dataRead:
    print "Entry Time of Packet: "+str(datetime.now())
    detectRA.detect_neighbor_spoofing(message_details)