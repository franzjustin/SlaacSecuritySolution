from impacket import version
from ClassS3 import DataRead
from TestFiles.Detection import Detection

print version.BANNER

dataRead = DataRead.DataRead('../Packets/MyNigga.s0i0.pcap').getSlaac
detectRA = Detection()
for message_details in dataRead:
    detectRA.detect_dos_dad(message_details)