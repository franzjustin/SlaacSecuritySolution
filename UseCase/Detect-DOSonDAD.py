from TestFiles.SLAAC_Message import SLAAC_Message
from impacket import version
from ClassS3 import DataRead
from TestFiles.Detection import Detection

print version.BANNER

dataRead = DataRead.DataRead('../Packets/DOSonDAD.s0i1.pcap').getSlaac
detectRA = Detection()
for item in dataRead:
    x = 1
   # print "Entry Time of Packet: "+str(datetime.now())
    detectRA.detect_dos_dad(item)
   # print "End"
    print str(item.get_source_link_layer_address()) +"  "+ str(item.get_ndp_message_number())
