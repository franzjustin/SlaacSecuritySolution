__author__ = 'root'
import sched,time
from ClassS3 import SendPackets
#justin777 fe80::2941:36b9:520f:996d
lol = SendPackets.SendPacket("fe80::20c:29ff:fe23:8411","ff02::1", "eth0")

#ip neigh show
#ip link show


def sendRA():
    time.sleep(1)
    #lol.send_ra_packet("000c29238450",1,10)
    #lol.send_ns_packet("111c291f53db", 1,"2001:db8:acad:b::b",0)
    lol.send_na_packet("111c291f53db",1,"fe80::20c:29ff:fe23:8411",0)
    #lol.send_ra_packet("000c29238450",1,0)
while(1):
    sendRA()