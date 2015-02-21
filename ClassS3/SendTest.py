__author__ = 'root'
import sched,time
from ClassS3 import SendPackets
#justin777 fe80::2941:36b9:520f:996d
lol = SendPackets.SendPacket("fe80::20c:29ff:fe23:3123","ff02::1", "eth0")

#ip neigh show
#ip link show


def sendRA():
    time.sleep(1)
    #lol.send_ra_packet("000c29238450",1,0)
    lol.send_ns_packet("000c29238150", 1,"fe80::19d:d168:9d36:6dd",0)
    lol.send_na_packet("000c29238450",1,0)

while(1):
    sendRA()