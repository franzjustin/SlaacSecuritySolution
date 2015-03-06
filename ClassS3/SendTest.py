__author__ = 'root'
import sched,time
import pcapy

from ClassS3 import SendPackets
#justin777 fe80::2941:36b9:520f:996d
lol = SendPackets.SendPacket("fe80::20c:29ff:fe23:8411","ff02::1", "eth0")
lol2 = SendPackets.SendPacket("fe80::8af0:77ff:fea1:1111","ff02::1", "eth0")

#ip neigh show
#ip link show

def sendRA():
    #pcapy.findalldevs()

     time.sleep(1)
    #time.sleep(20000)
    #lol.send_ra_packet("000c29238450",1,10)fe80::20c:29ff:fef3:3f92
    #lol2.send_ns_packet("ffffffffffff", 1,"fe80::222:b0ff:fe62:1bd7",0)
    #lol2.send_na_packet("ffffffffffff",1,"fe80::8af0:77ff:fea1:1111",0)
    #lol.send_ra_packet("000c29238450",1,0)
    #fe80::85e2:f6c3:7eda:2afe
sendRA()

#while(1):
#    sendRA()