__author__ = 'root'
import sched,time
import pcapy

from ClassS3 import SendPackets
#justin777 fe80::2941:36b9:520f:996d
#windows fe80::5d7f:5d51:cff9:4280
#Ubuntu fe80::221:5dff:fef2:f550

lol = SendPackets.SendPacket("fe80::20c:29ff:fe23:1112","ff02::1", "eth0")
lol2 = SendPackets.SendPacket("fe80::8af0:77ff:fea1:1111","ff02::1", "eth0")

#ip neigh show
#ip link show

def sendRA():
	#pcapy.findalldevs()
    #this is sleep, it sleeps thread.
	 time.sleep(1)
	#time.sleep(20000)
	 print "1"
	# lol.send_ra_packet("000c29238450",1,10,"Erase")#fe80::20c:29ff:fef3:3f92
	# lol.send_ra_packet("000c29238450",1,20,"Erase")#fe80::20c:29ff:fef3:3f92
	# lol.send_ra_packet("000c29238450",1,30,"Erase")#fe80::20c:29ff:fef3:3f92
	# lol.send_ra_packet("000c29238450",1,40,"Erase")#fe80::20c:29ff:fef3:3f92
	# lol.send_ra_packet("000c29238450",1,0)#fe80::20c:29ff:fef3:3f92
	 lol2.send_ns_packet("ffffffffffff", 1,"fe80::221:5dff:fef2:f550",0)
	#lol2.send_na_packet("ffffffffffff",1,"fe80::8af0:77ff:fea1:1111",0)
    #lol.send_ra_packet("000c29238450",1,0)
	# lol.send_ra_packet("000c29238450",1,0)
	# lol.send_na_packet("000c29238450",1,"fe80::20c:29ff:fe23:8411",0)
	#fe80::85e2:f6c3:7eda:2afe
sendRA()

while(1):
 sendRA()