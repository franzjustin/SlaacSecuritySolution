__author__ = 'root'
from ClassS3 import SendPackets

lol = SendPackets.SendPacket("fe80::20c:29ff:fe04:3796","fe80::20c:29ff:fe04:3796")
lol.send_ra_packet("88f077a1d88c",12)
lol.send_na_packet("88f077a1d88c",12)