import pcapy
import time
import threading
from threading import Thread
from pcapy import findalldevs
from datetime import datetime
from decimal import *
from impacket.ImpactDecoder import *
import DataParse
import SendPackets
import SLAAC_Message


class Forever_Loop(threading.Thread):
    def __init__(self):
        self.isRunning = True
        Thread.__init__(self)

    def start(self):
        Thread.__init__(self)
        Thread.start(self)

    def stop(self):
        self.isRunning = False

    def setExpression(self, expression):
        self.expression = expression

    def run(self):
        Thread.__init__(self)
        while self.isRunning == True:
            def getInterface(expression):
                ifs = findalldevs()
                if 0 == len(ifs):
                    print "You don't have enough permissions to open any interface on this system."
                    sys.exit(1)

                # Only one interface available, use it.
                elif 1 == len(ifs):
                    print 'Only one interface present, defaulting to it.'
                    return ifs[0]

                input = int(expression) # turns into an integer for the function to accept
                return ifs[input] # returns the inputted interface

                # list all the network devices

            def recv_pkts(hdr, data):
                try:
                    mode = False
                    eth = EthDecoder().decode(data)
                    ethChild = eth.child()
                    ethChild2 = ethChild.child()
                    if ethChild2.get_type() == 134:
                        # ------------Time Start------------
                        test_open = open("../TestFiles/realtime_test1_sniff", 'a')
                        test_start = datetime.now()
                        sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f"))) / 1000000
                        test_open.write(str(sum))
                        test_open.write('\n')
                        test_open.close()
                        #-----------------------------------
                        parser.sniffSlaac(data)
                        #------------Time Start------------
                        test_open = open("../TestFiles/realtime_test1_detect", 'a')
                        test_start = datetime.now()
                        sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f"))) / 1000000
                        test_open.write(str(sum))
                        test_open.write('\n')
                        test_open.close()
                        #-----------------------------------
                        #print "Hello"

                    elif ethChild2.get_type() == 135:
                        # ------------Time Start------------
                        test_open = open("../TestFiles/realtime_test1_sniff", 'a')
                        test_start = datetime.now()
                        sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f"))) / 1000000
                        test_open.write(str(sum))
                        test_open.write('\n')
                        test_open.close()
                        #-----------------------------------
                        parser.sniffSlaac(data)
                        #------------Time Start------------
                        test_open = open("../TestFiles/realtime_test1_detect", 'a')
                        test_start = datetime.now()
                        sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f"))) / 1000000
                        test_open.write(str(sum))
                        test_open.write('\n')
                        test_open.close()
                        #-----------------------------------
                        #print "Hello"
                    elif ethChild2.get_type() == 136:
                        # ------------Time Start------------
                        test_open = open("../TestFiles/realtime_test1_sniff", 'a')
                        test_start = datetime.now()
                        sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f"))) / 1000000
                        test_open.write(str(sum))
                        test_open.write('\n')
                        test_open.close()
                        #----------0-------------------------
                        parser.sniffSlaac(data)
                        #------------Time Start------------
                        test_open = open("../TestFiles/realtime_test1_detect", 'a')
                        test_start = datetime.now()
                        sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f"))) / 1000000
                        test_open.write(str(sum))
                        test_open.write('\n')
                        test_open.close()
                        #-----------------------------------
                        #print "Hello"

                except:
                    x = 1
                    print "error"


            pcapy.findalldevs()
            max_bytes = 1024
            promiscuous = False
            read_timeout = 100  # in milliseconds
            pc = pcapy.open_live(getInterface(self.expression), max_bytes, promiscuous, read_timeout)
            pc.setfilter('icmp6')
            mode = False
            parser = DataParse.Dataparse(mode)
            # callback for received packets
            packet_limit = -1  # infinite
            pc.loop(packet_limit, recv_pkts)  # capture packets
