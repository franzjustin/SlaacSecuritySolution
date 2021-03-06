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
        self.mode = False
        self.expression = 0
        Thread.__init__(self)

    def start(self):
        Thread.__init__(self)
        Thread.start(self)

    def stop(self):
        self.isRunning = False

    def setMode(self, mode):
        self.mode = mode

    def setExpression(self, expression):
        self.expression = expression

    def run(self):
        Thread.__init__(self)

        def getInterface(expression):
            ifs = findalldevs()
            if 0 == len(ifs):
                print "You don't have enough permissions to open any interface on this system."
                sys.exit(1)

            # Only one interface available, use it.
            elif 1 == len(ifs):
                print 'Only one interface present, defaulting to it.'
                return ifs[0]

            input = int(expression)  # turns into an integer for the function to accept
            return ifs[input]  # returns the inputted interface

        def recv_pkts(hdr, data):
            try:
                currentInt = getInterface(self.expression)
                #print "parser.mode is "+ str(parser.learn_mode)
                if str(parser.learn_mode) == str(False):
                    eth = EthDecoder().decode(data)
                    ethChild = eth.child()
                    ethChild2 = ethChild.child()
                    if ethChild2.get_type() == 134:
                        # ------------Time Start------------
                        #test_open = open("../TestFiles/realtime_test1_sniff", 'a')
                        #test_start = datetime.now()
                        #sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f"))) / 1000000
                        #test_open.write(str(sum))
                        #test_open.write('\n')
                        #test_open.close()
                        # -----------------------------------
                        parser.sniffSlaac(data,currentInt)
                        # ------------Time Start------------
                        #test_open = open("../TestFiles/realtime_test1_detect", 'a')
                        #test_start = datetime.now()
                        #sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f"))) / 1000000
                        #test_open.write(str(sum))
                        #test_open.write('\n')
                        #test_open.close()
                    # -----------------------------------
                    # print "Hello"

                    elif ethChild2.get_type() == 135:
                        # ------------Time Start------------
                        #test_open = open("../TestFiles/realtime_test1_sniff", 'a')
                        #test_start = datetime.now()
                        #sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f"))) / 1000000
                        #test_open.write(str(sum))
                        #test_open.write('\n')
                        #test_open.close()
                        # -----------------------------------
                        parser.sniffSlaac(data,currentInt)
                        #------------Time Start------------
                        #test_open = open("../TestFiles/realtime_test1_detect", 'a')
                        #test_start = datetime.now()
                        #sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f"))) / 1000000
                        #test_open.write(str(sum))
                        #test_open.write('\n')
                        #test_open.close()
                    # -----------------------------------
                    #print "Hello"
                    elif ethChild2.get_type() == 136:
                        # ------------Time Start------------
                        #test_open = open("../TestFiles/realtime_test1_sniff", 'a')
                        #test_start = datetime.now()
                        #sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f"))) / 1000000
                        #test_open.write(str(sum))
                        #test_open.write('\n')
                        #test_open.close()
                        # ----------0-------------------------
                        parser.sniffSlaac(data,currentInt)
                        #------------Time Start------------
                        #test_open = open("../TestFiles/realtime_test1_detect", 'a')
                        #test_start = datetime.now()
                        #sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f"))) / 1000000
                        #test_open.write(str(sum))
                        #test_open.write('\n')
                        #test_open.close()
                    # -----------------------------------
                    #print "Hello"
                elif str(parser.learn_mode) == str(True):
                    #print "activating learning mode"
                    parser.activateLearningMode(data)
            except:
                x = 1
                print "error"

        pcapy.findalldevs()
        max_bytes = 1024
        promiscuous = False
        read_timeout = 100  # in milliseconds
        #print "self.mode " + str(self.mode)
        parser = DataParse.Dataparse(self.mode)
        # callback for received packets
        #print "---------------"
        #print self.expression
        pc = pcapy.open_live(getInterface(self.expression), max_bytes, promiscuous, read_timeout)
        pc.setfilter('icmp6')
        # list all the network devices
        while self.isRunning is True:
            pc.loop(1, recv_pkts)  # capture packets while the thread is running


