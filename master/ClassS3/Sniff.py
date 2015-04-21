import pcapy
import threading
from threading import Thread
from pcapy import findalldevs
from impacket.ImpactDecoder import *
import DataParse

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
            input = int(expression)  # turns into an integer for the function to accept
            return ifs[input]  # returns the inputted interface

        def recv_pkts(hdr, data):
            try:
                currentInt = getInterface(self.expression)
                if str(parser.learn_mode) == str(False):
                    eth = EthDecoder().decode(data)
                    ethChild = eth.child()
                    ethChild2 = ethChild.child()
                    if ethChild2.get_type() == 134:
                        parser.sniffSlaac(data,currentInt)
                    elif ethChild2.get_type() == 135:
                        parser.sniffSlaac(data,currentInt)
                    elif ethChild2.get_type() == 136:
                        parser.sniffSlaac(data,currentInt)
                elif str(parser.learn_mode) == str(True):
                    parser.activateLearningMode(data)
            except:
                pass

        pcapy.findalldevs()
        max_bytes = 1024
        promiscuous = False
        read_timeout = 100
        parser = DataParse.Dataparse(self.mode)
        pc = pcapy.open_live(getInterface(self.expression), max_bytes, promiscuous, read_timeout)
        pc.setfilter('icmp6')
        while self.isRunning is True:
            pc.loop(1, recv_pkts)  # capture packets while the thread is running


