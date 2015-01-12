from impacket import version
from ClassS3 import DataRead
from ClassS3 import LearningMode

print version.BANNER

dataRead = DataRead.DataRead('../Packets/RouterAdvertismentAttack-Test2.s0i1.pcap').activateLearningMode()
learningmode = LearningMode.LearningMode()
for message_details in dataRead:
    learningmode.learn(message_details)

        #detectRA.detect_neighbor_spoofing(message_details)
