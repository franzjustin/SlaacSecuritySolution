import os.path
from datetime import datetime
import time

# Creates a class called Detection
from TestFiles import BackwardsReader


class Detection:
    # Initialize when created. Self tells its from this class and the others are your created attributes
    def __init__(self):
        # Self is the new object
        self.name = "hello"
    # Creates method called lastname
    def check_for_database(self,filename):
        flag = os.path.isfile(filename)
        return flag
    def get_router_database(self):
        checkflag = self.check_for_database("dafuq")
        #print checkflag
        templine = []
        temp_database = []
        router_database = open('dafuq','r')
        if checkflag:
            for line in router_database:
                templine = line.split( ' ',2)
                templine[1] = templine[1][:-1]
                temp_database.append(templine)
        else:
            print "No such file detected"
            #must add else here with error message
            #print len(temp_database)
            #print temp_database
        return temp_database

    def detect_rogue_advertisement(self,vlan,ip_address):
        x=0
        y=0
        #vlan = "1"
        #ip_address = "7c:69:f6:1:e6:b8"
        router_database = []
        router_database = self.get_router_database()
        print "------Router Advertisement"
        print vlan
        print ip_address
        for x in range(len(router_database)):
            for y in range(4):
                if(vlan == router_database[x][0]):
                    if(ip_address != router_database[x][1]):
                        print "Rogue Router Advertisement Detected"
                        return "true"
                    else:
                        print "Legitimate Router Advertisement Detected"
                        return "false"
                else:
                    print "Incorrect Vlan, Checking other VLANs ..."


        return "false"


    def detect_neighbor_spoofing(self):
        x = 0
        y=0
        router_database = []
        router_database = self.get_router_database()
        print "------Neighbor Advertisement-------"
        vlan = "1"
        ip_address="7c:69:f6:1:e6:b8"
        print vlan
        print ip_address
        for x in range(len(router_database)):
            for y in range(4):
                if(vlan == router_database[x][0]):
                    if(ip_address != router_database[x][1]):
                        print "Rogue Neighbor Advertisement Detected"
                        return "true"
                    else:
                        print "Legitimate Neighbor Advertisement Detected"
                        return "false"
                else:
                    print "Incorrect Vlan, Checking other VLANs ..."
        return "false"

    def update_attempt_database(self,message_details):
        checkflag = self.check_for_database('dad_attempt')
        
        vlan = 1;
        message = ""
        #add get vlan somewhere in message details later on
        if checkflag :
            print "inside"
            f = open('dad_attempt','a')
            message = str(vlan) + " " + str(message_details.get_ip_destination_address()) +" "+ str(datetime.now()) + '\n'
            print message
            f.write(message)
            f.close()

        print "hello"
        

    def check_old_attempt(self,vlan,ip_address):
        #must read last 5 attempts made
        ip_address = "::"
        num_lines = sum(1 for line in open('dad_attempt'))
        f = BackwardsReader.BackwardsReader('dad_attempt')
        x =0
        attempt_count = []
        count_entry = ["1","::"]
        count_entry1 = ["1","1::1"]
        attempt_count.append(count_entry)
        attempt_count.append(count_entry1)

        attempt_entry = []
        for x in range(num_lines):
            attempt = f.readline()
            attempt_entry = attempt.split(' ',2)
            if vlan == attempt_entry[0]:
                if ip_address == attempt_entry[1]:
                    print " "
            print attempt_entry[0]
            print attempt_entry[1]
            print attempt_entry[2]

        print attempt_count[0][1]    
        print "qwqw"
        #f.close()
    def get_dad_attempt_database(self):
        checkflag = self.check_for_database('dad_attempt')
        
        #print checkflag
        #templine = []
        #temp_database = []
        #router_database = open('dafuq','r')
        #if checkflag:
        #    for line in router_database:
        #        templine = line.split( ' ',2)
        #        templine[1] = templine[1][:-1]
        #        temp_database.append(templine)
        #else:
        #    print "No such file detected"
            #must add else here with error message
            #print len(temp_database)
            #print temp_database
        return "Hello"

    def detect_dos_dad(self):
        first = datetime.now()
        print first
        time.sleep(1)
        second = datetime.now()
        print second
        third = second - first
        print third
        final = third.total_seconds()
        print final

        









    