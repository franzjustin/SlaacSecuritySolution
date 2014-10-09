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
        checkflag = self.check_for_database("../Database/Router_Database")
        print checkflag
        temp_database = []
        if checkflag:
            router_database = open('../Database/Router_Database','r')
            for line in router_database:
                templine = line.split(' ',2)
                templine[1] = templine[1][:-1]
                temp_database.append(templine)
            #router_database.close()
        else:
            print "No such file detected"
            #must add else here with error message
            print len(temp_database)
            #print temp_database
        return temp_database

    def detect_rogue_advertisement(self,message_details):
        #This method detects the if the router detects any Last Hop Malicious Router Attack
        #This method first checks if the database exist before proceeding to open the file
        #This method first checks the VLAN of the message with the vlan of the router database
        #If the VLANs do not match, the system proceeds to examine the next entry in the router database
        #If they match, the system checks if the src link layer is equal to the address in the database
        #if the addresses are equal, it means that the RA is legitimate
        #if not, it means that there is an attack happening
        x=0
        y=0
        vlan = "1"
        router_database = self.get_router_database()
        print "Checking Last Hop Router Attack"
        for x in range(len(router_database)):
            for y in range(4):
                if(vlan == router_database[x][0]):
                    if(str(message_details.get_source_link_layer_address()) != router_database[x][1]):
                        print "Rogue Router Advertisement Detected"
                        return "true"
                    else:
                        print "Legitimate Router Advertisement Detected"
                        return "false"
                else:
                    print "Incorrect Vlan, Checking other VLANs ..."


        return "false"


    def detect_neighbor_spoofing(self,message_details):
        #This method detects the if the router detects any Neighbor Spoofing Attack
        #This method first checks if the database exist before proceeding to open the file
        #This method first checks the VLAN of the message with the vlan of the router database
        #If the VLANs do not match, the system proceeds to examine the next entry in the router database
        #If they match, the system checks if the src link layer is equal to the address in the database
        #if the addresses are equal, it means that the NA is legitimate
        #if not, it means that there is an attack happening
        x = 0
        y=0
        router_database = []
        router_database = self.get_router_database()
        vlan = "1"
        for x in range(len(router_database)):
            for y in range(4):
                if(vlan == router_database[x][0]):
                    if(str(message_details.get_source_link_layer_address)!= router_database[x][1]):
                        print "Rogue Neighbor Advertisement Detected"
                        return "true"
                    else:
                        print "Legitimate Neighbor Advertisement Detected"
                        return "false"
                else:
                    print "Incorrect Vlan, Checking other VLANs ..."
        return "false"

    def update_attempt_database(self,message_details):
        checkflag = self.check_for_database('../Database/Dad_Attempt')
        
        vlan = 1;
        message = ""
        #add get vlan somewhere in message details later on
        if checkflag :
            print "inside"
            f = open('../Database/Dad_Attempt','a')
            message = str(vlan) + " " + str(message_details.get_ip_destination_address()) +" "+ str(datetime.now()) + '\n'
            print message
            f.write(message)
            f.close()

        print "hello"
        

    def check_old_attempt(self,vlan,ip_address):
        #must read last 5 attempts made
        ip_address = "::"
        num_lines = sum(1 for line in open('../Database/Dad_Attempt'))
        f = BackwardsReader.BackwardsReader('../Database/Dad_Attempt')
        x =0
        y=0
        attempt_count = []
        #test for making 2d array
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
                    #must initially  or after the count check if attempt count is old already
                    #check if entry is new or old
                    for y in range(len(attempt_count)):
                        if attempt_count[y][1] == str(ip_address):
                            attempt_count[y][0] == int(attempt_count[y][0]) + 1
                        else:
                            attempt_count.append(1,str(ip_address))
                    print " "
            print attempt_entry[0]
            print attempt_entry[1]
            print attempt_entry[2]

        print attempt_count[0][1]    
        print "qwqw"

        #f.close()
    def get_dad_attempt_database(self):
        checkflag = self.check_for_database('Dad_Attempt')
        
        #print checkflag
        #templine = []
        #temp_database = []
        #router_database = open('Router_Database','r')
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

        









    