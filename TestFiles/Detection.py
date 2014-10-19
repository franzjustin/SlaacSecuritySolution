from decimal import Decimal
import os.path
from datetime import datetime, timedelta
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
        #print checkflag
        temp_database = []
        if checkflag:
            router_database = open('../Database/Router_Database','r')
            for line in router_database:
                templine = line.split(' ',3)
                templine[2] = templine[2][:-1]
                temp_database.append(templine)
            #router_database.close()
        else:
            print "No such file detected"
            #must add else here with error message
            #print len(temp_database)
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
        if message_details.ndp_message_number == 134:
            for x in range(len(router_database)):
                if vlan == router_database[x][0]:
                    if str(message_details.get_source_link_layer_address()) != router_database[x][1]:
                        print "Rogue Router Advertisement Detected - " + message_details.get_source_link_layer_address()
                        #return "true"
                        test_open = open("../TestFiles/AfterDetectionLastHop",'a')
                        test_start = datetime.now()
                        sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f")))/1000000
                        test_open.write(str(sum))
                        test_open.write('\n')
                        test_open.close()
                    else:
                        print "Legitimate Router Advertisement Detected"
                        #return "false"
                else:
                    print "Incorrect VLAN, Checking other VLANs ..."
            return "false"
        else:
            return "Not RA"

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
        if message_details.ndp_message_number == 136:
            for x in range(len(router_database)):
#                for y in range(4):
                if(vlan == router_database[x][0]):
                    #print router_database[x][1]
                    #print message_details.get_target_address()
                    if str(router_database[x][2]) != str(message_details.get_target_address()):
                        if(str(message_details.target_link_layer_address)!= router_database[x][1]):
                            print "Rogue Neighbor Advertisement Detected - at " + str(datetime.now())
                            #return "true"
                        else:
                            print "Legitimate Neighbor Advertisement Detected"
                            #return "false"
                    else:
                        print "Valid Neighbor Advertisement"
                else:
                    print "Incorrect Vlan, Checking other VLANs ..."
            return "false"
        else:
            return "Not NS"

    def update_attempt_database(self,message_details):
        #This function basically adds entry to the DAD Attempt database
        #it uses the details from the message_details sent from the detect dos in dad func
        #it checks if the database Dad_attempt exist and if yes , it packages the details
        #details are in the format as follows
        #vlan no^ip_address^timestamp
        #where ^ is a space character :)
        checkflag = self.check_for_database('../Database/Dad_Attempt')
        vlan = 1
        #add get vlan somewhere in message details later on
        if checkflag :
            #print "Start DAD_Attempt File"
                f = open('../Database/Dad_Attempt','a')
                message = str(vlan) + " " + str(message_details.target_address) +" "+ str(datetime.now()) + '\n'
                #print message
                f.write(message)
                f.close()


    def check_old_attempt(self):
        #This function checks the old DAD attempts made and deletes them
        #The function determines if the attempt is old with the number of dad attempts on a specific address
        #this means that an address with 6 different attempts would only have the oldest attempt deleted
        #a maximum of 5 attempts per address would only be stored in the database
        #the function first checks the total number of lines as well as uses a backward reader class
        #then the function examines the lines from the DAD attempt database one by one
        #the function stores the line from the DAD attempt database if they fit the requirements
        #after which, the system proceeds to overwrite the dad database with the new updated list
        num_lines = sum(1 for line in open('../Database/Dad_Attempt'))
        f = BackwardsReader.BackwardsReader('../Database/Dad_Attempt')
        x =0
        y=1
        temp_list = [] #array to be used for new list
        attempt_count = []
        attempt_entry = []
        for x in range(3):
            attempt = f.readline()
            attempt_entry = attempt.split(' ',2)
            print "attempt entry index0 %s"%attempt_entry[0]
            print "attempt entry index1 %s"%attempt_entry[1]
            print "attempt entry index2 %s"%attempt_entry[2]
            temp_list.append(attempt)
        #print temp_list

            #if len(attempt_count) ==0:
            #    #print "empty"
            #    new_entry = [1,str(attempt_entry[1])]
            #    attempt_count.append(new_entry)
            #    temp_list.append(attempt)
            #else:
            #    for y in range(len(attempt_count)):
            #        if str(attempt_count[y][1]) == str(attempt_entry[1]):
            #            #print "count incremented"
            #            attempt_count[y][0] = attempt_count[y][0] + 1
            #            #print "increment successfull"
            #            found = "true"
            #            if attempt_count[y][0] <6:
            #                temp_list.append(attempt)

            #    if str(found) =="false" :
                    #print "new entry found"
            #        new_entry = [1,str(attempt_entry[1])]
            #        attempt_count.append(new_entry)
            #        temp_list.append(attempt)

        f = open('../Database/Updated_DAD_attempt','w')
        f.writelines(temp_list)
        f.close()

    def get_dad_attempt_database(self):
        #FORGOT WHAT I INTENDED THIS FOR
        #MUST BE EXTRA CODE
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

    def detect_dos_dad(self, message_details):
        #The detect dos in dad function detects dos in dad attacks in the network.
        #it first updates the attempts dad attemps with the new packet
        #Then, the system first deletes the old dad attemps made
        #For my sake, the output of the update dos attempts is in another file so that i can compare it first with the old dad attempts
        #then, after updating the list, the function proceeds to get the first and last attempt for an anddress
        #it stores it in a list :)
        #the system thens simply converts the string into datetime and extracts the difference of the first and last
        # after extracting, the system convers the difference into seconds
        #if the total number of seconds between the last and first attempt is greater than 5, an attack is detected.
        # personally, i feel that the values need to be adjusted
        # I think the total seconds allowable should be minimized to at the minimum 1 or 2 seconds
        #DO NOT DELETE THIS LINES :)
        #must check first and last attempt of each address
        if message_details.ndp_message_number == 135:
            if str(message_details.get_ip_source_address())=="::":
                self.update_attempt_database(message_details)
                self.check_old_attempt()
                address_list = []
                dad_attempt_database = open('../Database/Updated_DAD_attempt')
                for line in dad_attempt_database:
                    address_entry = line.split(' ',2)
                    address_list.append(address_entry)
                    #print "------Start---------"
                    #print line
                    #address_entry = line.split(' ', 2)
                    #found = "false"
                    #print first
                    #if len(address_list) == 0:
                    #    #print "Entering first "
                    #    new_entry = [str(address_entry[1]),str(address_entry[2]),str(address_entry[1]),str(address_entry[2])]
                    #    address_list.append(new_entry)
                    #else:
                    #    for x in range(len(address_list)):
                    #        if str(address_list[x][0]) == str(address_entry[1]):
                    #            address_list[x][2] = str(address_entry[1])
                    #            address_list[x][3] = str(address_entry[2])
                    #            #print "match found"
                    #            found = "DOS on DAD Detected in Network"
                    #            #print datetime.now()
                    #    if found=="false":
                    #        new_entry = [str(address_entry[1]),str(address_entry[2]),str(address_entry[1]),str(address_entry[2])]
                    #        address_list.append(new_entry)
                    #        #print "new entry"

                dad_attempt_database.close()
                #date_sum = datetime.strptime("00-00-00 00:00:00.00000","%Y-%m-%d %H:%M:%S.%f" )
                #for z in range(len(address_list)):
                #    print address_list[z]
                #print "*****************************************************************************"

                #time_period = datetime.strptime("00-00-00 00:00")
                #trytry = timedelta()
                #print trytry

                date_half = str(address_list[0][2]).split()
                #print address_list[0][2]
                date = date_half[0].split("-",3)
                #print date
                time = date_half[1].split(":",3)
                microseconds = time[2].split(".",2)
                #print time
                #print microseconds
                date_addend1 = timedelta(int(date[2]),int(microseconds[0]),int(microseconds[1]),0,int(time[1]),int(time[0]),0)
                #print date_addend1.total_seconds()

                date_half = str(address_list[len(address_list)-1][2]).split()
                #print address_list[len(address_list)-1][2]
                date = date_half[0].split("-",3)
                #print date
                time = date_half[1].split(":",3)
                microseconds = time[2].split(".",2)
                #print time
                #print microseconds
                date_addend2 = timedelta(int(date[2]),int(microseconds[0]),int(microseconds[1]),0,int(time[1]),int(time[0]),0)
                #print date_addend2.total_seconds()

                difference = date_addend1 - date_addend2
                print difference.total_seconds()

                    #new_date    = date[0] + " " + date[1]

                    #format = "%Y-%m-%d %H:%M:%S.%f"
                    #date_addend = datetime.strptime(new_date,format)
                    #qwerty = date_addend +qwerty
                    #print date_addend
                    #total_sec = date_addend.total_seconds()
                    #date_sum = date_sum + date_addend

                #print date_sum.total_seconds()
                    #date = str(address_list[q][2]).split()
                    #new_date = date[0] + " " + date[1]
                    #date_subtrahend = datetime.strptime(new_date,format)
                    #date_difference = date_minuend - date_subtrahend
                    #total_difference_seconds = date_difference.total_seconds()
                    #print "minuend"
                    #print date_minuend
                    #print "subtrahend"
                    #print date_subtrahend
                    #print "difference"
                    #print date_difference
                    #print "total seconds"
                    #print total_difference_seconds
                    #if total_difference_seconds<5:
                    #    print "DOS on DAD Attack Detected " + str(total_difference_seconds)
                    #else:
                    #    x = 1
                    #return total_difference_seconds





    