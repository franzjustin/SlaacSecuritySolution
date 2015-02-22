import os.path
from datetime import datetime
from decimal import *
from ClassS3 import RotatingFileOpener


# Creates a class called Detection
from ClassS3 import BackwardsReader


class Detection:

    #TODO: TEST ON Real Time Environment

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
                templine = line.split(' ',3)
                templine[2] = templine[2][:-1]
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
        vlan = message_details.get_vlan_id()
        router_database = self.get_router_database()
        #print "Checking Last Hop Router Attack"
        if message_details.ndp_message_number == 134:
            #print message_details.get_source_link_layer_address()
            #print router_database[x][1]
            for x in range(len(router_database)):
                    if str(vlan) == str(router_database[x][0]):

                        if str(message_details.get_source_link_layer_address()) != str(router_database[x][1]):
                            print "Rogue Router Advertisement Detected"
                            with RotatingFileOpener.RotatingFileOpener('../Logs/', prepend='log_report-', append='.s3') as logger:
                                current_datetime = datetime.now()
                                log = str(current_datetime) + " SA001 Attacker:" + str(message_details.get_source_link_layer_address())
                                log =log + ";Victim:" + str(router_database[x][1]) + "\n"
                                logger.write(log)
                            test_open = open("../TestFiles/realtime_test_success",'a')
                            message = "True" +" "+ str(message_details.get_source_MAC_address())+ " " + str(router_database[x][1])
                            test_open.write(message)
                            test_open.write('\n')
                            test_open.close()
                            #return "true"
                        else:
                            print "Legitimate Router Advertisement Detected"
                            test_open = open("../TestFiles/realtime_test_success",'a')
                            message = "False" +" "+ str(message_details.get_source_MAC_address())+ " " + str(router_database[x][1])
                            test_open.write(message)
                            test_open.write('\n')
                            test_open.close()
                            #return "false"
                    else:
                        print "Incorrect Vlan, Checking other VLANs ..."


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
        vlan = message_details.get_vlan_id()
        #print "Hello World"
        print vlan
        if message_details.ndp_message_number == 136:
            for x in range(len(router_database)):
                if(str(vlan) == str(router_database[x][0])):
                    if message_details.get_router_flag() == True and  message_details.get_override_flag() == True:
                        if message_details.get_ip_source_address() == router_database[x][2]:
                            #address of router is present, check for correct MAC
                            if message_details.get_source_MAC_address() == router_database[x][1]:
                                print "Legitimate NA detected ( Same IP and MAC)"
                                test_open = open("../TestFiles/realtime_test_success",'a')
                                message = "False" +" "+ str(message_details.get_source_MAC_address())+ " " + str(router_database[x][1])
                                test_open.write(message)
                                test_open.write('\n')
                                test_open.close()
                            else:
                                print "Spoofed NA detected"
                                with RotatingFileOpener.RotatingFileOpener('../Logs/', prepend='log_report-', append='.s3') as logger:
                                    current_datetime = datetime.now()
                                    log = str(current_datetime) + " SA002 Attacker:" + str(message_details.get_source_MAC_address())
                                    log =log + ";Victim:" + str(router_database[x][1]) + "\n"
                                    logger.write(log)

                                test_open = open("../TestFiles/realtime_test_success",'a')
                                message = "True" +" "+ str(message_details.get_source_MAC_address())+ " " + str(router_database[x][1])
                                test_open.write(message)
                                test_open.write('\n')
                                test_open.close()
                        else:
                            print "Spoofed NA ( Different IP)"

                            with RotatingFileOpener.RotatingFileOpener('../Logs/', prepend='log_report-', append='.s3') as logger:
                                    current_datetime = datetime.now()
                                    log = str(current_datetime) + " SA002 Attacker:" + str(message_details.get_source_MAC_address())
                                    log =log + ";Victim:" + str(router_database[x][1]) + "\n"
                                    logger.write(log)

                            test_open = open("../TestFiles/realtime_test_success",'a')
                            message = "True" +" "+ str(message_details.get_source_MAC_address())+ " " + str(router_database[x][1])
                            test_open.write(message)
                            test_open.write('\n')
                            test_open.close()
                    else:
                        print "Legitimate NA detected (No router and Override) "
                        test_open = open("../TestFiles/realtime_test_success",'a')
                        message = "False" +" "+ str(message_details.get_source_MAC_address())+ " " + str(router_database[x][1])
                        test_open.write(message)
                        test_open.write('\n')
                        test_open.close()
                    #if str(router_database[x][2]) == str(message_details.get_target_address()):
                    #    if(str(message_details.get_source_link_layer_address)!= router_database[x][1]):
                    #        print "Rogue Neighbor Advertisement Detected"
                    #        #return "true"
                    #    else:
                    #        print "Legitimate Neighbor Advertisement Detected"
                    #        #return "false"
                    #else:
                    #    print "Valid Neighbor Advertisement"
                else:
                    print "Incorrect Vlan, Checking other VLANs ..."
            #return "false"
        else:
            print "Not NS"
        test_openb = open("../TestFiles/test2b",'a')
        test_startb = datetime.now()
        sum =  Decimal(test_startb.strftime(("%s"))) + Decimal(test_startb.strftime(("%f")))/1000000
        test_openb.write(str(sum))
        test_openb.write('\n')
        test_openb.close()
        print "Packet Process Ended"
        print datetime.now()
    def update_attempt_database(self,message_details):
        #This function basically adds entry to the DAD Attempt database
        #it uses the details from the message_details sent from the detect dos in dad func
        #it checks if the database Dad_attempt exist and if yes , it packages the details
        #details are in the format as follows
        #vlan no^ip_address^timestamp
        #where ^ is a space character :)
        checkflag = self.check_for_database('../Database/Dad_Attempt')
        vlan = message_details.get_vlan_id()
        #add get vlan somewhere in message details later on
        if checkflag :
            #print "Start DAD_Attempt File"
                f = open('../Database/Dad_Attempt','a')
                message = str(vlan) + " " + str(message_details.get_source_MAC_address()) +" "+ str(datetime.now()) + " " + str(message_details.get_destination_MAC_address()) +'\n'
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
        for x in range(num_lines):
            attempt = f.readline()
            attempt_entry = attempt.split(' ',4)
            arrive_date = attempt_entry[2] + " " + attempt_entry[3]
            arrival_date = datetime.strptime(arrive_date,"%Y-%m-%d %H:%M:%S.%f" )
            check_date = datetime.now()
            subtrahend = Decimal( arrival_date.strftime(("%s"))) + Decimal(arrival_date.strftime(("%f")))/1000000
            minuend = Decimal(check_date.strftime(("%s"))) + Decimal(check_date.strftime(("%f")))/1000000
            difference = minuend - subtrahend
            time_limit =  Decimal("2.00")
            if difference < time_limit:
                temp_list.append(attempt)

        f = open('../Database/Updated_DAD_attempt','w')
        f.writelines(temp_list)
        f.close()

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
            #print '********************************************************************* - '+ message_details.get_ip_source_address()
            if str(message_details.get_ip_source_address())=="::":
                #print '*********************************************************************'
                self.update_attempt_database(message_details)
                self.check_old_attempt()
                address_list = []
                dad_attempt_database = open('../Database/Updated_DAD_attempt')
                for line in dad_attempt_database:
                    found = False
                    address_entry = line.split(' ',4)
                    print address_entry[0]
                    print address_entry[1]
                    print address_entry[2]
                    print address_entry[3]
                    print address_entry[4]
                    #format for address entry is 0     ,  1      ,      2     ,     3      ,     4
                    #                            VLAN  , SRC_MAC , entry date , entry time , DEST_MAC
                    #format for address list
                    #format for new entry/   is  0        ,  1      ,      2     ,     3     ,   4
                    #                            SRC_MAC  ,DEST_MAC , entry date , entry time , VLAN

                    if len(address_list) ==0:
                        new_entry = [str(address_entry[1]),str(address_entry[4][:-1]),str(address_entry[2]),str(address_entry[3]),str(address_entry[0])]
                        address_list.append(new_entry)


                    else :
                        for x in range(len(address_list)):
                            if address_list[x][0] == address_entry[1] and address_list[x][1]==address_entry[4]:
                                found = True

                        if found == False:
                            new_entry = [str(address_entry[1]),str(address_entry[4][:-1]),str(address_entry[2]),str(address_entry[3]),str(address_entry[0])]
                            address_list.append(new_entry)
                earliest= 0
                #print address_list.__len__()
                searched_list = []
                count_list = []
                for x in range(len(address_list)-2):
                    #check count per source first
                    #format for address list/   is  0        ,  1      ,      2     ,     3     ,   4
                    #                           SRC_MAC  ,DEST_MAC , entry date , entry time , VLAN
                    #format for count list  /   is  0   ,  1      ,      2     ,     3    , 4
                    #                           SRC_MAC  , entry date , entry time , VLAN , count
                    y = x +1
                    print "????"
                    print len(address_list)
                    while y <= len(address_list)-1:
                        found = False
                        if y in searched_list:
                            pass
                        else:
                            print "**"
                            print x
                            print y
                            if address_list[x][0] == address_list[y][0]:
                                searched_list.append(y)
                                #search for entry
                                if len(count_list) == 0:
                                    new_entry = [address_list[x][0],address_list[x][2],address_list[x][3],address_list[x][4],1]
                                    count_list.append(new_entry)
                                else:
                                    for count_entry in count_list:
                                        if count_entry[0] == address_list[y][0]:
                                            count_entry[4] = count_entry[4] + 1
                                            found = True
                                    if found == False:
                                        new_entry =  [address_list[x][0],address_list[x][2],address_list[x][3],address_list[x][4],1]
                                        count_list.append(new_entry)
                        y = y+1
                        print "y now is " + str(y)
                        #entry_date = address_updated[2] + " " + address_updated[3]
                        #datetime_subtrahend = datetime.strptime(str(entry_date),"%Y-%m-%d %H:%M:%S.%f").microsecond
                        #datetime_minuend = datetime.now().microsecond
                        #difference = datetime_minuend - datetime_subtrahend
                        print count_list
                        #if difference < earliest:
                         #   earliest = difference

                        for dad_entry in count_list:
                            entry_date = dad_entry[1] + " " + dad_entry[2]
                            datetime_subtrahend = datetime.strptime(str(entry_date),"%Y-%m-%d %H:%M:%S.%f").microsecond
                            datetime_minuend = datetime.now().microsecond
                            difference = datetime_minuend - datetime_subtrahend
                            print datetime.now()
                            print entry_date
                            print "-----"
                            print datetime_minuend
                            print datetime_subtrahend
                            print difference
                            print dad_entry[4]
                            if dad_entry[4] > 2 and difference <2000000:
                                print "DOS in DAD Detected"
                                test_open = open("../TestFiles/realtime_test1_success",'a')
                                message = "True"
                                test_open.write(message)
                                test_open.write('\n')
                                test_open.close()
                                with RotatingFileOpener.RotatingFileOpener('../Logs/', prepend='log_report-', append='.s3') as logger:
                                    current_datetime = datetime.now()
                                    log = str(entry_date) + " SA003 Attacker:" + str(dad_entry[0])
                                    log =log+"\n"
                                    logger.write(log)
                            else:
                                print "DAD Legitimate"
                                test_open = open("../TestFiles/realtime_test1_success",'a')
                                message = "False"
                                test_open.write(message)
                                test_open.write('\n')
                                test_open.close()

                    test_open = open("../TestFiles/AfterDetectionLastHop",'a')
                    test_start = datetime.now()
                    sum = Decimal(test_start.strftime(("%s"))) + Decimal(test_start.strftime(("%f")))/1000000
                    test_open.write(str(sum))
                    test_open.write('\n')
                    test_open.close()




    