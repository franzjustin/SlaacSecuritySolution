import os.path
from datetime import datetime
from decimal import *
import RotatingFileOpener,SendPackets
import BackwardsReader

class Detection:
    def __init__(self):
        f = open('../Database/Manual_VLAN', 'r')
        manual = f.read()
        f.close()
        self.manualVlan = manual

    def getVlanFromRouterDb(self):
        f = open('../Database/Router_Database', 'r')
        RouterTemp = f.read()
        f.close()
        RouterRawAddress = RouterTemp.split('\n')
        RouterIPs = []
        vlanList =[]
        for x in RouterRawAddress:
            RouterIPs.append( x.split(' '))
        for x in range(len(RouterIPs)):
            vlanList.append(RouterIPs[x][0])
        vlanList = filter(None,vlanList)
        return vlanList

    def check_for_database(self,filename):
        flag = os.path.isfile(filename)
        return flag

    def get_router_database(self):
        checkflag = self.check_for_database("../Database/Router_Database")
        temp_database = []
        if checkflag:
            router_database = open('../Database/Router_Database','r')
            for line in router_database:
                templine = line.split(' ',3)
                templine[2] = templine[2][:-1]
                temp_database.append(templine)
        else:
            print "No such file detected"
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
        if message_details.ndp_message_number == 134:
            if str(message_details.get_router_lifetime()) != "00" and str(message_details.get_router_lifetime()) != "ffff":
                for x in range(len(router_database)):
                        if str(vlan) == str(router_database[x][0]):
                           if str(message_details.get_ip_source_address()) == str(router_database[x][2]) :
                                if str(message_details.get_source_link_layer_address()) != str(router_database[x][1]):
                                    print "Rogue Router Advertisement Detected"
                                    with RotatingFileOpener.RotatingFileOpener('../Logs/', prepend='log_report-', append='.s3') as logger:
                                        current_datetime = datetime.now()
                                        log = str(current_datetime) + " SA001 Attacker:" + str(message_details.get_source_link_layer_address())
                                        log =log + ";Victim:" + str(router_database[x][1]) + "\n"
                                        logger.write(log)
                                    parseIpSourceAdd =  str(message_details.get_ip_source_address()).lower()
                                    mitigateMessage = SendPackets.SendPacket(parseIpSourceAdd,"ff02::1", str(message_details.get_interface()))
                                    IpSourceMac = message_details.get_source_link_layer_address().replace(':','')
                                    if  self.manualVlan == "True":
                                            for x in self.getVlanFromRouterDb():
                                                mitigateMessage.mitigate_last_hop_router(parseIpSourceAdd,IpSourceMac,str(x))
                                    else:
                                        mitigateMessage.mitigate_last_hop_router(parseIpSourceAdd,IpSourceMac,message_details.get_vlan_id())
                                    test_open = open("../Database/Notification", 'a')
                                    test_start = datetime.now()
                                    sum = str(test_start) + " SA001 Attacker:" + str(message_details.get_source_link_layer_address())
                                    test_open.write(str(sum))
                                    test_open.write('\n')
                                    test_open.close()
                                else:
                                    print "Legitimate Router Advertisement Detected"
                           else:
                                print "Rogue Router Advertisement Detected"
                                with RotatingFileOpener.RotatingFileOpener('../Logs/', prepend='log_report-', append='.s3') as logger:
                                    current_datetime = datetime.now()
                                    log = str(current_datetime) + " SA001 Attacker:" + str(message_details.get_source_link_layer_address())
                                    log =log + ";Victim:" + str(router_database[x][1]) + "\n"
                                    logger.write(log)
                                parseIpSourceAdd =  str(message_details.get_ip_source_address()).lower()
                                mitigateMessage = SendPackets.SendPacket(parseIpSourceAdd,"ff02::1", str(message_details.get_interface()))
                                IpSourceMac = message_details.get_source_link_layer_address().replace(':','')
                                if self.manualVlan == "True":
                                        for x in self.getVlanFromRouterDb():
                                            mitigateMessage.mitigate_last_hop_router(parseIpSourceAdd,IpSourceMac,str(x))
                                else:
                                    mitigateMessage.mitigate_last_hop_router(parseIpSourceAdd,IpSourceMac,message_details.get_vlan_id())
                                test_open = open("../Database/Notification", 'a')
                                test_start = datetime.now()
                                sum = str(test_start) + " SA001 Attacker:" + str(message_details.get_source_link_layer_address())
                                test_open.write(str(sum))
                                test_open.write('\n')
                                test_open.close()
                        else:
                            pass
            else:
                print "Legitimate Router Advertisement Detected"

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
        router_database = self.get_router_database()
        vlan = message_details.get_vlan_id()
        if message_details.ndp_message_number == 136:
            for x in range(len(router_database)):
                if(str(vlan) == str(router_database[x][0])):
                    if message_details.get_router_flag() == True and  message_details.get_override_flag() == True:
                        if message_details.get_ip_source_address() == router_database[x][2]:
                            if message_details.get_source_MAC_address() == router_database[x][1]:
                                print "Legitimate NA detected (Same IP and MAC)"
                            else:
                                print "Spoofed NA detected"
                                with RotatingFileOpener.RotatingFileOpener('../Logs/', prepend='log_report-', append='.s3') as logger:
                                    current_datetime = datetime.now()
                                    log = str(current_datetime) + " SA002 Attacker:" + str(message_details.get_source_MAC_address())
                                    log =log + ";Victim:" + str(router_database[x][1]) + "\n"
                                    logger.write(log)
                                parseTargetLinkLayer = message_details.get_target_link_layer_address().replace(':','')
                                parseIpSourceAdd =  str(message_details.get_ip_source_address()).lower()
                                mitigateMessage = SendPackets.SendPacket(parseIpSourceAdd,"ff02::1", message_details.get_interface())
                                if self.manualVlan == "True":
                                    for x in self.getVlanFromRouterDb():
                                        mitigateMessage.mitigate_neighbor_advertisement_spoofing(parseTargetLinkLayer,parseIpSourceAdd,x)
                                else:
                                    mitigateMessage.mitigate_neighbor_advertisement_spoofing(parseTargetLinkLayer,parseIpSourceAdd,message_details.get_vlan_id())
                                test_open = open("../Database/Notification", 'a')
                                test_start = datetime.now()
                                sum = str(test_start) + " SA002 Attacker:" + str(message_details.get_source_MAC_address())
                                test_open.write(str(sum))
                                test_open.write('\n')
                                test_open.close()
                        else:
                            print "Spoofed NA(Different IP)"
                            parseTargetLinkLayer = message_details.get_target_link_layer_address().replace(':','')
                            parseIpSourceAdd =  str(message_details.get_ip_source_address()).lower()
                            mitigateMessage = SendPackets.SendPacket(parseIpSourceAdd,"ff02::1",  message_details.get_interface())
                            if self.manualVlan == "True":
                                for y in self.getVlanFromRouterDb():
                                    mitigateMessage.mitigate_neighbor_advertisement_spoofing(parseTargetLinkLayer,parseIpSourceAdd,y)
                            else:
                                mitigateMessage.mitigate_neighbor_advertisement_spoofing(parseTargetLinkLayer,parseIpSourceAdd,message_details.get_vlan_id())
                            with RotatingFileOpener.RotatingFileOpener('../Logs/', prepend='log_report-', append='.s3') as logger:
                                    current_datetime = datetime.now()
                                    log = str(current_datetime) + " SA002 Attacker:" + str(message_details.get_source_MAC_address())
                                    log =log + ";Victim:" + str(router_database[x][1]) + "\n"
                                    logger.write(log)
                            test_open = open("../Database/Notification", 'a')
                            test_start = datetime.now()
                            sum = str(test_start) + " SA002 Attacker:" + str(message_details.get_source_MAC_address())
                            test_open.write(str(sum))
                            test_open.write('\n')
                            test_open.close()
                    else:
                        print "Legitimate NA detected (No router and Override) "
                else:
                    print "Incorrect Vlan, Checking other VLANs ..."
        else:
            print "Not NS"
        print "Packet Process Ended"

    def update_attempt_database(self,message_details):
        #This function basically adds entry to the DAD Attempt database
        #it uses the details from the message_details sent from the detect dos in dad func
        #it checks if the database Dad_attempt exist and if yes , it packages the details
        #details are in the format as follows
        #vlan no^ip_address^timestamp
        #where ^ is a space character :)
        checkflag = self.check_for_database('../Database/Dad_Attempt')
        vlan = message_details.get_vlan_id()
        if checkflag :
                f = open('../Database/Dad_Attempt','a')
                message = str(vlan) + " " + str(message_details.get_source_MAC_address()) +" "+ str(datetime.now()) + " " + str(message_details.get_destination_MAC_address()) +'\n'
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
        temp_list = []
        for x in range(num_lines):
            attempt = f.readline()
            attempt_entry = attempt.split(' ',4)
            arrive_date = attempt_entry[2] + " " + attempt_entry[3]
            arrival_date = datetime.strptime(arrive_date,"%Y-%m-%d %H:%M:%S.%f" )
            check_date = datetime.now()
            subtrahend = Decimal( arrival_date.strftime(("%s"))) + Decimal(arrival_date.strftime(("%f")))/1000000
            minuend = Decimal(check_date.strftime(("%s"))) + Decimal(check_date.strftime(("%f")))/1000000
            difference = minuend - subtrahend
            time_limit = Decimal("2.00")
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
        #if the total number of seconds between the last and first attempt is greater than 2, an attack is detected.
        if message_details.ndp_message_number == 135:
            if str(message_details.get_ip_source_address())=="::":
                self.update_attempt_database(message_details)
                self.check_old_attempt()
                address_list = []
                dad_attempt_database = open('../Database/Updated_DAD_attempt')
                for line in dad_attempt_database:
                    found = False
                    address_entry = line.split(' ',4)
                    if len(address_list) ==0:
                        new_entry = [str(address_entry[1]),str(address_entry[4][:-1]),str(address_entry[2]),str(address_entry[3]),str(address_entry[0]),0]
                        address_list.append(new_entry)
                    else:
                        for x in range(len(address_list)):
                            if address_list[x][0] == address_entry[1] :
                                found = True
                                address_list[x][5] = address_list[x][5] + 1
                        if found == False:
                            new_entry = [str(address_entry[1]),str(address_entry[4][:-1]),str(address_entry[2]),str(address_entry[3]),str(address_entry[0]),0]
                            address_list.append(new_entry)
                for dad_entry in address_list:
                    entry_date = dad_entry[2] + " " + dad_entry[3]
                    if dad_entry[5] > 2 :
                        print "DOS in DAD Detected"
                        with RotatingFileOpener.RotatingFileOpener('../Logs/', prepend='log_report-', append='.s3') as logger:
                            log = str(entry_date) + " SA003 Victim:" + str(dad_entry[0])
                            log =log+"\n"
                            logger.write(log)
                        test_open = open("../Database/Notification", 'a')
                        sum = str(entry_date) + " SA003 Victim:" + str(dad_entry[0])
                        test_open.write(str(sum))
                        test_open.write('\n')
                        test_open.close()
                    else:
                        print "DAD Legitimate"
