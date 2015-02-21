import os.path

class LearningMode:

    def __init__(self):
        self.name = "Hello"
        #constructor for Learning mode

    def getRouterList(self):
        checkflag = os.path.isfile("../Database/Router_Database")
        temp_database = []
        if checkflag:
            router_database = open('../Database/Router_Database','r')
            for line in router_database:
                templine = line.split(' ',3)
                templine[2] = templine[2][:-1]
                temp_database.append(templine)
            router_database.close()
        else:
            print "No such file detected"
            #must add else here with error message
            print len(temp_database)
            #print temp_database
        return temp_database


    def learn(self,message_details  ):
        # In this method, it must always be assumed that all of the router advertisements
        # detected are TRUE and LEGITIMATE. In line with this, the latest RA recieved for a
        # particular VLAN must be considered true and accepted.
        # It must be noted that for each VLAN, only 1 router is accepted.

        #3 scenarios, 1 is new entry , 2 is duplicate entry, 3 is different vlan
        router_database = self.getRouterList()
        found_flag  = False
        vlan = message_details.get_vlan_id()
        #vlan2 = "2" # used for testing , will remove once vlan is finalized na
        for router_entry in router_database:
            if router_entry[0] == vlan: #will chance once vlan number is inserted in message_details
                router_entry[1] = message_details.get_source_link_layer_address()
                router_entry[2] = str(message_details.get_ip_source_address())
                found_flag = True

        if found_flag == False:
            temp_array= [ vlan, str(message_details.get_source_link_layer_address()), str(message_details.get_ip_source_address())]
            router_database.append(temp_array)
        print router_database
        updated_router_database = open('../Database/Updated_Router_Database','w')

        for updated_entry in router_database:
            line = updated_entry[0] +" "+ updated_entry[1] + " " + updated_entry[2]+"\n"
            updated_router_database.write(line)



        updated_router_database.close()

