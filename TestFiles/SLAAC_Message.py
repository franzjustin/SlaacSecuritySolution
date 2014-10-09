# Creates a class called SLAAC_Message
class SLAAC_Message:
    # Initialize when created. Self tells its from this class and the others are your created attributes
    def __init__(self,ndp_message_number,source_link_layer_address,ip_source_address,ip_destination_address,source_MAC_address_final,destination_MAC_address_final,target_address):
        # Self is the new object
        self.ndp_message_number = ndp_message_number
        self.source_link_layer_address= source_link_layer_address
        self.source_MAC_address = source_MAC_address_final
        self.ip_source_address = ip_source_address
        self.destination_MAC_address = destination_MAC_address_final
        self.ip_destination_address = ip_destination_address
        self.target_address = target_address
        
    # Creates method called lastname
    def get_target_address(self):
        return self.target_address

    def get_ip_destination_address(self):
    	return self.ip_destination_address

    def get_destination_MAC_address(self):
    	return self.destination_MAC_address

    def get_ip_source_address(self):
    	return self.ip_source_address

    def get_source_MAC_address(self):
    	return self.source_MAC_address

    def get_source_link_layer_address(self):
    	return self.source_link_layer_address

    def get_ndp_message_number(self):
        return self.ndp_message_number
