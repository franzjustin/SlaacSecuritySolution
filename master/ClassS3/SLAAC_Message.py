# Creates a class called SLAAC_Message
class SLAAC_Message:
    def __init__(self, vlan_id, ndp_message_number, source_link_layer_address, ip_source_address, ip_destination_address,
                 source_MAC_address_final, destination_MAC_address_final, target_address,target_link_layer_address,override_flag,router_flag,router_lifetime="00",interface ="eth0"):
        self.vlan_id = vlan_id
        self.ndp_message_number = ndp_message_number
        self.source_link_layer_address = source_link_layer_address
        self.source_MAC_address = source_MAC_address_final
        self.ip_source_address = ip_source_address
        self.destination_MAC_address = destination_MAC_address_final
        self.ip_destination_address = ip_destination_address
        self.target_address = target_address
        self.target_link_layer_address = target_link_layer_address
        self.override_flag = override_flag
        self.router_flag = router_flag
        self.router_lifetime = router_lifetime
        self.interface = interface
    def get_vlan_id(self):
        return self.vlan_id

    def get_target_link_layer_address(self):
        return self.target_link_layer_address

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

    def get_override_flag(self):
        return self.override_flag

    def get_router_flag(self):
        return self.router_flag

    def get_router_lifetime(self):
        return self.router_lifetime

    def get_interface(self):
        return self.interface