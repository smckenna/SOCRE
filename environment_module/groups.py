class MachineGroup(object):
    """
    Class that defines a machine group object
    """

    def __init__(self, label, network_group):
        self.label = label
        #self.type = type
        self.node = None
        self.assets = []
        self.network_group = network_group


class NetworkGroup(object):
    """
    Class that defines a network group object
    """

    def __init__(self, label):
        self.label = label
        self.node = None
        self.assets = []
        self.ip_address_set = None
        self.machine_groups = []


