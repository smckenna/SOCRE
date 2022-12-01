from helpers.helper_functions import compute_metric


class MachineGroup(object):
    """
    Class that defines a machine group object
    """

    def __init__(self, label, network_group):
        self.label = label
        self.node = None
        self.assets = []
        self.network_group = network_group
        self.exploitability = 0.5
        self.attack_surface = 0.5
        self.vulnerability = compute_metric(exploitability=self.exploitability,
                                            attack_surface=self.attack_surface, method='geometric')


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
        self.exploitability = 0.5
        self.attack_surface = 0.5
        self.vulnerability = compute_metric(exploitability=self.exploitability,
                                            attack_surface=self.attack_surface, method='geometric')
