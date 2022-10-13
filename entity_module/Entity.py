from uuid import uuid4
import numpy as np

class AllEntities:
    def __init__(self):
        self.dict = {}
        self.list = []
        self.uuid_list = []

    def add_to_all_entities(self, entity):
        self.dict[entity.uuid] = entity
        self.list.append(entity)
        self.uuid_list.append(entity.uuid)


class Entity(object):

    def __init__(self, label="", owner=None):
        self.uuid = uuid4()
        self.value = 0
        self.label = label
        self.network_label = label.lower().replace(' ', '_')
        self.owner = owner
        self.properties = dict()
        self.data = {}
        self.manifest = {}
        self.controls = {'csf': {
            "identify": {
                "value": 0.5,
                "categories": {
                    "assetManagement": {
                        "value": 0.5,
                        "subcategories": {
                            "ID.AM-1": 0.5,
                            "ID.AM-2": 0.5,
                            "ID.AM-3": 0.5,
                            "ID.AM-4": 0.5,
                            "ID.AM-5": 0.5,
                            "ID.AM-6": 0.5
                        }
                    },
                    "businessEnvironment": {
                        "value": 0.5,
                        "subcategories": {
                            "ID.BE-1": 0.5,
                            "ID.BE-2": 0.5,
                            "ID.BE-3": 0.5,
                            "ID.BE-4": 0.5,
                            "ID.BE-5": 0.5
                        }
                    },
                    "governance": {
                        "value": 0.5,
                        "subcategories": {
                            "ID.GV-1": 0.5,
                            "ID.GV-2": 0.5,
                            "ID.GV-3": 0.5,
                            "ID.GV-4": 0.5
                        }
                    },
                    "riskAssessment": {
                        "value": 0.5,
                        "subcategories": {
                            "ID.RA-1": 0.5,
                            "ID.RA-2": 0.5,
                            "ID.RA-3": 0.5,
                            "ID.RA-4": 0.5,
                            "ID.RA-5": 0.5,
                            "ID.RA-6": 0.5
                        }
                    },
                    "riskManagementStrategy": {
                        "value": 0.5,
                        "subcategories": {
                            "ID.RM-1": 0.5,
                            "ID.RM-2": 0.5,
                            "ID.RM-3": 0.5
                        }
                    },
                    "supplyChainRiskManagement": {
                        "value": 0.5,
                        "subcategories": {
                            "ID.SC-1": 0.5,
                            "ID.SC-2": 0.5,
                            "ID.SC-3": 0.5,
                            "ID.SC-4": 0.5,
                            "ID.SC-5": 0.5
                        }
                    }
                }
            },
            "protect": {
                "value": 0.5,
                "categories": {
                    "identityManagementAuthenticationAndAccessControl": {
                        "value": 0.5,
                        "subcategories": {
                            "PR.AC-1": 0.5,
                            "PR.AC-2": 0.5,
                            "PR.AC-3": 0.5,
                            "PR.AC-4": 0.5,
                            "PR.AC-5": 0.5,
                            "PR.AC-6": 0.5,
                            "PR.AC-7": 0.5
                        }
                    },
                    "awarenessAndTraining": {
                        "value": 0.5,
                        "subcategories": {
                            "PR.AT-1": 0.5,
                            "PR.AT-2": 0.5,
                            "PR.AT-3": 0.5,
                            "PR.AT-4": 0.5,
                            "PR.AT-5": 0.5
                        }
                    },
                    "dataSecurity": {
                        "value": 0.5,
                        "subcategories": {
                            "PR.DS-1": 0.5,
                            "PR.DS-2": 0.5,
                            "PR.DS-3": 0.5,
                            "PR.DS-4": 0.5,
                            "PR.DS-5": 0.5,
                            "PR.DS-6": 0.5,
                            "PR.DS-7": 0.5,
                            "PR.DS-8": 0.5
                        }
                    },
                    "informationProtectionProcessesAndProcedures": {
                        "value": 0.5,
                        "subcategories": {
                            "PR.IP-1": 0.5,
                            "PR.IP-2": 0.5,
                            "PR.IP-3": 0.5,
                            "PR.IP-4": 0.5,
                            "PR.IP-5": 0.5,
                            "PR.IP-6": 0.5,
                            "PR.IP-7": 0.5,
                            "PR.IP-8": 0.5,
                            "PR.IP-9": 0.5,
                            "PR.IP-10": 0.5,
                            "PR.IP-11": 0.5,
                            "PR.IP-12": 0.5
                        }
                    },
                    "maintenance": {
                        "value": 0.5,
                        "subcategories": {
                            "PR.MA-1": 0.5,
                            "PR.MA-2": 0.5
                        }
                    },
                    "protectiveTechnology": {
                        "value": 0.5,
                        "subcategories": {
                            "PR.PT-1": 0.5,
                            "PR.PT-2": 0.5,
                            "PR.PT-3": 0.5,
                            "PR.PT-4": 0.5,
                            "PR.PT-5": 0.5
                        }
                    }
                }
            },
            "detect": {
                "value": 0.5,
                "categories": {
                    "anomaliesAndEvents": {
                        "value": 0.5,
                        "subcategories": {
                            "DE.AE-1": 0.5,
                            "DE.AE-2": 0.5,
                            "DE.AE-3": 0.5,
                            "DE.AE-4": 0.5,
                            "DE.AE-5": 0.5
                        }
                    },
                    "securityContinuousMonitoring": {
                        "value": 0.5,
                        "subcategories": {
                            "DE.CM-1": 0.5,
                            "DE.CM-2": 0.5,
                            "DE.CM-3": 0.5,
                            "DE.CM-4": 0.5,
                            "DE.CM-5": 0.5,
                            "DE.CM-6": 0.5,
                            "DE.CM-7": 0.5,
                            "DE.CM-8": 0.5
                        }
                    },
                    "detectionProcesses": {
                        "value": 0.5,
                        "subcategories": {
                            "DE.DP-1": 0.5,
                            "DE.DP-2": 0.5,
                            "DE.DP-3": 0.5,
                            "DE.DP-4": 0.5,
                            "DE.DP-5": 0.5
                        }
                    }
                }
            },
            "respond": {
                "value": 0.5,
                "categories": {
                    "responsePlanning": {
                        "value": 0.5,
                        "subcategories": {
                            "RS.RP-1": 0.5
                        }
                    },
                    "communications": {
                        "value": 0.5,
                        "subcategories": {
                            "RS.CO-1": 0.5,
                            "RS.CO-2": 0.5,
                            "RS.CO-3": 0.5,
                            "RS.CO-4": 0.5,
                            "RS.CO-5": 0.5
                        }
                    },
                    "analysis": {
                        "value": 0.5,
                        "subcategories": {
                            "RS.AN-1": 0.5,
                            "RS.AN-2": 0.5,
                            "RS.AN-3": 0.5,
                            "RS.AN-4": 0.5,
                            "RS.AN-5": 0.5
                        }
                    },
                    "mitigation": {
                        "value": 0.5,
                        "subcategories": {
                            "RS.MI-1": 0.5,
                            "RS.MI-2": 0.5,
                            "RS.MI-3": 0.5
                        }
                    },
                    "improvements": {
                        "value": 0.5,
                        "subcategories": {
                            "RS.IM-1": 0.5,
                            "RS.IM-2": 0.5
                        }
                    }
                }
            },
            "recover": {
                "value": 0.5,
                "categories": {
                    "recoveryPlanning": {
                        "value": 0.5,
                        "subcategories": {
                            "RC.RP-1": 0.5
                        }
                    },
                    "improvements": {
                        "value": 0.5,
                        "subcategories": {
                            "RC.IM-1": 0.5,
                            "RC.IM-2": 0.5
                        }
                    },
                    "communications": {
                        "value": 0.5,
                        "subcategories": {
                            "RC.CO-1": 0.5,
                            "RC.CO-2": 0.5,
                            "RC.CO-3": 0.5
                        }
                    }
                }
            }
        }, '80053': {}}

    #def allocate_data_space(self, size):
    #    self.impactI = np.zeros((size,))
    #    self.impactR = np.zeros((size,))
    #    self.accessI = np.zeros((size,))
    #    self.accessR = np.zeros((size,))

    def allocate_data_space(self, keys, size):
        for k in keys:
            self.manifest[k] = np.zeros((size,))


class CriticalEntity(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Organization(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Process(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Division(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Application(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Product(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Function(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Asset(Entity):

    def __init__(self, label="", owner=None, ip_address='0.0.0.0', operating_system='linux'):
        super().__init__(label=label, owner=owner)
        self.ip_address = ip_address
        self.os = operating_system


class Server(Asset):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Laptop(Asset):

    def __init__(self, label="", owner=None, operating_system="windows"):
        super().__init__(label=label, owner=owner)
        self.os = operating_system


class Desktop(Asset):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class MobileDevice(Asset):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class VirtualMachine(Asset):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class CloudObject(Entity):

    def __init__(self, label="", owner=None, provider='aws'):
        super().__init__(label=label, owner=owner)
        self.provider = provider


class CloudDataBase(CloudObject):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Data:

    def __init__(self, label="", owner=None):
        self.uuid = uuid4()
        self.value = {}
        self.label = label
        self.owner = owner
        self.properties = dict()
        self.data = {}


class EntityGroup:

    def __init__(self, list_of_entities, label, owner):
        self.list_of_entities = list_of_entities
        self.uuid = uuid4()
        self.value = {}
        self.label = label
        self.owner = owner
        self.properties = dict()
        self.data = {}


class DataGroup:

    def __init__(self, list_of_data, label, owner):
        self.list_of_data = list_of_data
        self.uuid = uuid4()
        self.value = 0
        self.label = label
        self.owner = owner
        self.properties = dict()
        self.data = {}


if __name__ == '__main__':
    acme = Organization(label="ACME", owner=None)
    all_entities = AllEntities()
    all_entities.add_to_all_entities(acme)

    app1 = Application(owner="Jane", label="Payroll")
    all_entities.add_to_all_entities(app1)

    svr1 = Server(owner="Jane", label="Mainframe")
    svr2 = Server(owner="Steve", label="Print server")
    laptop1 = Laptop(owner="Hank", label="Employee machine", operating_system="linux")
    laptop2 = Laptop(owner="Sue", label="Employee machine")
    laptop3 = Laptop(owner="Bill", label="Employee machine")
    laptop4 = Laptop(owner="Mary", label="Employee machine")
    all_entities.add_to_all_entities(svr1)
    all_entities.add_to_all_entities(svr2)
    all_entities.add_to_all_entities(laptop1)
    all_entities.add_to_all_entities(laptop2)
    all_entities.add_to_all_entities(laptop3)
    all_entities.add_to_all_entities(laptop4)

    div1 = Division(label="Operations", owner="SVP1")
    div2 = Division(label="Sales", owner="SVP2")
    all_entities.add_to_all_entities(div1)
    all_entities.add_to_all_entities(div2)

    all_laptops = EntityGroup(list_of_entities=[laptop1, laptop2, laptop3, laptop4],
                              label="all laptops", owner=None)
    my_db = CloudDataBase("cloud db", "me")
    db_records = Data(label="Database Records", owner="Sue")
