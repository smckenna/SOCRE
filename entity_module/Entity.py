from uuid import uuid4
import numpy as np
from helpers.helper_functions import flatten_list

"""
self.type = 'critical_entity'
self.type = 'organization'
self.type = 'process'
self.type = 'organization'
self.type = 'application'
self.type = 'product'
self.type = 'function'
self.type = 'asset'
self.type = 'server'
self.type = 'critical_server'
self.type = 'laptop'
self.type = 'desktop'
self.type = 'mobile_device'
self.type = 'virtual_machine'
self.type = 'cloud_object'
self.type = 'cloud_database'
"""


class AllEntities(object):
    def __init__(self):
        self.dict = {}
        self.list = []
        self.uuid_list = []

    def add_to_all_entities(self, entity):
        self.dict[entity.uuid] = entity
        self.list.append(entity)
        self.uuid_list.append(entity.uuid)


class Entity(object):
    def __init__(self, label="default", type="asset", critical=False):
        self.uuid = uuid4()
        self.value = 0
        self.type = type
        self.label = label
        self.owner = None
        self.properties = dict()
        self.manifest = {}
        self.critical = critical
        self.machine_group = None
        self.network_group = None
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
        }, 'sp80053': {
            "AC": {
                "AC-1": 0.0952559621518162,
                "AC-2": 0.34234270463886973,
                "AC-3": 0.7086438556591361,
                "AC-4": 0.17991596930513565,
                "AC-5": 0.48947215182640813,
                "AC-6": 0.35700800128335797,
                "AC-7": 0.4329436882103801,
                "AC-8": 0.13826617917780915,
                "AC-10": 0.8200528797861281,
                "AC-11": 0.6013412901373216,
                "AC-12": 0.8863134817828183,
                "AC-14": 0.6745042970256023,
                "AC-17": 0.7360249958515401,
                "AC-18": 0.4017310700978457,
                "AC-19": 0.16734708086111338,
                "AC-20": 0.6531181241821233,
                "AC-21": 0.17817512086257836,
                "AC-22": 0.3571558077115574
            },
            "AT": {
                "AT-1": 0.44099410872963773,
                "AT-2": 0.5192005653510756,
                "AT-3": 0.27516265074384605,
                "AT-4": 0.7157178533520256
            },
            "AU": {
                "AU-1": 0.3813230810557463,
                "AU-2": 0.8855381174910827,
                "AU-3": 0.8232512881366821,
                "AU-4": 0.5281786650526944,
                "AU-5": 0.8940519219471865,
                "AU-6": 0.16364203534437383,
                "AU-7": 0.021784906601170162,
                "AU-8": 0.5879823831344938,
                "AU-9": 0.36979179789145245,
                "AU-10": 0.36105320626489856,
                "AU-11": 0.9181718495943952,
                "AU-12": 0.5356339029336895
            },
            "CA": {
                "CA-1": 0.24772662370827825,
                "CA-2": 0.3394412538482698,
                "CA-3": 0.8014057164321295,
                "CA-5": 0.42229464147220186,
                "CA-6": 0.525228525146073,
                "CA-7": 0.1351448810056502,
                "CA-8": 0.34919011221392005,
                "CA-9": 0.5017388486277778
            },
            "CM": {
                "CM-1": 0.6225057276122768,
                "CM-2": 0.2773363170347181,
                "CM-3": 0.7960652849740286,
                "CM-4": 0.3321632199861721,
                "CM-5": 0.4719052182009942,
                "CM-6": 0.3697056208869884,
                "CM-7": 0.8779558952128893,
                "CM-8": 0.7685119329536517,
                "CM-9": 0.02459856142098449,
                "CM-10": 0.8489322751311692,
                "CM-11": 0.9322899595196098,
                "CM-12": 0.20609253262932614
            },
            "CP": {
                "CP-1": 0.5714890896910725,
                "CP-2": 0.4283824470606367,
                "CP-3": 0.8033830626578657,
                "CP-4": 0.5511346352735148,
                "CP-6": 0.5786225485984152,
                "CP-7": 0.7112151119042094,
                "CP-8": 0.6127081546075148,
                "CP-9": 0.3328518584518111,
                "CP-10": 0.7385468686432455
            },
            "IA": {
                "IA-1": 0.8560570444697211,
                "IA-2": 0.5497632675403924,
                "IA-3": 0.4578816025423271,
                "IA-4": 0.9414486025817653,
                "IA-5": 0.34908724144275394,
                "IA-6": 0.883578234232823,
                "IA-7": 0.8302055417589421,
                "IA-8": 0.7012135983102245,
                "IA-11": 0.40134016515102877,
                "IA-12": 0.4285861534196811
            },
            "IR": {
                "IR-1": 0.05214526513627382,
                "IR-2": 0.14235010186607028,
                "IR-3": 0.9806466341213904,
                "IR-4": 0.28907390927642446,
                "IR-5": 0.6955651943115191,
                "IR-6": 0.8388730907973805,
                "IR-7": 0.4072701135550796,
                "IR-8": 0.7251452407483999
            },
            "MA": {
                "MA-1": 0.2645286205448205,
                "MA-2": 0.6085254286083471,
                "MA-3": 0.4006119487064678,
                "MA-4": 0.6748187238964158,
                "MA-5": 0.29593548750659315,
                "MA-6": 0.3061945698570423
            },
            "MP": {
                "MP-1": 0.7269537192965705,
                "MP-2": 0.5043980159522993,
                "MP-3": 0.8670443608315678,
                "MP-4": 0.09957448955164494,
                "MP-5": 0.5274214789528457,
                "MP-6": 0.6123545276056438,
                "MP-7": 0.7471775851471063
            },
            "PE": {
                "PE-1": 0.6095865939119806,
                "PE-2": 0.07777894995686851,
                "PE-3": 0.9943781802585022,
                "PE-4": 0.27739460171369834,
                "PE-5": 0.029419197704042777,
                "PE-6": 0.42555602055310765,
                "PE-8": 0.264552647168775,
                "PE-9": 0.06549061312610283,
                "PE-10": 0.9551567535892187,
                "PE-11": 0.7881129157145061,
                "PE-12": 0.7575891762185143,
                "PE-13": 0.6548782464051961,
                "PE-14": 0.33950631829228617,
                "PE-15": 0.11442377882276422,
                "PE-16": 0.05460543901065429,
                "PE-17": 0.5889478701881702,
                "PE-18": 0.7908372586135765
            },
            "PL": {
                "PL-1": 0.6502069617046727,
                "PL-2": 0.21612236473363766,
                "PL-4": 0.7741434051204913,
                "PL-8": 0.5151794907000481,
                "PL-10": 0.7925432193637534,
                "PL-11": 0.002729199170136365
            },
            "PS": {
                "PS-1": 0.14228929585257355,
                "PS-2": 0.5663184131710929,
                "PS-3": 0.07670992693567935,
                "PS-4": 0.1513915804826328,
                "PS-5": 0.4083664861057974,
                "PS-6": 0.7324600254723874,
                "PS-7": 0.21110072065566388,
                "PS-8": 0.07673683302976075,
                "PS-9": 0.38157432709097516
            },
            "RA": {
                "RA-1": 0.3157912353012109,
                "RA-2": 0.9401278457364661,
                "RA-3": 0.9638802938554957,
                "RA-5": 0.48034130456401947,
                "RA-7": 0.3569980875891533,
                "RA-9": 0.22258100166278494
            },
            "SA": {
                "SA-1": 0.5848047702197771,
                "SA-2": 0.386675349527578,
                "SA-3": 0.5322062859557084,
                "SA-4": 0.5935979400989637,
                "SA-5": 0.7695420854971986,
                "SA-8": 0.5567389608211951,
                "SA-9": 0.8091975545647399,
                "SA-10": 0.31841435277383945,
                "SA-11": 0.6610265639681939,
                "SA-15": 0.37410892871891765,
                "SA-16": 0.6235118655767475,
                "SA-17": 0.6111459405288441,
                "SA-21": 0.523387805814462,
                "SA-22": 0.4675728786620219
            },
            "SC": {
                "SC-1": 0.5364109278505202,
                "SC-2": 0.9862974233998864,
                "SC-3": 0.9269262370562876,
                "SC-4": 0.6222899396597871,
                "SC-5": 0.7276096341525277,
                "SC-7": 0.45964299644486656,
                "SC-8": 0.02064965017141085,
                "SC-10": 0.4496073117259769,
                "SC-12": 0.8059478162794681,
                "SC-13": 0.6826168831261326,
                "SC-15": 0.2859644113080648,
                "SC-17": 0.8739191143531442,
                "SC-18": 0.8712749721186255,
                "SC-20": 0.71806220565618,
                "SC-21": 0.5183107768398024,
                "SC-22": 0.6353694893697268,
                "SC-23": 0.15949395346489992,
                "SC-24": 0.9352161346439735,
                "SC-28": 0.34856333411136564,
                "SC-39": 0.08771574292787487
            },
            "SI": {
                "SI-1": 0.9746408972351303,
                "SI-2": 0.7395624805870479,
                "SI-3": 0.7086098065799245,
                "SI-4": 0.6322107100860794,
                "SI-5": 0.18539981767593317,
                "SI-6": 0.43496491504697843,
                "SI-7": 0.42065242125071567,
                "SI-8": 0.2263355845101982,
                "SI-10": 0.1985262589297081,
                "SI-11": 0.44642328463067216,
                "SI-12": 0.6059888434019679,
                "SI-16": 0.6649732006406863
            },
            "SR": {
                "SR-1": 0.6150228258291629,
                "SR-2": 0.009085213983742735,
                "SR-3": 0.6132188094197704,
                "SR-5": 0.629932979881432,
                "SR-6": 0.4670976562406335,
                "SR-8": 0.33675952178866453,
                "SR-9": 0.03797324519975076,
                "SR-10": 0.3562736475811489,
                "SR-11": 0.44917385196176873,
                "SR-12": 0.22932668185152727
            }
        }}

    def allocate_data_space(self, keys, size):
        for k in keys:
            self.manifest[k] = np.zeros((size,))

    def assign_owner(self, owner):
        self.owner = owner

    def assign_properties(self, prop, val):
        self.properties[prop] = val
        # ip
        # data?
        # os
        # cloud provider


class Data:

    def __init__(self, label="default", critical=False):
        self.uuid = uuid4()
        self.value = {}
        self.label = label
        self.properties = dict()
        self.owner = None

    def assign_owner(self, owner):
        self.owner = owner

    def assign_properties(self, prop, val):
        self.properties[prop] = val


class EntityGroup:

    def __init__(self, label="default", critical=False):
        self.list_of_entities = []
        self.uuid = uuid4()
        self.value = {}
        self.label = label
        self.owner = None
        self.properties = dict()
        self.critical = critical

    def add_entity(self, entity_list):
        self.list_of_entities = self.list_of_entities + entity_list
#        self.list_of_entities = flatten_list(self.list_of_entities)

    def assign_properties(self, prop, val):
        self.properties[prop] = val


class DataGroup:

    def __init__(self, label='default', critical=False):
        self.list_of_data = []
        self.uuid = uuid4()
        self.value = 0
        self.label = label
        self.properties = dict()
        self.critical = critical

    def add_data(self, data_list):
        self.list_of_data.append(data_list)
        self.list_of_data = flatten_list(self.list_of_data)


if __name__ == '__main__':
    acme = Entity(type='organization', label="ACME")
    all_entities = AllEntities()
    all_entities.add_to_all_entities(acme)

    app1 = Entity(type='application', label='Payroll')
    all_entities.add_to_all_entities(app1)

    svr1 = Entity(type='server', label="Mainframe")
    svr2 = Entity(type='server', label="Print server")
    laptop1 = Entity(type='laptop', label="Employee 1 machine")
    laptop2 = Entity(type='laptop', label="Employee 2 machine")
    laptop3 = Entity(type='laptop', label="Employee 3 machine")
    laptop4 = Entity(type='laptop', label="Employee 4 machine")
    all_entities.add_to_all_entities(svr1)
    all_entities.add_to_all_entities(svr2)
    all_entities.add_to_all_entities(laptop1)
    all_entities.add_to_all_entities(laptop2)
    all_entities.add_to_all_entities(laptop3)
    all_entities.add_to_all_entities(laptop4)

    div1 = Entity(type='division', label="Operations")
    div2 = Entity(type='division', label="Sales")
    all_entities.add_to_all_entities(div1)
    all_entities.add_to_all_entities(div2)

    all_laptops = EntityGroup(label="all laptops")
    all_laptops.add_entity([laptop1, laptop2, laptop3, laptop4])
    my_db = Entity(type='cloud_database')
    db_records = Data(label="Database Records")
