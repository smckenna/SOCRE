from uuid import uuid4


class ThreatActor:

    def __init__(self, label="Threat Actor"):
        self.uuid = uuid4()
        self.label = label
        self.properties = {'motivation': 0,
                           "sophistication": 0,
                           "type": "",
                           "resources": 0,
                           "capacity": 0,
                           "origin": "",
                           "targets": []}
        # below is the idea; should come from DB
        self.attempt_limit = 1
        self.impact_objective = ["c, i", "a"]
        self.attack_properties = {"Malware": {'Motivation': 0,
                                              "Sophistication": 0,
                                              "Capacity": 0},
                                  "Phishing": {'Motivation': 0,
                                               "Sophistication": 0,
                                               "Capacity": 0},
                                  "MitM": {'Motivation': 0,
                                           "Sophistication": 0,
                                           "Capacity": 0},
                                  "DoS": {'Motivation': 0,
                                          "Sophistication": 0,
                                          "Capacity": 0},
                                  "SQL Injections": {'Motivation': 0,
                                                     "Sophistication": 0,
                                                     "Capacity": 0},
                                  "Zero-day Exploit": {'Motivation': 0,
                                                       "Sophistication": 0,
                                                       "Capacity": 0},
                                  "Password Attack": {'Motivation': 0,
                                                      "Sophistication": 0,
                                                      "Capacity": 0},
                                  "Cross-site Scripting": {'Motivation': 0,
                                                           "Sophistication": 0,
                                                           "Capacity": 0},
                                  "Rootkits": {'Motivation': 0,
                                               "Sophistication": 0,
                                               "Capacity": 0},
                                  "IoT": {'Motivation': 0,
                                          "Sophistication": 0,
                                          "Capacity": 0}
                                  }
        self.ttp_properties = {"T0000": {'Motivation': 0,
                                         "Sophistication": 0,
                                         "Capacity": 0}
                               }
        self.threat_action_properties = {"Action": {'Motivation': 0,
                                                    "Sophistication": 0,
                                                    "Capacity": 0}
                                         }

    def assign_property(self, prop, val):
        self.properties[prop.lower()] = val


if __name__ == '__main__':
    threat_actor = ThreatActor(label="APT1")
