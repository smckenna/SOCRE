from uuid import uuid4

import numpy as np


class ThreatActor:

    def __init__(self, type="threatactor", label="Threat Actor"):
        self.uuid = uuid4()
        self.label = label
        self.properties = {'determination': 0,
                           "sophistication": 0,
                           "type": "",
                           "resources": 0,
                           "capability": 0,
                           "origin": "",
                           "targets": []}
        # below is the idea; should come from DB
        self.attempt_limit = 1
        self.impact_objective = ["c, i", "a"]
        self.attack_properties = {"malware": {'determination': 0,
                                              "sophistication": 0,
                                              "resources": 0,
                                              "capability": 0},
                                  "phishing": {'determination': 0,
                                               "sophistication": 0,
                                               "resources": 0,
                                               "capability": 0},
                                  "mitm": {'determination': 0,
                                           "sophistication": 0,
                                           "resources": 0,
                                           "capability": 0},
                                  "dos": {'determination': 0,
                                          "sophistication": 0,
                                          "resources": 0,
                                          "capability": 0},
                                  "sql injections": {'determination': 0,
                                                     "sophistication": 0,
                                                     "resources": 0,
                                                     "capability": 0},
                                  "zero-day exploit": {'determination': 0,
                                                       "sophistication": 0,
                                                       "resources": 0,
                                                       "capability": 0},
                                  "password attack": {'determination': 0,
                                                      "sophistication": 0,
                                                      "resources": 0,
                                                      "capability": 0},
                                  "cross-site scripting": {'determination': 0,
                                                           "sophistication": 0,
                                                           "resources": 0,
                                                           "capability": 0},
                                  "rootkits": {'determination': 0,
                                               "sophistication": 0,
                                               "resources": 0,
                                               "capability": 0},
                                  "iot": {'determination': 0,
                                          "sophistication": 0,
                                          "resources": 0,
                                          "capability": 0}
                                  }
        self.ttp_properties = {"T0000": {'determination': 0,
                                         "sophistication": 0,
                                         "resources": 0,
                                         "capability": 0}
                               }
        self.threat_action_properties = {"action": {'determination': 0,
                                                    "sophistication": 0,
                                                    "resources": 0,
                                                    "capability": 0}
                                         }

    def assign_property(self, prop, val):
        self.properties[prop.lower()] = val

    def set_attempt_limit(self):
        self.attempt_limit = max(1, int(self.properties['determination'] * 10))

    def set_capability(self, cyrce_input):
        if cyrce_input.scenario.attackAction == 'error':
            cyrce_input.threatActorInput.determinationWeight = 0
        self.properties['capability'] = np.sum((
            self.properties['determination'] * cyrce_input.threatActorInput.determinationWeight,
            self.properties['resources'] * cyrce_input.threatActorInput.resourcesWeight,
            self.properties['sophistication'] * cyrce_input.threatActorInput.sophisticationWeight)) / (
                                                cyrce_input.threatActorInput.determinationWeight +
                                                cyrce_input.threatActorInput.resourcesWeight +
                                                cyrce_input.threatActorInput.sophisticationWeight)


class UnwittingInsider:

    def __init__(self, label="employee"):
        self.uuid = uuid4()
        self.label = label
        self.properties = {"tenure": 0,
                           "role": 0,
                           "training": 0.,
                           "capacity": 0,
                           "origin": "",
                           "targets": []}

        self.impact_objective = ["c, i", "a"]

    def assign_property(self, prop, val):
        self.properties[prop.lower()] = val


if __name__ == '__main__':
    threat_actor = ThreatActor(type="threatactor", label="APT1")
