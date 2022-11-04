import os
from uuid import uuid4

import numpy as np
from pybbn.graph.dag import Bbn
from pybbn.graph.jointree import EvidenceBuilder
from pybbn.pptc.inferencecontroller import InferenceController


class Scenario:

    def __init__(self, attackGeography=None, attackAction=None, attackThreatType=None,
                 attackLossType=None, orgSize=None, attackIndustry=None, attackTarget=None,
                 label="Scenario"):
        self.label = label
        self.uuid = uuid4()
        self.bbn_file = None
        self.probability_scale_factor = 0.5
        self.attackGeography = attackGeography
        self.attackAction = attackAction
        if attackLossType is None:
            self.attackLossType = np.random.choice(['c', 'i', 'a'])  # pick a loss type randomly
        else:
            self.attackLossType = attackLossType
        self.attackIndustry = attackIndustry
        self.orgSize = orgSize
        self.attackThreatType = attackThreatType
        self.attackTarget = attackTarget
        self.veris_threat_actions = []
        self.ttps = []

    def determine_scenario_probability_scale_factor(self, bbn_file, verbose=False):
        """
        Function that returns a scale factor for the relative probability of  attack using DBIR data in a BBN
        :param bbn_file: bbn strucutre file
        :param verbose: Boolean to print result to terminal
        """

        self.bbn_file = bbn_file
        bbn = Bbn.from_json(bbn_file)

        # convert the BBN to a join tree
        join_tree = InferenceController.apply(bbn)

        # insert evidence
        if (self.attackGeography is not None) and (self.attackGeography != "global"):
            ev1 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('geography')) \
                .with_evidence(self.attackGeography, 1.0) \
                .build()
            join_tree.set_observation(ev1)

        if self.attackIndustry is not None:
            ev2 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('industry')) \
                .with_evidence(self.attackIndustry, 1.0) \
                .build()
            join_tree.set_observation(ev2)

        if self.attackThreatType is not None:
            ev3 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('threatType')) \
                .with_evidence(self.attackThreatType, 1.0) \
                .build()
            join_tree.set_observation(ev3)

        if self.attackLossType is not None:
            ev4 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('impactType')) \
                .with_evidence(self.attackLossType, 1.0) \
                .build()
            join_tree.set_observation(ev4)

        if self.attackAction is not None:
            ev5 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('action')) \
                .with_evidence(self.attackAction, 1.0) \
                .build()
            join_tree.set_observation(ev5)

        if (self.orgSize is not None) and (self.orgSize != "unknown"):
            ev6 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('size')) \
                .with_evidence(self.orgSize, 1.0) \
                .build()
            join_tree.set_observation(ev6)

        # Only used for development
        # ev7 = EvidenceBuilder() \
        #     .with_node(join_tree.get_bbn_node_by_name('incident')) \
        #     .with_evidence('T', 1.0) \
        #     .build()
        # join_tree.set_observation(ev7)

        # print all the marginal probabilities
        if verbose:
            for node, posteriors in join_tree.get_posteriors().items():
                p = ', '.join([f'{val}={prob:.5f}' for val, prob in posteriors.items()])
                print(f'{node} : {p}')

        potentialOut = 0
        for node in join_tree.get_bbn_nodes():
            potential = join_tree.get_bbn_potential(node)
            if verbose:
                print(potential)
            if node.variable.name == 'incident':
                if 'T' in potential.entries[0].entries.values():
                    potentialOut = potential.entries[0].value
                else:
                    potentialOut = potential.entries[1].value

        if verbose:
            print("potentialOut = " + str(round(potentialOut, 2)))
        self.probability_scale_factor = potentialOut


if __name__ == '__main__':
    bbn_file = os.path.join(os.path.dirname(__file__), './scenario_bbn_dbir.json')

    # scenario = Scenario(attackLossType='c', orgSize='small', attackAction='hacking', attackGeography='apac',
    #                    attackThreatType='external', aprioriProbability=0.5)
    # scenario = Scenario(attackAction='hacking', attackGeography='na', attackIndustry='professional', aprioriProbability=0.5)
    scenario = Scenario(attackLossType='a', orgSize='small', attackAction='social', attackGeography='na',
                        attackIndustry='professional')
    scenario = Scenario(attackThreatType='internal', attackAction='misuse')
    scenario = Scenario(attackIndustry='information', orgSize='large', attackThreatType='threatactor',
                        attackAction='malware', attackGeography='na',
                        attackLossType='c')
    scenario = Scenario(attackIndustry='finance', orgSize='large',
                        attackGeography='na')
    scenario = Scenario()
    scenario.determine_scenario_probability_scale_factor(bbn_file=bbn_file, verbose=True)

    print(round(scenario.probability_scale_factor, 2))
