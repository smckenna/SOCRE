from pybbn.graph.dag import Bbn
from pybbn.graph.jointree import EvidenceBuilder
from pybbn.pptc.inferencecontroller import InferenceController
import os
from uuid import uuid4


class Scenario:

    def __init__(self, bbn_file, attackGeography=None, attackAction=None, attackThreatType=None,
                 attackLossType=None, orgSize=None, attackIndustry=None, attackTarget=None,
                 aprioriProbability=0.5):
        self.uuid =uuid4()
        self.bbn_file = bbn_file
        self.bbn_incident_prob = 0.5  # for T
        self.aprioriProbability = aprioriProbability
        self.posteriorProbability = aprioriProbability
        self.attackGeography = attackGeography
        self.attackAction = attackAction
        self.attackLossType = attackLossType
        self.attackIndustry = attackIndustry
        self.orgSize = orgSize
        self.attackThreatType = attackThreatType
        self.attackTarget = attackTarget

    def determine_scenario_probability(self, verbose=False):
        """
        Function that returns probability of attack using DBIR data in a BBN
        :param verbose: Boolean to print result to terminal
        """

        bbn = Bbn.from_json(self.bbn_file)

        # convert the BBN to a join tree
        join_tree = InferenceController.apply(bbn)

        # insert evidence
        if (self.attackGeography is not None) and (self.attackGeography != "global"):
            ev1 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('region')) \
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
                .with_node(join_tree.get_bbn_node_by_name('actor')) \
                .with_evidence(self.attackThreatType, 1.0) \
                .build()
            join_tree.set_observation(ev3)

        if self.attackLossType is not None:
            ev4 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('attribute')) \
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
                .with_node(join_tree.get_bbn_node_by_name('orgSize')) \
                .with_evidence(self.orgSize, 1.0) \
                .build()
            join_tree.set_observation(ev6)

        # ev7 = EvidenceBuilder() \
        #     .with_node(join_tree.get_bbn_node_by_name('incident')) \
        #     .with_evidence('T', 1.0) \
        #     .build()
        # join_tree.set_observation(ev7)

        # print all the marginal probabilities
        potentialOut = 0
        for node in join_tree.get_bbn_nodes():
            potential = join_tree.get_bbn_potential(node)
            if verbose:
                print(potential)
            if node.variable.name == 'incident':
                if potential.entries[0].entries.values() == 'T':
                    potentialOut = potential.entries[0].value
                else:
                    potentialOut = potential.entries[1].value

        self.posteriorProbability = max([0.001, potentialOut]) * \
                                    (self.aprioriProbability - self.bbn_incident_prob) + self.bbn_incident_prob


if __name__ == '__main__':
    bbn_file = os.path.join(os.path.dirname(__file__), './scenario_bbn.json')

    # scenario = Scenario(bbn_file, attackLossType='c', orgSize='small', attackAction='hacking', attackGeography='apac',
    #                    attackThreatType='external', aprioriProbability=0.5)
    # scenario = Scenario(bbn_file, attackAction='hacking', attackGeography='na', attackIndustry='professional', aprioriProbability=0.5)
    scenario = Scenario(bbn_file, attackLossType='a', orgSize='small', attackAction='social', attackGeography='na',
                        attackIndustry='professional', aprioriProbability=0.5)
    scenario = Scenario(bbn_file, attackThreatType='internal', attackAction='misuse', aprioriProbability=0.5)
    scenario = Scenario(bbn_file, attackIndustry='retail', orgSize='small', attackThreatType='external',
                        attackAction='malware',
                        attackLossType='c', aprioriProbability=0.05)
    #scenario = Scenario(bbn_file, aprioriProbability=0)
    scenario.determine_scenario_probability(verbose=True)

    print(round(100. * scenario.posteriorProbability, 1))
    print(round((1 - scenario.posteriorProbability) * 100., 1))
