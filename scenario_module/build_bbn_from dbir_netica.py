import os

import pandas as pd
from pybbn.graph.dag import Bbn
from pybbn.graph.edge import Edge, EdgeType
from pybbn.graph.jointree import EvidenceBuilder
from pybbn.graph.node import BbnNode
from pybbn.graph.variable import Variable
from pybbn.pptc.inferencecontroller import InferenceController

from helpers.helper_functions import flatten_list

aprioriProbability = 0.5

lossData = pd.read_csv(os.path.join(os.path.dirname(__file__), './loss.csv'), header=None)
regionData = pd.read_csv(os.path.join(os.path.dirname(__file__), './region.csv'), header=None)
actionIndustryData = pd.read_csv(os.path.join(os.path.dirname(__file__), './action_industry.csv'), header=None)
regionActionData = pd.read_csv(os.path.join(os.path.dirname(__file__), './region_action.csv'), header=None)
actionActorData = pd.read_csv(os.path.join(os.path.dirname(__file__), './action_actor.csv'), header=None)
industrySizeData = pd.read_csv(os.path.join(os.path.dirname(__file__), './industry_size.csv'), header=None)

incident = BbnNode(Variable(0, 'incident', ['T', 'F']), [aprioriProbability, 1 - aprioriProbability])

action = BbnNode(Variable(1, 'action', ['error', 'hacking', 'malware', 'misuse', 'social']), flatten_list(regionActionData.to_numpy().tolist()))
impactType = BbnNode(Variable(3, 'impactType', ['c', 'i', 'a']), flatten_list(lossData.to_numpy().tolist()))
threatType = BbnNode(Variable(2, 'threatType', ['threatactor', 'insider', 'thirdParty']), flatten_list(actionActorData.to_numpy().tolist()))
geography = BbnNode(Variable(4, 'geography', ['apac', 'emea', 'lac', 'na']), flatten_list(regionData.to_numpy().tolist()))
size = BbnNode(Variable(6, 'size', ['small', 'large']), flatten_list(industrySizeData.to_numpy().tolist()))
industry = BbnNode(Variable(5, 'industry', ['accommodation', 'administrative', 'construction',
                                            'education', 'entertainment',
                                            'finance', 'healthcare',
                                            'information', 'manufacturing',
                                            'mining', 'other services',
                                            'professional', 'public administration',
                                            'real estate', 'retail',
                                            'transportation']), flatten_list(actionIndustryData.to_numpy().tolist()))

bbn = Bbn() \
    .add_node(industry) \
    .add_node(geography) \
    .add_node(threatType) \
    .add_node(impactType) \
    .add_node(action) \
    .add_node(size) \
    .add_node(incident) \
    .add_edge(Edge(incident, action, EdgeType.DIRECTED)) \
    .add_edge(Edge(incident, threatType, EdgeType.DIRECTED)) \
    .add_edge(Edge(incident, impactType, EdgeType.DIRECTED)) \
    .add_edge(Edge(incident, geography, EdgeType.DIRECTED)) \
    .add_edge(Edge(incident, size, EdgeType.DIRECTED)) \
    .add_edge(Edge(incident, industry, EdgeType.DIRECTED))  \
    .add_edge(Edge(action, industry, EdgeType.DIRECTED)) \
    .add_edge(Edge(geography, action, EdgeType.DIRECTED)) \
    .add_edge(Edge(action, threatType, EdgeType.DIRECTED)) \
    .add_edge(Edge(industry, size, EdgeType.DIRECTED))

# convert the BBN to a join tree
join_tree = InferenceController.apply(bbn)

attackGeography = 'na'
attackIndustry = 'finance'
attackThreatType = 'threatactor'
attackLossType = 'c'
attackAction = 'hacking'
orgSize = 'small'
verbose = True

# insert evidence
# if (attackGeography is not None) and (attackGeography != "global"):
#     ev1 = EvidenceBuilder() \
#         .with_node(join_tree.get_bbn_node_by_name('geography')) \
#         .with_evidence(attackGeography, 1.0) \
#         .build()
#     join_tree.set_observation(ev1)
#
# if attackIndustry is not None:
#     ev2 = EvidenceBuilder() \
#         .with_node(join_tree.get_bbn_node_by_name('industry')) \
#         .with_evidence(attackIndustry, 1.0) \
#         .build()
#     join_tree.set_observation(ev2)
#
# if attackThreatType is not None:
#     ev3 = EvidenceBuilder() \
#         .with_node(join_tree.get_bbn_node_by_name('threatType')) \
#         .with_evidence(attackThreatType, 1.0) \
#         .build()
#     join_tree.set_observation(ev3)
#
# if attackLossType is not None:
#     ev4 = EvidenceBuilder() \
#         .with_node(join_tree.get_bbn_node_by_name('impactType')) \
#         .with_evidence(attackLossType, 1.0) \
#         .build()
#     join_tree.set_observation(ev4)
#
# if attackAction is not None:
#     ev5 = EvidenceBuilder() \
#         .with_node(join_tree.get_bbn_node_by_name('action')) \
#         .with_evidence(attackAction, 1.0) \
#         .build()
#     join_tree.set_observation(ev5)
#
# if orgSize is not None:
#     ev6 = EvidenceBuilder() \
#         .with_node(join_tree.get_bbn_node_by_name('size')) \
#         .with_evidence(orgSize, 1.0) \
#         .build()
#     join_tree.set_observation(ev6)
ev7 = EvidenceBuilder() \
    .with_node(join_tree.get_bbn_node_by_name('incident')) \
    .with_evidence('T', 1.0) \
    .build()
join_tree.set_observation(ev7)

# print all the marginal probabilities
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

    #posteriorProbability = potentialOut * (aprioriProbability - bbn_incident_prob) + bbn_incident_prob
    #posteriorProbability = potentialOut/bbn_incident_prob * aprioriProbability

#print(round(posteriorProbability * 100, 2))
print(round(potentialOut * 100, 2))
bbn.to_json(bbn, 'C:\\Users\\570835\\PycharmProjects\\CyberRiskComputationalEngine\\scenario_module\\scenario_bbn_dbir.json')

if False:
    n, d = bbn.to_nx_graph()
    nx.draw_circular(n, font_size=14, font_weight='bold', arrowsize=20, node_size=500, with_labels=True, labels=d,
                     node_color='b', alpha=0.5)
    plt.show()
