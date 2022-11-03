import logging
import random

import numpy as np
from netaddr import *

from environment_module.groups import NetworkGroup, MachineGroup
from helpers.helper_functions import parse_ip_ranges


class Network(object):
    """
    Class that defines a network object
    """

    def __init__(self, graph):
        """
        :param graph: network graph
        """
        self.graph = graph
        self.list_of_network_groups = []
        self.__set_up_network_groups()

    def from_node_to_node(self, from_node, objective_list, network_model, failed_node_list, random_seed):

        np.random.seed(random_seed)
        objective = [_.network_group for _ in objective_list]

        # Find all paths from the from_node to each to_node
        all_paths = []
        for obj in objective:
            all_paths.extend(self.find_all_paths(from_node, obj))

        all_paths = [ap for ap in all_paths if len(ap) > 0]
        # if attack_type != 'SocialEng':
        #    for ap in all_paths:
        #        if 'endpoint' in ap:
        #            ap.remove('endpoint')

        if len(all_paths) == 0:
            return None

        # Original scheme was to choose "best" next hop, based on "ROI"
        to_mg = None
        ct = 0
        while ct < 3:  # TODO what should this be?
            p = random.choice(all_paths)
            path = [n for n in p if n != 'hub']
            if len(path) == 1:
                ng = path[0]
            else:
                ng = path[1]
            if ng != from_node:
                end_ng = [i for i in network_model.list_of_network_groups if i.label == ng][0]
                if len(end_ng.machine_groups) > 0:
                    end_ng_mgs = end_ng.machine_groups
                else:
                    ct += 1
                    continue
                choose_from = list(set(end_ng_mgs) - set(failed_node_list))
                if len(choose_from) > 0:
                    to_mg = np.random.choice(choose_from)
                    break
                else:
                    if len(end_ng.assets) > 0:
                        ct += 1
                    continue
            else:
                ct += 1

        return to_mg

    def find_all_paths(self, start, end):
        path = []
        paths = []
        queue = [(start, end, path)]
        while queue:
            start, end, path = queue.pop()

            path = path + [start]
            if start == end:
                paths.append(path)
            for node in set(self.graph[start]).difference(path):
                queue.append((node, end, path))

        return paths

    def __set_up_network_groups(self):

        logger = logging.getLogger('Main')
        logger.setLevel(level=logging.DEBUG)

        logger.info("      " + str(len(self.graph.nodes)) + " network nodes with " + str(len(self.graph.edges)) +
                    " edges loaded")

        logger.info("      Setting up IP addresses for model ...")
        for n in self.graph.nodes:
            network_group = NetworkGroup(n)
            network_group.assets = []
            network_group.node = self.graph.nodes[n]

            ip_groups = parse_ip_ranges(network_group.node['ip_range'])
            ip_address_list = []
            for ip_grp in ip_groups:
                grp_rng = IPNetwork(ip_grp)
                ip_address_list.append(grp_rng)

            network_group.ip_address_set = IPSet(ip_address_list)

            self.list_of_network_groups.append(network_group)

        # nx.write_graphml(self.graph, "../model_resources/network_model.graphml")

    def assign_assets_to_network_groups(self, asset_list):

        logger = logging.getLogger('Main')
        logger.setLevel(level=logging.DEBUG)

        located = 0
        all_ips = []
        group_ip_set_list = []
        orphans = []

        orphan_group_exists = False

        for asset in asset_list:

            asset.network_group = ""

            entry = asset.properties['ip_address']
            asset_ip_addresses = parse_ip_ranges(entry)

            for ng in self.list_of_network_groups:

                if asset_ip_addresses is not None:
                    for asset_last_ip in asset_ip_addresses:
                        if IPNetwork(asset_last_ip) in ng.ip_address_set and asset.network_group == '':
                            ng.assets.append(asset)
                            asset.network_group = ng.label
                            group_ip_set_list.append(ng.ip_address_set)
                            all_ips.append(asset_ip_addresses)
                            located += 1
                            continue

                if ng.label == 'orphans':
                    orphan_group_exists = True
                    orphanGroup = ng
                    continue

        logger.info("         " + str(located) + " of " + str(len(asset_list)) + " assets placed into network model")
        logger.info("         " + str(len(orphans)) + " orphan assets identified")

        if len(orphans) > 0:
            if orphan_group_exists == False:
                orphanGroup = NetworkGroup('orphans')
                orphanGroup.machine_groups = []
                orphanGroup.assets = orphans
                self.list_of_network_groups.append(orphanGroup)
            else:
                orphanGroup.assets = orphanGroup.assets + orphans

    def assign_assets_to_machine_groups(self):

        logger = logging.getLogger('Main')
        logger.setLevel(level=logging.DEBUG)

        for ng in self.list_of_network_groups:

            if ng.label == 'orphans':
                orphanGroup = ng
                continue

            if len(ng.assets) > 0:
                unique_os = list(set([a.properties['os'] for a in ng.assets]))
                if len(unique_os) == 0:
                    continue
            else:
                continue

            group_count = 0
            logger.info("      Assigning assets to machine groups within " + ng.label)
            asset_count = 0
            for os in unique_os:
                mg_assets = list(set([a for a in ng.assets if a.properties['os'] == os]))

                asset_count += len(mg_assets)
                if len(mg_assets) > 0:
                    mg = MachineGroup(label=os, network_group=ng)
                    for mg_asset in mg_assets:
                        mg_asset.machine_group = mg.label
                    mg.assets = mg_assets
                    mg.network_group = ng.label
                    mg.node = ng.node
                    ng.machine_groups.append(mg)

                    group_count += 1
            logger.info("         " + str(group_count) + " machine groups with a total of " + str(asset_count) + " assets")

        # Handle orphans
        try:
            orphans = orphanGroup.assets
        except:
            logging.info("      " + "No orphan assets found :)")
            return

