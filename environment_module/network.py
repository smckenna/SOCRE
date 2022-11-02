import random


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

    def from_node_to_node(self, from_node, objective_list, network_model, failed_node_list):

        objective = [_.network_group.label for _ in objective_list]
        #objective_node_labels = [item.label for obj_node in objective_list for item in
        #                         network_model.list_of_network_groups if item.label.__contains__(obj_node)]

        # Find all paths from the from_node to each to_node
        all_paths = []
        for obj in objective:
            all_paths.extend(self.find_all_paths(from_node, obj))

        all_paths = [ap for ap in all_paths if len(ap) > 0]
        #if attack_type != 'SocialEng':
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
                    to_mg = random.choice(choose_from)
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
