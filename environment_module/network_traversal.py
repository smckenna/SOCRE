import random


# hacked, dumbed-down version for single node model

def from_node_to_node(graph, from_node, objective, attack_type, all_assets_list, failed_node_list):
    attack_graph = graph

    # Handle entry cases where objective_node might be a list and it contains generic labels (like, 'dmz'),
    # so we need to find all the target nodes that match those generic labels
    objective_labels = [_.network_label for _ in objective]

    if isinstance(objective_labels, list):
        all_paths = []
        for ix in range(len(objective_labels)):
            all_paths.extend(find_all_paths(attack_graph, from_node, objective_labels[ix]))
    # else:
    #    all_paths = find_all_paths(attack_graph, from_node, objective)

    # Find all paths from the from_node to each to_node
    # all_paths = find_all_paths(attack_graph, from_node, objective)

    all_paths = [ap for ap in all_paths if len(ap) > 0]
    if attack_type != "social_eng":
        for ap in all_paths:
            if "laptop1" in ap:
                ap.remove('laptop1')
            if "laptop2" in ap:
                ap.remove('laptop2')
            if "laptop3" in ap:
                ap.remove('laptop3')
            if "laptop4" in ap:
                ap.remove('laptop4')
            if "laptop5" in ap:
                ap.remove('laptop5')

    if len(all_paths) == 0:
        return None

    ct = 0
    end_point = None
    while ct < 5:
        p = random.choice(all_paths)
        path = [n for n in p if n != 'hub']
        if len(path) == 1:
            node = path[0]
        else:
            node = path[1]
        if node != from_node:
            choose_from = list(set(all_assets_list) - set(failed_node_list))
            if len(choose_from) == 0:
                ct += 1
                continue
            else:
                # choose_from = list(set(all_assets_list) - set(failed_node_list))
                # if len(choose_from) > 0:
                end_point_list = [i for i in choose_from if i.network_label == node]
                if len(end_point_list) == 0:
                    ct += 1
                    continue
                elif len(list(set(objective_labels).intersection(set(end_point_list)))) > 0:
                    end_point = random.choice(end_point_list)
                    break
                else:
                    end_point = random.choice(end_point_list)
                    ct += 1
                    continue
        else:
            ct += 1

    return end_point


def find_all_paths(graph, start, end):
    path = []
    paths = []
    queue = [(start, end, path)]
    while queue:
        start, end, path = queue.pop()

        path = path + [start]
        if start == end:
            paths.append(path)
        for node in set(graph[start]).difference(path):
            queue.append((node, end, path))

    return paths
