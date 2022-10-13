from anytree import NodeMixin, RenderTree
from entity_module.Entity import Entity

"""
Want to use a graph / tree approach to value; a separate graph for each value modality
Look to use a graphml input to set up the anytree
Ideally, a UI driven tool to create the graphml
"""

class EntityValueClass(NodeMixin, Entity):
    def __init__(self, label, parent=None, children=None, value=0, **kwargs):
        super(EntityValueClass, self).__init__(**kwargs)
        self.label = label
        self.value = value
        self.parent = parent
        if children:
            self.children = children


if __name__ == '__main__':

    acme = EntityValueClass(label='acme', value=100)
    div1 = EntityValueClass(label="ops", parent=acme, value=40)
    div2 = EntityValueClass(label="sales", parent=acme, value=60)
    svr1 = EntityValueClass(label="mainframe", parent=div1, value=40, owner="Steve")
    svr2 = EntityValueClass(label="database", parent=div2, value=25)
    svr3 = EntityValueClass(label="mail", parent=div2, value=35)

    for pre, _, node in RenderTree(acme):
        treestr = u"%s%s" % (pre, node.label)
        print(treestr.ljust(8), node.value)

    db = 1
