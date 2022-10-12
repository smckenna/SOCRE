from uuid import uuid4



class AllEntities:
    def __init__(self):
        self.dict = {}
        self.list = []
        self.uuid_list = []

    def add_to_all_entities(self, entity):
        self.dict[entity.uuid] = entity
        self.list.append(entity)
        self.uuid_list.append(entity.uuid)


class Entity(object):

    def __init__(self, label="", owner=None):
        self.uuid = uuid4()
        self.value = 0
        self.label = label
        self.owner = owner
        self.properties = dict()
        self.data = {}
        self.manifest = {}

class CriticalEntity(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Organization(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Process(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Division(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Application(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Product(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Function(Entity):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Asset(Entity):

    def __init__(self, label="", owner=None, ip_address='0.0.0.0', operating_system='linux'):
        super().__init__(label=label, owner=owner)
        self.ip_address = ip_address
        self.os = operating_system


class Server(Asset):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Laptop(Asset):

    def __init__(self, label="", owner=None, operating_system="windows"):
        super().__init__(label=label, owner=owner)
        self.os = operating_system

class Desktop(Asset):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class MobileDevice(Asset):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class VirtualMachine(Asset):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class CloudObject(Entity):

    def __init__(self, label="", owner=None, provider='aws'):
        super().__init__(label=label, owner=owner)
        self.provider = provider


class CloudDataBase(CloudObject):

    def __init__(self, label="", owner=None):
        super().__init__(label=label, owner=owner)


class Data:

    def __init__(self, label="", owner=None):
        self.uuid = uuid4()
        self.value = {}
        self.label = label
        self.owner = owner
        self.properties = dict()
        self.data = {}


class EntityGroup:

    def __init__(self, list_of_entities, label, owner):
        self.list_of_entities = list_of_entities
        self.uuid = uuid4()
        self.value = {}
        self.label = label
        self.owner = owner
        self.properties = dict()
        self.data = {}


class DataGroup:

    def __init__(self, list_of_data, label, owner):
        self.list_of_data = list_of_data
        self.uuid = uuid4()
        self.value = 0
        self.label = label
        self.owner = owner
        self.properties = dict()
        self.data = {}


if __name__ == '__main__':
    acme = Organization(label="ACME", owner=None)
    all_entities = AllEntities()
    all_entities.add_to_all_entities(acme)

    app1 = Application(owner="Jane", label="Payroll")
    all_entities.add_to_all_entities(app1)

    svr1 = Server(owner="Jane", label="Mainframe")
    svr2 = Server(owner="Steve", label="Print server")
    laptop1 = Laptop(owner="Hank", label="Employee machine", operating_system="linux")
    laptop2 = Laptop(owner="Sue", label="Employee machine")
    laptop3 = Laptop(owner="Bill", label="Employee machine")
    laptop4 = Laptop(owner="Mary", label="Employee machine")
    all_entities.add_to_all_entities(svr1)
    all_entities.add_to_all_entities(svr2)
    all_entities.add_to_all_entities(laptop1)
    all_entities.add_to_all_entities(laptop2)
    all_entities.add_to_all_entities(laptop3)
    all_entities.add_to_all_entities(laptop4)

    div1 = Division(label="Operations", owner="SVP1")
    div2 = Division(label="Sales", owner="SVP2")
    all_entities.add_to_all_entities(div1)
    all_entities.add_to_all_entities(div2)

    all_laptops = EntityGroup(list_of_entities=[laptop1, laptop2, laptop3, laptop4],
                              label="all laptops", owner=None)
    my_db = CloudDataBase("cloud db", "me")
    db_records = Data(label="Database Records", owner="Sue")
