class Attack(object):
    def __init__(self, type):
        self.type = type
        if type == 'network':
            print(f'This is a {type} attack')
        elif type == 'remote':
            print(f'This is a {type} attack')
        elif type == 'error':
            print(f'This is a {type} attack')
        elif type == 'misuse':
            print(f'This is a {type} attack')


if __name__ == '__main__':
    a = Attack(type='network')
