import yaml


def index_tuples(l, v, c=0):
    return filter(lambda x: x[c] == v, l)[0]

def load_config():
    # load the configuration file
    with open('config.yml', 'rb') as f:
        return yaml.load(f.read()) 
