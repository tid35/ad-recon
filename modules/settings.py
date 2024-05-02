import toml

def get_config():
    config = toml.load('config.toml')
    return config

def update_config(config):
    f = open("config.toml",'w')
    toml.dump(config, f)
    f.close()

