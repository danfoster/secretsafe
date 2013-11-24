import os
import ConfigParser

class Config:
    # Use ConfigParser to get settings from config file.
    def __init__(self):
        self.config = ConfigParser.ConfigParser()
        self.config.readfp(open(os.path.expanduser('~/.secretsafe')))
        self.user = self.config.get("main","user")
        self.secrets = os.path.expanduser(self.config.get("main","secrets"))
