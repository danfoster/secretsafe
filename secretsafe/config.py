"""Client-side config for secretsafe"""
import os, sys
import ConfigParser

class Config(object):
    """Client-side config for secretsafe"""
    def __init__(self):
        """Use ConfigParser to get settings from config file."""
        self.config = ConfigParser.ConfigParser()
        self.filename = os.path.expanduser('~/.secretsafe')
        if not os.path.isfile(self.filename):
            self._createconfig()
        self.config.readfp(open(self.filename))
        self.user = self.config.get("main", "user")
        self.secrets = os.path.expanduser(self.config.get("main", "secrets"))
        self.mode = self.config.get("main", "mode")
        if not (self.mode == "local" or self.mode == "remote"):
            print "ERROR: unknown mode %s. Options are local or remote"\
                %self.mode
            sys.exit(1)

    def _createconfig(self):
        """Interactivity create a basic config."""
        if not self.config.has_section("main"):
            self.config.add_section("main")

        # Assume local mode by default
        self.config.set("main", "mode", "local")
        # Add user
        # TODO: Pick user from list of GPG private keys
        i = raw_input('Enter username: ')
        self.config.set("main", "user", i)
        # Add sensible guess of Secrets home
        self.config.set("main", "secrets", "~/secretsafe.data")

        with open(self.filename, 'wb') as configfile:
            self.config.write(configfile)
