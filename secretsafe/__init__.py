
import ConfigParser, os
class Config:
    # Use ConfigParser to get settings from config file.
    def __init__(self):
        self.config = ConfigParser.ConfigParser()
        self.config.readfp(open(os.path.expanduser('~/.secretsafe')))
        self.user = self.config.get("main","user")
        self.secrets = os.path.expanduser(self.config.get("main","secrets"))

import gnupg, sys, random, os, getpass
import re
class SecretSafe:
    def __init__(self):
        self.config = Config()
        self.gpg = gnupg.GPG(gnupghome=os.path.expanduser(self.config.config.get("main","gnupghome")))
        self._findprivatekey()
        self.preauth()

    def add(self, name):
        # Add a secret to the database
        secretpath = os.path.join(self.config.secrets,name)

        # Check to see if secretpath already exists.
        if os.path.exists(secretpath):
            print "A secret under this name exists, not adding."
            return 1
        os.mkdir(secretpath)

        # Prompt for user to enter secretpath
        secret = getpass.getpass("Enter Secret (not echoed): ")
        secretgpg = str(self.gpg.encrypt(secret, self.config.user))

        # Write the plain secret
        with open(os.path.join(secretpath,"plain.gpg"),"w") as file:
            file.write(secretgpg)

    def get(self, name):
        # View a scret from the database
        secretpath = os.path.join(self.config.secrets,name)

        # Check to see if secretpath already exists.
        if not os.path.exists(secretpath):
            print "A secret under this name does not exist"
            return 1

        #Read the secret
        with open(os.path.join(secretpath,"plain.gpg"),"r") as file:
            secretgpg = file.read()
        print self.gpg.decrypt(secretgpg)

    def list(self,pattern):
        # List all secrets

        prog = re.compile(pattern)
        secrets = os.listdir(self.config.secrets)
        for secret in secrets:
            if prog.match(secret) != None:
                print secret

    def _findprivatekey(self):
        private_keys = self.gpg.list_keys(True) # True => private keys

        # Try and find the private key assosiated with the 'user' varible in
        # the config.
        self.user_private_key = None
        for key in private_keys:
            for uid in key['uids']:
                if uid == self.config.user:
                    self.user_private_key = key
        if not self.user_private_key:
            print "Cannot find a private key assosiated with the user: " \
                + self.config.user \
                +". Exiting..."
            sys.exit(1)


    def preauth(self):
        # Check the user has valid credentials to the private key, by encrypting
        # and decrpyting some random data.
        # This allows us to warn the user before we proceed.
        random.seed() # Auto seeds on system time with no argument specified.
        clear = str(random.getrandbits(1024))
        fingerprint = self.user_private_key['fingerprint']
        crypt = str(self.gpg.encrypt(clear, fingerprint))
        # TODO: Check that is encrypted
        decrypt = str(self.gpg.decrypt(crypt))
        if clear != decrypt:
            print "Cannot preauth using private key + passphrase. Please \
confirm you have entered the correct password."
            sys.exit(1)
        

