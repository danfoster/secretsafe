import gnupg
import sys
import random
import os
import getpass
import re
import pprint

import config

class Client:
    def __init__(self):
        self.config = config.Config()
        self.gpg = gnupg.GPG(gnupghome=os.path.expanduser(self.config.config.get("main","gnupghome")))
        self._findprivatekey()
#        self.preauth()

    def checktrust(self, user):
        keys = self.gpg.list_keys()
        for key in keys:
            for uid in key['uids']:
                if uid == user:
                    if key['trust'] == 'u':
                        return 0
                    else:
                        print "ERROR: Key not trusted"
                        return 1
        print "ERROR: Key not found"
        return 1


    def add(self, name):
        # Add a secret to the database
        secretpath = os.path.join(self.config.secrets,name)

        # Check that name is valid
        if not re.match("[a-zA-Z0-9.-]+$",name):
            print "ERROR: Invalid secret name"
            sys.exit(1)

        # Check to see if secretpath already exists.
        if os.path.exists(secretpath):
            print "A secret under this name exists, not adding."
            return 1

        #Check that users public key is trusted
        if self.checktrust(self.config.user) == 1:
            sys.exit(1)

        # Prompt for user to enter secretpath
        secret = getpass.getpass("Enter Secret (not echoed): ")
        secretgpg = str(self.gpg.encrypt(secret, self.config.user))
        if secretgpg == "":
            print "ERROR: Failed to encrypt secret."
            sys.exit(1)

        os.mkdir(secretpath)
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
        

