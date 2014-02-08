import gnupg
import sys
import random
import os
import getpass
import re
import pprint

import config

class RecipientList:
    def __init__(self,gpg,filter=None):
        self.recipients = []
        keys = gpg.list_keys()
        for key in keys:
            if key['trust'] == 'u':
                for uid in key['uids']:
                    if uid not in self.recipients:
                        if not filter:
                            self.recipients.append(uid)
                        elif filter in uid:
                            self.recipients.append(uid)

    def list(self):
        for key,value in enumerate(self.recipients):
            print "  %s: %s"%(key,value)

    def get(self,num):
        try:
            return self.recipients[num]
        except IndexError:
            return None

class Client:
    def __init__(self):
        self.config = config.Config()
        self.gpg = gnupg.GPG(gnupghome=os.path.expanduser(self.config.config.get("main","gnupghome")))
        self._findprivatekey()
#        self.preauth()
        if self.config.mode == 'local':
            if not os.path.isdir(self.config.secrets):
                #No secret dir, lets create an empty one.
                os.mkdir(self.config.secrets)


    def checkrecipient(self, user):
        """
        Check that we have a key for a recipient and that we trust it.
        """

        if user=='':
            return None
        keys = self.gpg.list_keys()
        for key in keys:
            for uid in key['uids']:
                if user in uid:
                    if key['trust'] == 'u':
                        return key
                    else:
                        print "Corresponding Key for %s isnot trusted"%user
                        return None
        print "Corresponding Key for %s not found."%user
        return None

    def _readrecipients(self):
        # Interactive input for building a list of recipients.
        def readrecipientshelp():
            print "Enter recipients, one per line. Blank line to finish."
            print "L <filter>: List possible Recipients"
            print "?: Print this help"
        
        recipients = set()
        r = None
        readrecipientshelp()
        while r != "":
            r = raw_input("Enter Recipient: ")
            if r == '?':
                # Show help
                readrecipientshelp()
            elif r == 'L'or r.startswith('L '):
                # List valid recipients
                if r == 'L':
                    recipients_list = RecipientList(self.gpg)
                else:
                    filter_ = r.lstrip('L ')
                    recipients_list = RecipientList(self.gpg,filter_)
                count = 1
                recipients_list.list()
            elif re.match('[0-9]+$',r):
                # Add recipient by index number
                if recipients_list:
                    r = recipients_list.get(int(r))
                    if r and self.checkrecipient(r):
                        recipients.add(r)
            elif self.checkrecipient(r):
                # Add valid recipient
                recipients.add(r)
        return recipients
        

    def add(self, name, recipients):
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

        # Build a list of recipients
        if recipients:
            # Recipients were given on command line.
            for r in recipients:
                if not self.checkrecipient(r):
                    sys.exit(1)
            recipients = set(recipients)
        else:
            recipients = self._readrecipients()
        # Check that users public key is trusted
        if not self.checkrecipient(self.config.user):
            sys.exit(1)
        # Add ourselves to the recipient list
        recipients.add(self.config.user)
        

        # Prompt for user to enter secret
        secret = getpass.getpass("Enter Secret (not echoed): ")
        secretgpg = str(self.gpg.encrypt(secret, list(recipients)))
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
        

