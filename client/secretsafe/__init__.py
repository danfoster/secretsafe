
import ConfigParser, os
class Config:
	# Use ConfigParser to get settings from config file.
	def __init__(self):
		self.config = ConfigParser.ConfigParser()
		self.config.readfp(open(os.path.expanduser('~/.secretsafe')))
		self.user = self.config.get("main","user")

import gnupg, sys
class SecretSafe:
	def __init__(self):
		self.gpg = gnupg.GPG(gnupghome='/Users/dan/.gnupg')
		self.config = Config()
	def auth(self):
		# Read in public and private keys
		public_keys = self.gpg.list_keys() # same as gpg.list_keys(False)
		private_keys = self.gpg.list_keys(True) # True => private keys

		# Try and find the private key assosiated with the 'user' varible in the config
		self.user_private_key = None
		for key in private_keys:
			for uid in key['uids']:
				if uid == self.config.user:
					self.user_private_key = key
		if not self.user_private_key:
			print "Cannot find a private key assosiated with the user: "+self.config.user+". Exiting..."
			sys.exit(1)

		print self.user_private_key	

		
