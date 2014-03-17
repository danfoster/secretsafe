import gnupg
import getpass
import sys

def decrypt(gpg,secret):
    """Helper function to decrypt a message and only prompt for a
    passphrase if needed.""" 

    # Lets first try and decrypt without a providing a passphrase.
    # This should work if a GPG agent is running.
    plain = str(gpg.decrypt(secret))
    count = 0
    while plain == "":
        # We've failed to decrypt the message without passing a passphrase.
        # This is probably because no GPG agent is running and/or the
        # GPG binary doesn't have a graphical way of asking for a passphrase.
        count += 1
        passphrase = getpass.getpass("Enter passphrase: ")
        plain = str(gpg.decrypt(secret,passphrase=passphrase))

        if count >= 3:
            # We've tried enough times, give up.
            print "ERROR: Cannot decrypt secret"
            sys.exit(1)
    return plain
