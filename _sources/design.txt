Design
======

Overall Design
--------------

Secret Safe uses GPG encryption to safely store all secrets. GPG is suitable because it supports  multiple-key encryption by default and allows others to encrypt secrets with their public key without knowing the users private key.

Git
~~~

The secret back-end is stored in on disk in a git repository. This allows secretsafe to keep a history of previous secrets.

Key Trust
---------

//TODO: Key Trust

Client-Server & Local Mode
--------------------------

Secretsafe has 2 operation models. `Local` and `Client-Server`.

Local mode
~~~~~~~~~~

In local mode, the user has a copy of the whole git repository containing all the secrets in an encrypted format. Depending on your level of paranoia, this may be an issue if you believe an adversity could get hold of your git repository and brute-force a secret off-line.

The sharing of secrets in this mode is not done by secretsafe and left to the standard tools available by git.

Client-Server mode
~~~~~~~~~~~~~~~~~~

In client-server mode, a secretsafe server is run that contains all the secrets. A client first authenticates to the server before the encrypted secret is sent to the client. Decryption still happens client side.

While git is still used for history, the sharing of secrets is done by secretsafe itself, as clients connect to the same server.
