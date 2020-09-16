Author: Addison Shuppy
Python version: 2.7.17

How to execute program in CADE:

1. Make Bob start listening in one shell:  python Bob.py -a [IPAddress] -p [Port to listen on]
2. Initialize Alice in a second shell: python Alice.py -a [IPAddress] -p [Port Bob will be listening on]
3. Alice will prompt you to enter getKey. Enter "getKey" exactly and press enter.
4. Alice will request a key, Bob will send one and a signed message digest.
5. Alice will then verify and ask for a relative file path to the document you
  want to send.  Enter the file path exactly.  The provided example document is x.txt,
  to be entered in exactly "x.txt". It contains highly classified information.
6. Alice will then prompt you to enter a password to initialize the session key.
7. Enter anything.
8. The secure message will then be sent and deciphered by Bob, and he will print
  out the message for you to see.

Note: this program is always in visual verification mode and will not have the
-v option from the command line.
