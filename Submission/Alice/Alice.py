import socket
import os
import hashlib
from optparse import OptionParser
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3
from Crypto.Util import Counter

#Alice sends a secure message to Bob
def EncryptAndSend(targetAddress, targetPort, filepath):
    #Connect to Bob again
    consoleMessage = 'Sending {message} along with symmmetric key'
    print(consoleMessage.format(message = filepath))
    aliceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print 'bobsAddress: ', bobsAddress, '\nbobsPort: ', bobsPort
    aliceSocket.connect((bobsAddress, bobsPort))
    print 'Bound to: (after connect call)', aliceSocket.getsockname()

    #read the file to be sent
    f = open(filepath, 'rb')
    message = f.read()
    f.close()

    #Hash and sign message with Alice's private key
    key = RSA.importKey(open('privatekey.pem').read())
    h = SHA.new(message) #sha1 is 20 bytes
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(h)
    print "Signed message: ", signature
    f = open("EncryptedMessage" , 'wb')
    f.write(signature)
    f.close()

    #Create the message package by concatenating signature with original message
    #These files are for file comparison testing.
    messageSum = signature + b'\r\nbreak\r\n' + message
    totalPadding = 8 - len(messageSum) % 8
    while(totalPadding > 0):
        totalPadding -= 1
        messageSum += b' '
    print "Message Package: ", messageSum
    f = open('MessagePackage', 'wb')
    f.write(messageSum)
    f.close()

    #Sets variables for iv and key derivation
    IV_SIZE = 8
    KEY_SIZE = 16
    SALT_SIZE = 16

    #Derives IV and writes it to a file. These files are for file comparison testing.
    password = raw_input("Please enter a password for your symmetric encryption: ")
    salt = os.urandom(SALT_SIZE)
    derived = hashlib.pbkdf2_hmac('sha1', password, salt, 100000, dklen=IV_SIZE + KEY_SIZE)
    iv = derived[0:IV_SIZE]
    print "IV: ", iv
    f = open("IV", 'wb')
    f.write(iv)
    f.close()

    #Derives key and writes it to a file.  These files are for file comparison testing.
    key = derived[IV_SIZE:]
    print "Symmetric Key: ", key
    f = open("Symkey", 'wb')
    f.write(key)
    f.close()

    #Encrypts message package and writes it to a file.
    #These files are for file comparison testing.
    cipher = DES3.new(key, DES3.MODE_OFB, iv)
    encryptedMessage = cipher.encrypt(messageSum)
    print "Encrypted Package: ", encryptedMessage
    f = open("EncryptedMessagePackage", 'wb')
    f.write(encryptedMessage)
    f.close()

    #Encrypts Bob's public key.  While loop isn't necessary with my key.
    bobsPubKey = RSA.importKey(open('publickey1.pem').read())
    f = open('SymmetricKey.txt', 'w')
    f.write(key)
    f.close()
    f = open('SymmetricKey.txt', 'r')
    symKeyBuffered = ''
    while True:
        chunk = f.read(127)
        if not chunk:
            break
        encryptedChunk = bobsPubKey.encrypt(key, 0)[0]
        #symKeyBuffered += chr(len(encryptedChunk))
        #print "Encrypted Chunk: " + str(encryptedChunk)
        symKeyBuffered += encryptedChunk
    f.close()

    #Writes entire secure message to a file and sends it piece by piece.
    filePackage = open('FilePackage', 'wb')
    print "Encrypted Message: " + str(encryptedMessage)
    print "Key: " + str(key)
    filePackage.write(encryptedMessage)
    filePackage.write(b'\r\nbreak\r\n')
    filePackage.write(symKeyBuffered)
    filePackage.write(b'\r\nbreak\r\n')
    filePackage.write(iv)
    filePackage.write(b'\r\n\r\n')
    filePackage.close()
    f = open('FilePackage', 'rb')
    while True:
        chunk = f.read(1024)
        if not chunk:
            break
        aliceSocket.send(chunk)
    f.close()
    print "secure message sent"

#Connects to Bob, sends the request for a key, and returns the reply array
def GetKey(targetAddress, targetPort):
    aliceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print 'bobsAddress: ', bobsAddress, '\nbobsPort: ', bobsPort
    aliceSocket.connect((bobsAddress, bobsPort))
    print 'Bound to: (after connect call)', aliceSocket.getsockname()
    keyRequest = b'Requesting Key\r\n\r\n'
    print 'sending:\r\n', keyRequest
    aliceSocket.send(keyRequest)
    replyArr = ReceiveReply(aliceSocket)
    return replyArr

#Parses replies from Bob into arrays containing the original data.
def ReceiveReply(socket):
    totalReply = socket.recv(1024)#.decode(encoding='utf_16')
    while(totalReply.endswith(b'\r\n\r\n') == False):
        totalReply += socket.recv(1024)#.decode(encoding='utf_16')
    print 'totalReply: ', totalReply
    replyArr = totalReply.split(b'\r\nbreak\r\n')
    return replyArr

#Verifies if Bob's public key matches his signature
def Verify(replyArr):
    f1 = open('publickey1.pem', 'wb')
    f1.write(replyArr[0])
    f1.close()
    print 'Verifying...'
    signature = replyArr[1].strip(b'\r\n\r\n')
    f2 = open('signedPubKey', 'wb')
    f2.write(signature)
    f2.close()
    key = RSA.importKey(open('publickey2.pem').read())
    h = SHA.new(replyArr[0])
    verifier = PKCS1_v1_5.new(key)
    try:
        verifier.verify(h, signature)
        return True
    except:
        return False

#Beginning of the program
print "Hello, I am Alice."

#Sets defaults
bobsAddress = 'localhost'
bobsPort = 2100

#Parses command line options
parser = OptionParser()
parser.add_option("-a", "--address", dest="serverAddress",
                  help="The IP address that Bob will be on", metavar="ADDRESS")
parser.add_option("-p", "--port", dest="serverPort",
                  help="the port that Bob will be listening on.", metavar="PORT")
(options, args) = parser.parse_args()
if(options.serverAddress):
    bobsAddress = options.serverAddress
if(options.serverPort):
    bobsPort = int(options.serverPort)

#Alice's main secquence.
command = raw_input("To begin, enter getKey: ")
if(command == "getKey"):
    replyArr = GetKey(bobsAddress, bobsPort)
    if(Verify(replyArr)):
        print 'Verification successful.'
        filepath = raw_input("Enter the relative filepath to the message you would like to securely send: ")
        EncryptAndSend(bobsAddress, bobsPort, filepath)
        running = False
    else:
        print "The signature is not authentic."
        running = False
