import socket
import os
from optparse import OptionParser
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3
from Crypto import Random
from Crypto.Util import Counter

#Verifies if the message matches it's signed hash.
def Verify(replyArr):
    #This is where the message will be written to.
    f1 = open('Received.txt', 'wb')
    f1.write(replyArr[1])
    f1.close()

    f2 = open('EncryptedMessage', 'wb')
    f2.write(replyArr[0])
    f2.close()

    print 'Verifying...'
    signature = replyArr[0]
    h = SHA.new(replyArr[1])
    f = open('publickey.pem', 'rb')
    aliceKey = RSA.importKey(f.read())
    f.close()
    verifier = PKCS1_v1_5.new(aliceKey)
    try:
        verifier.verify(h, signature)
        return True
    except:
        return False

#Parses replies from Bob into arrays containing the original data.
def ReceiveReply(totalReply):
    replyArr = totalReply.split(b'\r\nbreak\r\n')
    print "ReplayArr[0]: " + str(replyArr[0])
    print "ReplyArr[1]: " + str(replyArr[1])
    return replyArr

#Decrypts using the DES3 algorithm.
def DecryptDES3(crypt, key, iv):
    print "Decrypting: " + str(crypt)
    print "Key: " + str(key)
    cipher = DES3.new(key, DES3.MODE_OFB, iv)
    #print "Got: " + str(cipher.decrypt(crypt))
    return cipher.decrypt(crypt)

#Decrypts using the RSA algorithm.
def DecryptRSA(crypt, key):
    f = open("encryptedMessage", 'wb')
    f.write(crypt)
    f.close()
    f = open("encryptedMessage", 'rb')
    decrypted = ''
    while True:
        data = f.read(128)
        if not data:
            break
        else:
            print str(data)
        decrypted += key.decrypt(data)
    f.close()
    print "Got: " + str(decrypted)
    return decrypted

#The beginning of the program.
print "Hello, I am Bob"

#sets defaults
serverAddress = 'localhost'
serverPort = 2100

#Parses command line input.
parser = OptionParser()
parser.add_option("-a", "--address", dest="serverAddress",
                  help="The IP address that Bob will be on", metavar="ADDRESS")
parser.add_option("-p", "--port", dest="serverPort",
                  help="the port for Bob to listen on.", metavar="PORT")
(options, args) = parser.parse_args()
if(options.serverAddress):
    serverAddress = options.serverAddress
if(options.serverPort):
    serverPort = int(options.serverPort)

#Starts listening on the specified port.
bobSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bobSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
bobSocket.bind((serverAddress,serverPort))
while True:
    print "listening on port: " + str(serverPort)
    bobSocket.listen(10)
    connectionSocket, addr = bobSocket.accept()
    data = connectionSocket.recv(1024)

    while data:
        i = 0
        while(data.endswith('\r\n\r\n') == False and i < 100):
            data += connectionSocket.recv(1024)
            i += 1
        print "Got request: " + data

        #Expects a key request from Alice, and processes it.
        if(data == b'Requesting Key\r\n\r\n'):
            print "Sending signed message digest of my public key along with my public key"
            f = open('publickey1.pem')
            totalPackage = ''
            segment = f.read(1024)
            while(segment):
                print "Sending"
                totalPackage += segment
                connectionSocket.send(segment)
                segment = f.read(1024)
            f.close()
            message = totalPackage
            key = RSA.importKey(open('privatekey2.pem').read())
            h = SHA.new(message)
            signer = PKCS1_v1_5.new(key)
            signature = signer.sign(h)
            f = open('signedPubKey', 'wb')
            f.write(signature)
            f.close()
            connectionSocket.send(b'\r\nbreak\r\n' + signature + b'\r\n\r\n')
            print "completed Sending"
            data = False
            connectionSocket.close()

        #Expects any data ending with two new lines and processes that as a message.
        elif(data.endswith(b'\r\n\r\n')):
            #Writes the entire received file for my own testing.
            filePackage = open('FilePackage', 'wb')
            filePackage.write(data)
            filePackage.close()

            #Parse data
            data.strip(b'\r\n\r\n')
            replyArr = ReceiveReply(data)

            print "Received message from Alice."
            print "Checking message integrity..."
            myPrivateKey = RSA.importKey(open('privatekey1.pem').read())

            print "Decrypting: " + replyArr[1]
            symKey = DecryptRSA(replyArr[1], myPrivateKey)
            f = open("Symkey", 'wb')
            f.write(symKey)
            f.close()

            replyArr[2] = replyArr[2][:8]
            f = open("IV", 'wb')
            f.write(replyArr[2])
            f.close()

            print "Got: " + str(symKey)
            f = open("EncryptedMessagePackage", 'wb')
            f.write(replyArr[0])
            f.close()

            #Decrypts the message using the symmetric key.
            decMessage1 = DecryptDES3(replyArr[0], symKey, replyArr[2])
            f = open("MessagePackage", 'wb')
            f.write(decMessage1)
            f.close()

            #Parses decrypted package
            replyArr2 = ReceiveReply(decMessage1)

            #Verifies
            if(Verify(replyArr2)):
                print "Verification and decryption successful."
            else:
                print "The signature is not authentic."
            f.close()
            print "This is the decrypted message: " + replyArr2[1]
            data = False
            connectionSocket.close()

        else:
            print "Could not process data"
            connectionSocket.close()
