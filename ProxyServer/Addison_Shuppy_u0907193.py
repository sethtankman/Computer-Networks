from threading import Thread
from optparse import OptionParser
from urlparse import urlparse
import hashlib
import socket
import os
import sys
import requests

#The client side of the proxy
class proxy_client:
    def __init__(self, serverThread, data, _host, _clientPort, _APIKey):
        print("Proxy Client:")
        clientPort = _clientPort
        #Do not assume server will be running on a particular IPAddress
        serverAddress = _host
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print 'Bound to: (after socket call)', clientSocket.getsockname()
        print 'serverAddress: ', serverAddress, '\nclientPort: ', clientPort
        clientSocket.connect((serverAddress, clientPort))
        print 'Bound to: (after connect call)', clientSocket.getsockname()
        formatted = self.formatRequest(data, serverAddress)
        print 'sending:\r\n', formatted
        clientSocket.send(formatted)
        print 'sent'
        totalReply = ''
        reply = clientSocket.recv(1024)
        print reply
        while reply:
            totalReply += reply
            reply = clientSocket.recv(1024)
            print reply
        print 'totalReply: ', totalReply
        #check if the request was successful
        if(totalReply.split()[1] == '200') :
        # write the contents of the file so you have it here.
            print 'filename: ' + data.split()[1]
            filename = data.split()[1]
            if(filename.find(_host) != -1):
                print totalReply
                serverThread.conn.send(totalReply)
                clientSocket.close()
            else:
                f = open(filename, "wb")
                fileContent = totalReply.split('\r\n\r\n')[1]
                print 'file content: ' + fileContent
                f.write(fileContent)
                f.close()
                #Calculate MD5 checksum
                checksum = hashlib.md5(open(filename).read()).hexdigest()
                print 'Checksum: ', checksum
                APIKey = _APIKey
                url = 'https://www.virustotal.com/vtapi/v2/file/report'
                params = {'apikey': APIKey, 'resource': checksum}
                response = requests.get(url, params=params)
            print 'Response: ', response.json()
            print 'Response JSON: ', response.json().keys()

            #if response contains malware,
            if ('scans' in response.json() and response.json()['scans']['McAfee']['detected'] == True) :
                #send some HTML page indicating the message was blocked.
#                HTTPResponsePage = """<!DOCTYPE html>
#                <html lang="en" dir="ltr">
#                 <head>
#                    <meta charset="utf-8">
#                    <title>200 Ok</title>
#                  </head>
#                  <body>
#                    <h1>The content was blocked because it was suspected of containing malware</h1>
#                  </body>
#                </html>
#"""
                serverThread.conn.send('content blocked')
            else:
                #Otherwise send everything back to the server
                serverThread.conn.send(totalReply)
        else:
            serverThread.conn.send(totalReply)
            clientSocket.close()

#A Helper method to format the request that is sent to the server.
    def formatRequest(self, rdata, hostname):
        url = rdata.split()[1]
        parsed = urlparse(url)
        lcRequest = rdata.split()[0]
        fdata = lcRequest.upper()
        fdata += ' ' + parsed.path + ' '
        fdata += rdata.split()[2]
        i = 1
        needsHost = True
        needsConnection = True
        print 'fdata: ', fdata
        #Add the rest of the lines in the raw request to the final request
        while(i<len(rdata.splitlines()) -3):
            print 'fdata: ', fdata
            if(rdata.splitlines()[i].split()[0] == 'Host:'):
                needsHost = False
                fdata += "\r\n" + rdata.splitlines()[i]
            elif(rdata.splitlines()[i].split()[0] == "Connection:"):
                needsConnection = False
                fdata += "\r\nConnection: close"
            else:
                fdata += "\r\n" + rdata.splitlines()[i]
            i += 1
        if(needsHost):
            fdata += '\nHost: ' + hostname
        if(needsConnection):
            fdata += '\nConnection: close'
        print('fdata: ' + fdata)
        return fdata

#The Server side of the proxy
class proxy_server_thread(Thread):
    #example telnet request: telnet localhost 8000
    #HTTP server shell entry: python -m SimpleHTTPServer
    def __init__(self, addr, _clientPort, _APIKey):
        Thread.__init__(self)
        self.conn = connectionSocket
        self.ip = addr[0]
        self.port = addr[1]
        self.clientPort = _clientPort
        self.apikey = _APIKey
        #print "[+] New server socket thread started for " + self.ip + ":" + str(self.port)

    def run(self):
        while True :
            data = self.conn.recv(2048)
            #print "Server received data:", data
            while(data.endswith('\r\n\r\n') == False):
                data += self.conn.recv(2048)
            dataArr = data.splitlines()
            print dataArr
            firstLine = dataArr[0].split()
            url = firstLine[1]
            parsed = urlparse(url)
            #parse the port from url
            if(parsed.port != None) :
                self.clientPort = parsed.port
            #parse the host from url
            host = 'localhost'
            if(parsed.hostname != None):
                host = parsed.hostname
                print host
            method = firstLine[0].upper()
            #print(firstLine)
            if(method == "GET" and len(firstLine) == 3):
                #print('accepted header')
                for line in dataArr[1:]:
                    print 'line:', line
                    if(line != '' and not(": " in line)):
                        print 'uh oh'
                        connectionSocket.send('400: Bad Request')
                        connectionSocket.close()
                        break
                    elif(line != '' and ": " in line):
                        key = line.split()[0]
                        if(key == "Host:"):
                            host = line.split()[1]
                proxy_client(self, data, host, self.clientPort, self.apikey)
            elif(method == "POST" or method == "HEAD" or method == "PUT"
            or method == "DELETE" or method == "CONNECT" or method == "OPTIONS"
            or method == "TRACE" or method == "PATCH"):
                connectionSocket.send('501: Not Implemented')
                connectionSocket.close()
            else:
                connectionSocket.send('400: Bad Request')
                connectionSocket.close()

#Set Default values
serverPort = 2100
clientPort = 80
APIKey = 'cf53d292a9a13d21af2004cd94cbe50258add957086b36dd1e342998e418393f'
#while index < len(sys.argv) :
#    if(sys.argv[index] == '-h') :
#        print '\nTo specify the port for this proxy to listen on, enter "-l<port number>" \nthe default server port is 9000.\n\nTo specify the port for the proxy client to request, enter "-r<port number>"'
#        index += 1
#    elif sys.argv[index].startswith('l') == True :
#        serverPort = int(sys.argv[index][1:])
#        print 'serverPort: ', serverPort
#        index += 1
#    elif sys.argv[index].startswith('r') == True :
#        clientPort = int(sys.argv[index][1:])
#        print 'clientPort: ', clientPort
#        index += 1
#    else:
#        index += 1

parser = OptionParser()

parser.add_option("-k", "--key", dest="APIKey",
                  help="The APIKey", metavar="APIKEY")
parser.add_option("-l", "--listen", dest="serverPort",
                  help="the port for this proxy to listen on.", metavar="LISTEN")
parser.add_option("-r", "--request", dest="clientPort",
                  help="The port for the client to request to.", metavar="REQUEST")


(options, args) = parser.parse_args()
if(options.APIKey):
    APIKey = options.APIKey
    print 'APIKey changed:', APIKey
if(options.serverPort):
    serverPort = int(options.serverPort)
if(options.clientPort):
    clientPort = int(options.clientPort)
#Server Address is always localhost
serverAddress = 'localhost'
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#print 'Got a socket with fd:', serverSocket.fileno()
serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serverSocket.bind((serverAddress,serverPort))
#print 'Bound to:', serverSocket.getsockname()
threads = []

while 1:
    serverSocket.listen(10)
    #print 'Listening for requests'
    connectionSocket, addr = serverSocket.accept()
    #print 'Accepted connection from:', connectionSocket.getpeername(), ' fd: ' , connectionSocket.fileno()
    #Thread limit is 100
    if(len(threads) < 100):
        newThread = proxy_server_thread(addr, clientPort, APIKey)
        newThread.start()
        threads.append(newThread)
    else:
        connectionSocket.send('Cannot process more than 100 concurrent threads.')

for t in threads:
    t.join()
