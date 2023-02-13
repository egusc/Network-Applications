#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import select
from urllib import request



def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=Traceroute, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))


class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        timeremaining = timeout
       
        pass

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        header = struct.pack('bbHHh', 8, 0, 0, ID, 1)
        data = bytes("hello, I am an ICMP ping hopefully if the person who created me did the right thing. If not I am merely a useless piece of data, a speck in the infinite universe.", 'utf-8')
        # 2. Checksum ICMP packet using given function
        new_checksum = self.checksum(header + data)
        # 3. Insert checksum into packet
        header = struct.pack('bbHHh', 8, 0, new_checksum, ID, 1)
        packet = header + data
        # 4. Send packet using socket
        while packet:
            
            sent = icmpSocket.sendto(packet, (destinationAddress, 1500)) #1500 = Port number
            packet = packet[sent:]
        # 5. Record time of sending
        sendTime = time.time()
        return sendTime

    def doOnePing(self, destinationAddress, timeout):
        # 1. Create ICMP socket
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp')) #Sends raw packets to ipv4 addresses
        ID = 1
        # 2. Call sendOnePing function
        sendTime = self.sendOnePing(new_socket, destinationAddress, ID)
        # 3. Call receiveOnePing function
        receiveTime = self.receiveOnePing(new_socket,destinationAddress, ID, 1)
        # 4. Close ICMP socket
        new_socket.close()
        # 5. Return total network delay
        delay = receiveTime - sendTime
        return delay

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        try:
            destinationAddress = socket.gethostbyname(args.hostname);
            while True:
                delay = self.doOnePing(destinationAddress, 1)
                self.printOneResult(destinationAddress, 203, delay * 1000, 150, args.hostname)
                time.sleep(1)
        except:
            print("Host name not recognised")
        # 2. Call doOnePing function, approximately every second
        # 3. Print out the returned delay (and other relevant details) using the printOneResult method
        
        # 4. Continue this process until stopped



class Traceroute(NetworkApplication):

    def __init__(self, args):
        #Traceroute to server
        print('Traceroute to: %s...' % (args.hostname))
        
        destinationAddress = socket.gethostbyname(args.hostname);   #Get IP of destination

        
        while True:
            ttl = 1
            while True:
                #Creates sockets
                receiveSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sendSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
                sendSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)    #Limit ttl of socket

                #COnstruct and send packet
                header = struct.pack('bbHHh', 8, 0, 0, 5, 1)
                data = "hello, I am an ICMP traceroute hopefully if the person who created me did the right thing. If not I am merely a useless piece of data, a speck in the infinite universe.".encode()
                new_checksum = self.checksum(header + data)
                header = struct.pack('bbHHh', 8, 0, new_checksum, 5, 1)
                packet = header + data
                sendSocket.sendto(packet, (destinationAddress, 7162))

                sendtime = time.time()  #Record beginning time

                #Loop until packet received
                run = True
                while run:
                    receivedpacket, address = receiveSocket.recvfrom(4568)
                    address = address[0]
                    
                    run = False
                
                sendSocket.close()
                receiveSocket.close()
                
                receivetime = time.time()

                #Find hostname of address if a hostname exists
                try:
                        hostname = socket.gethostbyaddr(address)[0]
                except:
                    hostname = address

                self.printOneResult(address, sys.getsizeof(packet), (receivetime - sendtime) * 1000, ttl, hostname)

                ttl += 1

                #Exit loop if destination is found
                if address == destinationAddress:
                    break
            print("\n")
            time.sleep(3)


class WebServer(NetworkApplication):

    def handleRequest(self, tcpSocket):
        # 1. Receive request message from the client on connection socket
        getrequest = tcpSocket.recv(2626).decode()
        print(getrequest)
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        headers = getrequest.split('\n')
        filename = headers[0].split()[1]

        try:
            # 3. Read the corresponding file from disk
            filetosend = open(filename.replace('/', ''))
            content = filetosend.read()
            filetosend.close()

             # 4. Store in temporary buffer
            response = 'HTTP/1.0 200 OK\n\n' + content

        # 5. Send the correct HTTP response error
        except FileNotFoundError:

            response = 'HTTP/1.0 404 NOT FOUND\n\nFile Not Found'

        # 6. Send the content of the file to the socket
        tcpSocket.sendall(response.encode())
        # 7. Close the connection socket
        tcpSocket.close()
        pass

    def __init__(self, args):
        #print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        serverSocket = socket.socket()
        serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 2. Bind the server socket to server address and server port
        serverSocket.bind(("127.0.0.1", 8080))
        # 3. Continuously listen for connections to server socket
        serverSocket.listen()
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)#
        run = True
        while run:
            clientSocket, clientAddress = serverSocket.accept()
            self.handleRequest(clientSocket)
            # 5. Close server socket
            serverSocket.close()
            run = False
            
       
        
        
        


class Proxy(NetworkApplication):

    def proxyHandleRequest(self, tcpSocket):
        #Receive clients request
        getrequest = tcpSocket.recv(2625).decode()
        
        #Extract URL to get HTML from
        url = getrequest.split('\n')[0]
        url = url.split(' ')[1]
        url = url.replace("http://", "")
        url = url.replace("/", "")

        #Send GET request to requested URL
        sendSocket = socket.socket() 
        sendSocket.connect((url, 80))
        sendSocket.sendall(getrequest.encode())

        #Loop until response received and send response to client
        run = True
        while run:
            data = sendSocket.recv(6058)
            tcpSocket.send(data)
            run = False
            sendSocket.close()
        pass

    def __init__(self, args):
        #print('Web Proxy starting on port: %i...' % (args.port))

        #Create socket for proxy server
        proxySocket = socket.socket()
        proxySocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   #Reuse address when running again
        proxySocket.bind(("127.0.0.1", 8080))
        proxySocket.listen()

        #Repeat until connection accepted, handle request then close socket
        run = True
        while run:
            clientSocket, clientAddress = proxySocket.accept()
            self.proxyHandleRequest(clientSocket)
            proxySocket.close()
            run = False


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
