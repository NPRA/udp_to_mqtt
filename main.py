#!/usr/bin/env python3

import sys
import socket
import time


HOST = ''
PORT = 50120
BUFSIZE = 1024
ADDR = (HOST, PORT)


class Client:
    def __init__(self, address):
        self.address = address
        self.ttl = 60  # 60 seconds TTL
        self.sent_history = []
        self.recv_history = []
        self.last_msg = time.time()

    def received(self, msg):
        self.recv_history.append(msg)

    def get_last_msg(self):
        if len(self.recv_history) > 0:
            return self.recv_history[-1]
        return str.encode("")

    def send(self, sock, data):
        self.sent_history.append(data)
        sock.sendto(str.encode(data), self.address)

    def __str__(self):
        return "Client(address=({}))".format(self.address)


class UdpServer:
    def __init__(self, address):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(address)
        self._clients = {}

    def run(self):
        while True:
            data, addr = self._sock.recvfrom(BUFSIZE)
            if data is None:
                print("Got zero data from {}:{} - ignore..".format(addr[0], addr[1]))
                continue

            print("[{}]: From addr {}:{} receive data: {}".format(time.ctime(), addr[0], addr[1], data))
            if addr not in self._clients:
                self._clients[addr] = Client(addr)
                self._clients[addr].received(data)
                self._clients[addr].send(self.sock, "Welcome new client!")
                print("New client registered: {}".format(self._clients[addr]))



            #send_data = input("> ")
            #if send_data is not None:
            #    encoded_data = str.encode(send_data)
            #    self._sock.sendto(encoded_data, addr)

        self._sock.close()


def main():
    server = UdpServer(ADDR)
    try:
        server.run()
    except KeyboardInterrupt:
        print("Server shutdown..")
        sys.exit(1)


if __name__ == '__main__':
    main()