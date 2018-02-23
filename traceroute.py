#!/usr/bin/python

import socket
import struct
import sys
import optparse
import os
import time
import random

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 60
TIMEOUT = 5
TRIES = 10

class flushfile(file):
    def __init__(self, f):
        self.f = f
    def write(self, x):
        self.f.write(x)
        self.f.flush()

sys.stdout = flushfile(sys.stdout)

def traceroute(dest_name):
    dest_addr = socket.gethostbyname(dest_name)

    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    sys.stdout.write(" tracing %s\n" % dest_name)

    ttl = 1
    tries = TRIES

    while True:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
        recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", TIMEOUT, 0))

        port = int((random.random() + 33434) % 65535)

        recv_socket.bind(("", port))
        sys.stdout.write(" %d  " % ttl)
        send_socket.sendto("", (dest_name, port))
        curr_addr = None
        curr_name = None
        finished = False
        while not finished and tries > 0:
            try:
                recvPacket, curr_addr = recv_socket.recvfrom(512)

                finished = True
                curr_addr = curr_addr[0]
                try:
                    curr_name = socket.gethostbyaddr(curr_addr)[0]
                except socket.error:
                    curr_name = curr_addr
            except socket.error as (errno, errmsg):
                tries = tries - 1
                sys.stdout.write("* ")

        send_socket.close()
        recv_socket.close()

        if not finished:
            pass

        if curr_addr is not None:
            type, code, checksum, id, sequence = struct.unpack('bbHHh', recvPacket[20:28])  # noqa

            if curr_name == curr_addr:
                curr_host = curr_addr
            else:
                curr_host = "%s (%s)" % (curr_name, curr_addr)
        else:
            curr_host = ""

        sys.stdout.write("%s\n" % (curr_host))

        ttl += 1
        if tries == 0 or curr_addr == dest_addr or ttl > MAX_HOPS:
            break

def main():
    cmdparser = optparse.OptionParser("%prog --target=IP_ADDRESS")
    cmdparser.add_option(
        "-t", "--target", type="string", default="8.8.8.8",
        help="Hostname or IP address of destination host (default: 8.8.8.8)")
    options, _ = cmdparser.parse_args()
    traceroute(options.target)
    return 0

if __name__ == "__main__":
    main()
