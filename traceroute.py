import socket
import os
import struct
import time
import select
import optparse

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 60
TIMEOUT = 2.0
TRIES = 10

def checksum(str):
    csum = 0
    until = (len(str) / 2) * 2
    count = 0
    while count < until:
        csum = (csum+ord(str[count+1])*256+ord(str[count])) & 0xffffffffL  # noqa
        count += 2
    if until < len(str):
        csum = (csum+ord(str[len(str)-1])) & 0xffffffffL  # noqa
    csum = (csum >> 16)+(csum & 0xffff)
    csum = csum+(csum >> 16)
    return (~csum & 0xffff) >> 8 | ((~csum & 0xffff) << 8 & 0xff00)


def get_name_or_ip(hostip):
    try:
        host = socket.gethostbyaddr(hostip)
        nameorip = nameorip = u'{0} ({1})'.format(hostip, host[0])
    except Exception:
        nameorip = u'{0}'.format(hostip)
    return nameorip


def packet():
    id = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = struct.pack('d', time.time())
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(checksum(header + data)) & 0xffff, id, 1)  # noqa
    return header+data


def traceroute(target):

    timeLeft = TIMEOUT
    for ttl in xrange(1, MAX_HOPS):
        for tries in xrange(TRIES):
            icmp = socket.getprotobyname('icmp')
            crawler = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            crawler.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))  # noqa
            crawler.settimeout(TIMEOUT)
            try:
                d = packet()
                crawler.sendto(d, (target, 0))
                t = time.time()
                startedSelect = time.time()
                if timeLeft <= 0:
                    continue
                chunk = select.select([crawler], [], [], timeLeft)
                #if chunk[0] != []:
                    #print " %d * * *" % (ttl)
                recvPacket, addr = crawler.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - (time.time() - startedSelect)
            except socket.timeout:
                continue
            else:
                type, code, checksum, id, sequence = struct.unpack('bbHHh', recvPacket[20:28])  # noqa
                hostname = get_name_or_ip(addr[0])
                if type == 11:
                    print " %d rtt=%.0fms %s" % (ttl, (timeReceived-t) * 1000, hostname)  # noqa
                elif type == 3:
                    print " %d rtt=%.0fms %s" % (ttl, (timeReceived-t) * 1000, hostname)  # noqa
                elif type == 0:
                    bytes = struct.calcsize('d')
                    timeSent = struct.unpack('d', recvPacket[28:28 + bytes])[0]
                    print " %d rtt=%.0fms %s\n" % (ttl, (timeReceived-timeSent) * 1000, hostname)  # noqa
                    return
                else:
                    print 'error'
                break
            finally:
                crawler.close()


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
