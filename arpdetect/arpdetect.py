#!/usr/bin/python
import sys
import os
import subprocess
#import wmi
import argparse
import logging
import datetime
import time

LOG = False
DROP = False
INSPECT_INTERVAL = 5 # In seconds

# A host device
class Host:
	def __init__(self, item):
		self.ipv4 = item[0]
		self.mac = item[1]
		self.type = item[2]

	def toString(self):
		return "Ip:{} | MAC:{} | Type:{}".format(
			self.ipv4,
			self.mac,
			self.type
		)

# A suspected device
class Suspect:
	def __init__(self):
		self.ipv4 = "Unknown"
		self.mac = "Unknown"

	def toString(self):
		return "Ip:{} | MAC:{}".format(
			self.ipv4,
			self.mac
		)

# Read the arp table and return its content
def arpFind():
	# Execute os arp to find known devices
	proc = subprocess.Popen('arp -a', shell=True, stdout=subprocess.PIPE)
	hosts = []
	for line in proc.stdout:
		items = line.split()

		if len(items) == 3 and items[2].startswith('dyn'):
			hosts.append( items )

	proc.wait()
	return hosts

# Drop the arp table
def arpDrop():
	if DROP:
		log("Dropping ARP table...")
		# Need admin rights to drop table
		os.system('arp -d')
		# log("ARP table dropped.")

# Compare current and past host to detect an arp spoof attack
def inspect(gateway, hosts, pHosts):
	suspicious = False
	suspect = Suspect()

	# Detect a change in the gateway's mac
	if len(pHosts) > 0:
		pGateway = pHosts[0]
		if (gateway.ipv4 == pGateway.ipv4) and (gateway.mac != pGateway.mac):
			suspicious = True
			suspect.mac = gateway.mac

	# Find a device thats has the same mac as our gateway
	for host in hosts[1:]: # Skip first
		if host.mac == gateway.mac:
			suspicious = True
			suspect.ipv4 = host.ipv4
			suspect.mac = host.mac

	return (suspicious, suspect)

def log(string):
	print string
	if LOG:
		logging.info("[{}] - {}".format(datetime.datetime.now(), string))

if __name__ == "__main__":
	# Script only runs on windows
	if os.name != "nt":
		sys.exit();

	parser = argparse.ArgumentParser()
	parser.add_argument("-l", "--log", nargs='?', default="none", help="log events to a file")
	parser.add_argument("-d", "--drop", action='store_true', help="drop ARP table when an attack is suspected")
	args = parser.parse_args()

	if args.log != 'none':
		logging.basicConfig(filename=args.log, level=logging.DEBUG)
		LOG = True
	if args.drop:
		DROP = True

	hosts = []
	pHosts = [] # Previous hosts

	log("ARP spoofing detection running...")
	try:
	    while True:
			hosts = [Host(x) for x in arpFind()]

			# TODO more stable
			gateway = hosts[0]
			suspicious, suspect = inspect(gateway, hosts, pHosts)

			pHosts = hosts

			# If we consider the arp table to have been altered
			# we drop it so it gets rebuilt
			if suspicious:
				log("ARP spoofing detected\nSuspect = {}".format(suspect.toString()))
				arpDrop()
				pHosts = []

			time.sleep(INSPECT_INTERVAL)

	except KeyboardInterrupt:
	    pass

	log("ARP spoofing detection stopped.")
	