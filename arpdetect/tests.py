#!/usr/bin/python
import sys
import os
import arpdetect

def test(result):
	print ("Success" if result else "Fail")

# Not suspicious ARP table
def test1():
	pHosts = [
		arpdetect.Host(["192.168.1.1", 		"00-00-00-00-00-00", "dynamique"]),
		arpdetect.Host(["192.168.1.101", 	"11-11-11-11-11-11", "dynamique"]),
		arpdetect.Host(["192.168.1.102", 	"22-22-22-22-22-22", "dynamique"]),
	]
	hosts = pHosts
	suspicious, suspect = arpdetect.inspect(hosts[0], hosts, pHosts)
	return not suspicious

# Suspicious as Gateway changed MAC
def test2():
	pHosts = [
		arpdetect.Host(["192.168.1.1", 		"00-00-00-00-00-00", "dynamique"]),
		arpdetect.Host(["192.168.1.101", 	"11-11-11-11-11-11", "dynamique"]),
		arpdetect.Host(["192.168.1.102", 	"22-22-22-22-22-22", "dynamique"]),
	]
	hosts = [
		arpdetect.Host(["192.168.1.1", 		"55-55-55-55-55-55", "dynamique"]),
		arpdetect.Host(["192.168.1.101",	"11-11-11-11-11-11", "dynamique"]),
		arpdetect.Host(["192.168.1.102",	"22-22-22-22-22-22", "dynamique"]),
	]
	suspicious, suspect = arpdetect.inspect(hosts[0], hosts, pHosts)
	return suspicious and suspect.mac == "55-55-55-55-55-55" and suspect.ipv4 == "Unknown"

# Suspicious as Gateway changed MAC, also suspecr ip is known
def test3():
	pHosts = [
		arpdetect.Host(["192.168.1.1", 		"00-00-00-00-00-00", "dynamique"]),
		arpdetect.Host(["192.168.1.101", 	"11-11-11-11-11-11", "dynamique"]),
		arpdetect.Host(["192.168.1.102", 	"22-22-22-22-22-22", "dynamique"]),
	]
	hosts = [
		arpdetect.Host(["192.168.1.1", 		"22-22-22-22-22-22", "dynamique"]),
		arpdetect.Host(["192.168.1.101",	"11-11-11-11-11-11", "dynamique"]),
		arpdetect.Host(["192.168.1.102",	"22-22-22-22-22-22", "dynamique"]),
	]
	suspicious, suspect = arpdetect.inspect(hosts[0], hosts, pHosts)
	return suspicious and suspect.mac == "22-22-22-22-22-22" and suspect.ipv4 == "192.168.1.102"

if __name__ == "__main__":
	# Script only runs on windows
	if os.name != "nt":
		sys.exit();

	# Test 1
	test(test1())
	test(test2())
	test(test3())