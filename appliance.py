from netfilterqueue import NetfilterQueue
from dnslib import DNSRecord
import dns.zone

import socket
import threading

from scapy.all import *

from constants import *
from map_honeypot import *
from map_server import map_server

from slot import slot

def timeout_mappings():
	print "starting thread"
	while True:
		if(mapped.empty()):
			#print "nothing"
			time.sleep(.2)
			continue
		else:
			currtime = datetime.datetime.now()
			if(currtime >= mapped.queue[0].timeout):
				obj2 = mapped.get()
				unmap_server(obj2)
				#unmap from server
				print "unmapped " + prefix + str(obj2.ip)
				continue

			diff = (mapped.queue[0].timeout - currtime).seconds
			if(diff >= .1):
				print "waiting " + str(diff)
				time.sleep((mapped.queue[0].timeout - currtime).seconds)
				continue
	print "ending thread"

def acceptAll(pkt) :
	d = IP(pkt.get_payload())

	print "'" + d['DNS Question Record'].qname + "'"
	print d[IP].src

	if(d['DNS Question Record'].qname != "www.cap.com."):
		pkt.accept()
	else:	
		print "Found www.cap.com!"
		print d.summary()
		client_IP = d[IP].src

		if client_IP in mapped_clients:
			modify_dns(mapped_clients[client_IP])

		else:
			#now we need to procure a new slot
			res = map_server(client_IP)

			if(res == None):
				print "No slots full! Can't make mapping"
				pkt.drop()
				#drop connection, all slots used up
			else:
				modify_dns(prefix + str(res.ip))

		pkt.accept()

def modify_dns(new_IP):
	domain = "cap.com"
	print "Getting zone object for domain " + domain
	zoneFile = "/etc/bind/zones/db.cap.com"

	zone = dns.zone.from_file(zoneFile, domain)
	for (name, ttl, rdata) in zone.iterate_rdatas('SOA'):
		serial = rdata.serial + 1
		rdata.serial = serial
		print "Changing serial to ", serial

		change = "www"
		rdataset = zone.find_rdataset(change, rdtype='A')

		for rdata in rdataset:
			rdata.address = new_IP

		print "Changed IP to ", rdata.address

		print "Writing zone file"
		zone.to_file(zoneFile)

		print "reloading zone file"
		subprocess.call(["rndc", "reload", "cap.com"])
		print "reloading file finished"



#script

t = threading.Thread(target = timeout_mappings)
t.daemon = True
t.start()

subprocess.call(["iptables", "-t", "nat", "-F"])
for i in xrange(0,slots):
	mapping = slot(i,i+50,"10.4.12.1")
	subprocess.call(["ifconfig", iface + ":" + str(i), prefix + str(i + 50)])
	map_honeypot(mapping)

# "-d", server,
subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
subprocess.call(["ifconfig", iface + ":255", prefix + "255"])
subprocess.call(["iptables", "-I", "INPUT", "-d", prefix+"255", "-j", "NFQUEUE", "--queue-num", "1"])

nfqueue = NetfilterQueue()
nfqueue.bind(1, acceptAll)
s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
try:
    nfqueue.run_socket(s)
except KeyboardInterrupt:
    print('')

s.close()
nfqueue.unbind()