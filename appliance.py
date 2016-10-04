from netfilterqueue import NetfilterQueue
from dnslib import DNSRecord

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

	if(d['DNS Question Record'].qname != "cap.com."):
		pkt.accept()
	else:	
		print "Found cap.com!"
		print d.summary()
		print d[IP].src

		#modify dns zone file

		if(map_server(d[IP].src) == None):
			pkt.reject()
			#drop connection, all slots used up


		#print ' '.join(c.encode('hex') for c in pkt.get_payload()[0:20])
		pkt.accept()

t = threading.Thread(target = timeout_mappings)
t.daemon = True
t.start()

subprocess.call(["iptables", "-t", "nat", "-F"])
for i in xrange(0,slots):
	mapping = slot(i,i+50,"10.4.12.1")
	subprocess.call(["ifconfig", iface + ":" + str(i), prefix + str(i + 50)])
	map_honeypot(mapping)

subprocess.call(["iptables", "-t", "nat", "-I", "POSTROUTING", "-o", iface, "-d", server, "-j", "MASQUERADE"])
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