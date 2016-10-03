from constants import *

from slot import slot
from map_honeypot import map_honeypot
from map_server import map_server

def setup(num):
	for i in xrange(0,num):
		mapping = slot(i,i+50,"10.4.12.1")
		subprocess.call(["sudo", "ifconfig", "enp0s3:" + str(i), prefix + str(i + 50)])
		map_honeypot(mapping)
	subprocess.call(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "enp0s3", "-j", "MASQUERADE"])

#script

setup(2)

#obj = map_server()
#print "mapped " + prefix + str(obj.ip) + " to server"

while not mapped.empty():
	currtime = datetime.datetime.now()
	if(currtime >= mapped.queue[0].timeout):
		obj2 = mapped.get()
		map_honeypot(obj2)
		print "mapping to honeypot completed"



