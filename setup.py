from constants import *

def setup(num):
	subprocess.call(["iptables", "-t", "nat", "-F"])
	for i in xrange(0,num):
		mapping = slot(i,i+50,"10.4.12.1")
		subprocess.call(["ifconfig", iface + ":" + str(i), prefix + str(i + 50)])
		map_honeypot(mapping)
	subprocess.call(["iptables", "-t", "nat", "-I", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])