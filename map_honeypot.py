from constants import *

def map_honeypot(bucket):
		#map to the honeypot		
		subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-d", prefix + str(bucket.ip), "-j", "DNAT", "--to-destination", honeypot])
		subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", honeypot, "-j", "SNAT", "--to-source", prefix + str(bucket.ip)])
		unmapped.put(bucket)

def unmap_server(bucket):
		subprocess.call(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", bucket.client, "-d", prefix + str(bucket.ip), "-j", "DNAT", "--to-destination", server])
		subprocess.call(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", server, "-d", bucket.client, "-j", "SNAT", "--to-source", prefix + str(bucket.ip)])
		unmapped.put(bucket)