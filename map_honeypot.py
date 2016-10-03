from constants import *

def map_honeypot(bucket):
		#remove mappings to the server (might throw error the first time around, not an issue)
		subprocess.call(["sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-d", prefix + str(bucket.ip), "-j", "DNAT", "--to-destination", server])
		subprocess.call(["sudo", "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", server, "-j", "SNAT", "--to-source", prefix + str(bucket.ip)])

		#map to the honeypot		
		subprocess.call(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-d", prefix + str(bucket.ip), "-j", "DNAT", "--to-destination", honeypot])
		subprocess.call(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", honeypot, "-j", "SNAT", "--to-source", prefix + str(bucket.ip)])
		unmapped.put(bucket)
