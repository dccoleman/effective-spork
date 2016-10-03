from constants import *

def map_server():
	if(unmapped.empty()):
		return None
	else:
		bucket = unmapped.get()
		#remove rules created for the honeypot mapping
		subprocess.call(["sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-d", prefix + str(bucket.ip), "-j", "DNAT", "--to-destination", honeypot])
		subprocess.call(["sudo", "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", honeypot, "-j", "SNAT", "--to-source", prefix + str(bucket.ip)])
		
		#put rules in place for server mapping
		subprocess.call(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-d", prefix + str(bucket.ip), "-j", "DNAT", "--to-destination", server])
		subprocess.call(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", server, "-j", "SNAT", "--to-source", prefix + str(bucket.ip)])

		bucket.setTimeout()
		mapped.put(bucket)
		return bucket
