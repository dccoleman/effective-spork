from constants import *

def map_server(client):
	if(unmapped.empty()):
		return None
	else:
		bucket = unmapped.get()		
		bucket.client = client

		mapped_clients[client] = prefix + str(bucket.ip)

		#put rules in place for server mapping
		subprocess.call(["iptables", "-t", "nat", "-I", "PREROUTING", "-s", client, "-d", prefix + str(bucket.ip), "-j", "DNAT", "--to-destination", server])
		subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", server, "-d", client, "-j", "SNAT", "--to-source", prefix + str(bucket.ip)])

		bucket.setTimeout()
		mapped.put(bucket)
		return bucket
