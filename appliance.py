import subprocess
import datetime
import Queue
import time
import threading

ttl = 2 #time to live in seconds
honeypot = "10.44.12.1" #the honeypot's address
server = "10.44.12.2" 
prefix = "10.44.12."

mapped = Queue.Queue()
unmapped = Queue.Queue()

class slot:
	def __init__(self, interface, ip_addr):
		temptimeout = datetime.datetime.now()
		self.timeout = (temptimeout + datetime.timedelta(0,ttl))
		self.interface = interface		
		self.ip = ip_addr
		
	def setTimeout(self):
		temptimeout = datetime.datetime.now()
		self.timeout = (temptimeout + datetime.timedelta(0,ttl))

def setup(num):
	subprocess.call(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])

	for i in xrange(0,num):
		test = slot(i,i+50)
		map_honeypot(test)
		subprocess.call(["sudo", "ifconfig", "enp0s3:" + str(i), "10.44.13." + str(i + 50)])

def map_honeypot(bucket):
		subprocess.call(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-d", prefix + str(bucket.ip), "-j", "DNAT", "--to-destination", honeypot]) #map to honeypot
		subprocess.call(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", honeypot, "-j", "SNAT", "--to-source", prefix + str(bucket.ip)]) #map honeypot back to source IP (could conflict with multiple mappings?)
		unmapped.put(bucket)

def map_server():
	if(unmapped.empty()):
		return None
	else:
		bucket = unmapped.get()
		subprocess.call(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-d", prefix + str(bucket.ip), "-j", "DNAT", "--to-destination", honeypot]) #map to honeypot
		subprocess.call(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", server, "-j", "SNAT", "--to-source", prefix + str(bucket.ip)])
		bucket.setTimeout()
		print "mapped " + prefix + str(bucket.ip)
		mapped.put(bucket)
		return bucket

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
				map_honeypot(obj2)
				#unmap from server
				print "unmapped " + prefix + str(obj2.ip)
				continue

			diff = (mapped.queue[0].timeout - currtime).seconds
			if(diff >= .1):
				print "waiting " + str(diff)
				time.sleep((mapped.queue[0].timeout - currtime).seconds)
				continue
	print "ending thread"


#script

setup(3)

t = threading.Thread(target = timeout_mappings)
t.daemon = True
t.start()

map_server()
time.sleep(5)
map_server()
map_server()

time.sleep(999999999)

