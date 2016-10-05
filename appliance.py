
from dnslib import DNSRecord
from netfilterqueue import NetfilterQueue
import socket
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import threading
import datetime
from dnslib import DNSRecord
import dns.zone

NUM_SLOTS = 2
TTL_SECS = 20
ADDR_PREFIX = "10.4.12."
HONEYPOT_ADDR = ADDR_PREFIX + "4" #the honeypot's address
WEB_SERVER_ADDR = ADDR_PREFIX + "3" 
CLIENT_ADDR = ADDR_PREFIX + "1"
NET_INTERFACE = "eth0"

mapped = Queue.Queue()
unmapped = Queue.Queue()
mapped_clients = {}
quitting = False


class Slot(object):
    def __init__(self, interface, ip, client):
        temptimeout = datetime.datetime.now()
        self.timeout = (temptimeout + datetime.timedelta(0, TTL_SECS))
        self.interface = interface      
        self.ip = ip
        self.client = client
        
    def set_timeout(self):
        temptimeout = datetime.datetime.now()
        self.timeout = (temptimeout + datetime.timedelta(0, TTL_SECS))


def map_server(client):
    if(unmapped.empty()):
        return None
    else:
        bucket = unmapped.get()     
        bucket.client = client

        mapped_clients[client] = ADDR_PREFIX + str(bucket.ip)

        #put rules in place for server mapping
        subprocess.call(["iptables", "-t", "nat", "-I", "PREROUTING", "-s", client, "-d", ADDR_PREFIX + str(bucket.ip), "-j", "DNAT", "--to-destination", WEB_SERVER_ADDR])
        subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", WEB_SERVER_ADDR, "-d", client, "-j", "SNAT", "--to-source", ADDR_PREFIX + str(bucket.ip)])

        bucket.set_timeout()
        mapped.put(bucket)
        print "Capability acquired by " + bucket.client
        return bucket

def map_honeypot(bucket):
        #map to the honeypot
        #after prerouting: , "-d", ADDR_PREFIX + str(bucket.ip)  
        subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-d", ADDR_PREFIX + str(bucket.ip), "-j", "DNAT", "--to-destination", HONEYPOT_ADDR])
        subprocess.call(["iptables", "-t", "nat", "-I", "POSTROUTING", "-s", HONEYPOT_ADDR, "-j", "SNAT", "--to-source", ADDR_PREFIX + str(bucket.ip)])
        unmapped.put(bucket)


def unmap_server(bucket):
        subprocess.call(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", bucket.client, "-d", ADDR_PREFIX + str(bucket.ip), "-j", "DNAT", "--to-destination", WEB_SERVER_ADDR])
        subprocess.call(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", WEB_SERVER_ADDR, "-d", bucket.client, "-j", "SNAT", "--to-source", ADDR_PREFIX + str(bucket.ip)])
        
        del mapped_clients[bucket.client]

        unmapped.put(bucket)

        print "Capability timeout for " + bucket.client


def timeout_thread_runner():
    while not quitting:
        if(mapped.empty()):
            #print "nothing"
            time.sleep(.2)
            continue
        else:
            currtime = datetime.datetime.now()
            if(currtime >= mapped.queue[0].timeout):
                obj2 = mapped.get()
                unmap_server(obj2)
                continue

            diff = (mapped.queue[0].timeout - currtime).seconds
            if(diff >= .1):
                print "Next capability expires in " + str(diff) + " seconds"
                time.sleep((mapped.queue[0].timeout - currtime).seconds)
                continue


def on_packet_received(pkt):
    d = IP(pkt.get_payload())

    if(d['DNS Question Record'].qname == "www.cap.com."):
        client_IP = d[IP].src

        if client_IP in mapped_clients:
            modify_dns(mapped_clients[client_IP])

        else:
            res = map_server(client_IP)

            if(res == None):
                print "All slots full! Can't make mapping"
                pkt.drop()
                #drop connection, all slots used up
            else:
                modify_dns(ADDR_PREFIX + str(res.ip))

        pkt.accept()
    else:
        pkt.accept()

def modify_dns(new_IP):
    domain = "cap.com"
    zoneFile = "/etc/bind/zones/db.cap.com"

    zone = dns.zone.from_file(zoneFile, domain)
    for (name, ttl, rdata) in zone.iterate_rdatas('SOA'):
        serial = rdata.serial + 1
        rdata.serial = serial

        change = "www"
        rdataset = zone.find_rdataset(change, rdtype='A')

        for rdata in rdataset:
            rdata.address = new_IP

        zone.to_file(zoneFile)

        subprocess.call(["rndc", "reload", "cap.com"])
        print "DNS zone modification complete"
        

def setup(num_slots):
    subprocess.call(["iptables", "-t", "nat", "-F"])
    subprocess.call(["iptables", "-F"])
    for i in range(0, num_slots):
        mapping = Slot(i, i + 50, CLIENT_ADDR)
        subprocess.call(["ifconfig", NET_INTERFACE + ":" + str(i), ADDR_PREFIX + str(i + 50)])
        print "Interface " + NET_INTERFACE + ":" + str(i) + " created with IP " + ADDR_PREFIX + str(i + 50)
        map_honeypot(mapping)

    subprocess.call(["iptables", "-t", "nat", "-I", "POSTROUTING", "-o", NET_INTERFACE, "-j", "MASQUERADE"])
    subprocess.call(["ifconfig", NET_INTERFACE + ":255", ADDR_PREFIX + "255"])
    subprocess.call(["iptables", "-I", "INPUT", "-d", ADDR_PREFIX  + "255", "-j", "NFQUEUE", "--queue-num", "1"])


def main():
    global quitting

    setup(NUM_SLOTS)

    timeout_thread = threading.Thread(target = timeout_thread_runner)
    timeout_thread.daemon = True
    timeout_thread.start()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, on_packet_received)
    s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        nfqueue.run_socket(s)
    except KeyboardInterrupt:
        print('')

    quitting = True
    s.close()
    nfqueue.unbind()


main()
