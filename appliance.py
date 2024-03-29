#!/usr/bin/python
# CS 4404 final project
# Devon Coleman, Kyle McCormick, Christopher Navarro, William Van Rensselaer

import datetime
import dns.zone
from dnslib import DNSRecord
import logging
from netfilterqueue import NetfilterQueue
import socket
from scapy.all import *
from subprocess import Popen, PIPE
import threading

from shared_constants import *


NET_INTERFACE = "eth0"
NUM_SLOTS = 100
TTL_SECS = 20

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
        self.type = 0
        
    def set_timeout(self):
        temptimeout = datetime.datetime.now()
        self.timeout = (temptimeout + datetime.timedelta(0, TTL_SECS))


def honeypot_thread_runner():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(('0.0.0.0', APP_HONEYPOT_PORT))
    server_sock.listen(5)
    server_sock.setblocking(1)

    while not quitting:
        try:
            client_sock, (client_addr, _) = server_sock.accept()
        except:
            time.sleep(0.1)
            continue
        if client_addr != HONEYPOT_ADDR:
            continue

        bytes = client_sock.recv(512)
        port = bytes
        #print "Honeypot requesting capability for user on port " + `port`
        ip = nat_lookup(port)
        if ip:
	        map_honeypot_client(ip)   
    
    
def nat_lookup(port):
    ip = None

    proc = Popen(["conntrack", "-L", "-p", "tcp", "--sport", str(port)], stdout = PIPE, stderr = PIPE)
    out, err = proc.communicate()
    #print out
    #print err
    splits = out.split()
    #print splits
    if not splits:
        print "Error: No connection found using port " + str(port)
    else:
        ip = splits[4].split("=")[1]
        #Print "Port " + str(port) + " resolves to " + str(ip)

    return ip

def map_honeypot_client(client):
    if(unmapped.empty()):
        return None
    elif client in mapped_clients:
        return None
    else:
        bucket = unmapped.get()     
        bucket.client = client
        bucket.type = 1

        mapped_clients[client] = ADDR_PREFIX + str(bucket.ip)

        #put rules in place for server mapping
        #"-d", ADDR_PREFIX + str(bucket.ip),
        #"-d", client,
        iptables_cmd(["-t", "nat", "-I", "PREROUTING", "-p", "tcp", "-s", client, "-m", "iprange", "--dst-range", "10.4.12.50-10.4.12.149", "-j", "DNAT", "--to-destination", WEB_SERVER_ADDR])
        iptables_cmd(["-t", "nat", "-A", "POSTROUTING", "-p", "tcp", "-s", WEB_SERVER_ADDR, "-m", "iprange", "--dst-range", "10.4.12.50-10.4.12.149", "-j", "SNAT", "--to-source", ADDR_PREFIX + str(bucket.ip)])

        bucket.set_timeout()
        mapped.put(bucket)
        #print "Global capability acquired by " + bucket.client
        return bucket

def map_server(client):
    if(unmapped.empty()):
        return None
    elif client in mapped_clients:
        return None
    else:
        bucket = unmapped.get()     
        bucket.client = client

        mapped_clients[client] = ADDR_PREFIX + str(bucket.ip)

        #put rules in place for server mapping
        iptables_cmd(["-t", "nat", "-I", "PREROUTING", "-p", "tcp", "-s", client, "-d", ADDR_PREFIX + str(bucket.ip), "-j", "DNAT", "--to-destination", WEB_SERVER_ADDR])
        iptables_cmd(["-t", "nat", "-A", "POSTROUTING", "-p", "tcp", "-s", WEB_SERVER_ADDR, "-d", client, "-j", "SNAT", "--to-source", ADDR_PREFIX + str(bucket.ip)])

        bucket.set_timeout()
        mapped.put(bucket)
        #print "Capability acquired by " + bucket.client
        return bucket

def map_honeypot(bucket):
        #map to the honeypot
        #after prerouting: , "-d", ADDR_PREFIX + str(bucket.ip)  
        iptables_cmd(["-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-d", ADDR_PREFIX + str(bucket.ip), "-j", "DNAT", "--to-destination", HONEYPOT_ADDR])
        iptables_cmd(["-t", "nat", "-I", "POSTROUTING", "-p", "tcp", "-s", HONEYPOT_ADDR, "-j", "SNAT", "--to-source", ADDR_PREFIX + str(bucket.ip)])
        unmapped.put(bucket)


def unmap_server(bucket):

        if bucket.type == 0:
            iptables_cmd(["-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-s", bucket.client, "-d", ADDR_PREFIX + str(bucket.ip), "-j", "DNAT", "--to-destination", WEB_SERVER_ADDR])
            iptables_cmd(["-t", "nat", "-D", "POSTROUTING", "-p", "tcp", "-s", WEB_SERVER_ADDR, "-d", bucket.client, "-j", "SNAT", "--to-source", ADDR_PREFIX + str(bucket.ip)])
        else:
            iptables_cmd(["-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-s", bucket.client, "-m", "iprange", "--dst-range", "10.4.12.50-10.4.12.149", "-j", "DNAT", "--to-destination", WEB_SERVER_ADDR])
            iptables_cmd(["-t", "nat", "-D", "POSTROUTING", "-p", "tcp", "-s", WEB_SERVER_ADDR, "-m", "iprange", "--dst-range", "10.4.12.50-10.4.12.149", "-j", "SNAT", "--to-source", ADDR_PREFIX + str(bucket.ip)])
            bucket.type = 0

        del mapped_clients[bucket.client]

        unmapped.put(bucket)

        #print "Capability timeout for " + bucket.client


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
                #print "Next capability expires in " + str(diff) + " seconds"
                time.sleep((mapped.queue[0].timeout - currtime).seconds)
                continue


def on_packet_received(pkt):
    d = IP(pkt.get_payload())

    if(d['DNS Question Record'].qname == "www.cap.com."):
        client_IP = d[IP].src
        #print "DNS request sent for " + client_IP

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

        #Print "Accepted"
        pkt.accept()
    else:
        #print "Accepted"
        pkt.accept()

def modify_dns(new_IP):
    domain = "cap.com"
    zoneFile = "/etc/bind/zones/db.cap.com"

    zone = dns.zone.from_file(zoneFile, domain)

    change = "www"
    rdataset = zone.find_rdataset(change, rdtype='A')

    req_reload = False

    for rdata in rdataset:
        if rdata.address != new_IP:
            req_reload = True
            rdata.address = new_IP

    if req_reload:
        for (name, ttl, rdata) in zone.iterate_rdatas('SOA'):
            serial = rdata.serial + 1
            rdata.serial = serial

        zone.to_file(zoneFile)

        proc = Popen(["rndc", "reload", "cap.com"], stdout = PIPE, stderr = PIPE)
        out,err = proc.communicate()
        if err:
            print err
        else:
            pass
            #print "DNS zone modification complete"
    else:
        pass
        #print "No DNS modification necessary"

iptables_locked = False

def iptables_cmd(args):
    global iptables_locked
    while iptables_locked:
        time.sleep(0.02)
    iptables_locked = True
    subprocess.call(["iptables"] + args)
    iptables_locked = False
    return None

def setup(num_slots):
    iptables_cmd(["-t", "nat", "-F"])
    iptables_cmd(["-F"])
    for i in range(0, num_slots):
        mapping = Slot(i, i + 50, CLIENT_ADDR)
        subprocess.call(["ifconfig", NET_INTERFACE + ":" + str(i), ADDR_PREFIX + str(i + 50)])
        #print "Interface " + NET_INTERFACE + ":" + str(i) + " created with IP " + ADDR_PREFIX + str(i + 50)
        map_honeypot(mapping)

    iptables_cmd(["-t", "nat", "-I", "POSTROUTING", "-o", NET_INTERFACE, "-j", "MASQUERADE"])
    subprocess.call(["ifconfig", NET_INTERFACE + ":255", ADDR_PREFIX + "255"])
    iptables_cmd(["-I", "INPUT", "-p", "udp", "-d", ADDR_PREFIX  + "255", "-j", "NFQUEUE", "--queue-num", "1"])


def main():
    global quitting

    setup(NUM_SLOTS)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    timeout_thread = threading.Thread(target=timeout_thread_runner)
    timeout_thread.daemon = True
    timeout_thread.start()

    honeypot_thread = threading.Thread(target=honeypot_thread_runner)
    honeypot_thread.daemon = True
    honeypot_thread.start()

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
