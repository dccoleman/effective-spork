import Queue
import subprocess
import datetime
import time

log = 5
slots = 2
ttl = 20 #time to live in seconds
honeypot = "10.4.12.4" #the honeypot's address
server = "10.4.12.3" 
prefix = "10.4.12."
client = "10.4.12.1"
iface = "eth0"

mapped = Queue.Queue()
unmapped = Queue.Queue()

mapped_clients = {}
