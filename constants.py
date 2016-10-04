import Queue
import subprocess
import datetime
import time

log = 5
slots = 100
ttl = 120 #time to live in seconds
honeypot = "10.4.12.4" #the honeypot's address
server = "10.4.12.3" 
prefix = "10.4.12."
client = "10.4.12.1"
iface = "eth0"

mapped = Queue.PriorityQueue()
unmapped = Queue.Queue()
