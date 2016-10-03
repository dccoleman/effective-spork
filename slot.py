from constants import *

class slot:
	def __init__(self, interface, ip, client):
		temptimeout = datetime.datetime.now()
		self.timeout = (temptimeout + datetime.timedelta(0,ttl))
		self.interface = interface		
		self.ip = ip
		self.client = client
		
	def setTimeout(self):
		temptimeout = datetime.datetime.now()
		self.timeout = (temptimeout + datetime.timedelta(0,ttl))
