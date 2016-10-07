#!/usr/bin/python
# CS 4404 final project
# Devon Coleman, Kyle McCormick, Christopher Navarro, William Van Rensselaer

import subprocess
import threading
import time

from shared_constants import *

CLIENT_COUNTS = [1, 5, 15, 50, 100]
START_IP_NUMBER = 150

response_count = None
response_times = None

def thread_runner(addr):
    print "Sending request from " + addr
    APP_ADDR = 8.8.8.8
    proc = subprocess.Popen(["dig", "-b", addr, "@" + APP_ADDR, "www.cap.com"])
    proc.wait()
    output = proc.stdout.read()
    i = output.index("Query time: ")
    ln = len("Query time: ")
    time_str = output[i+ln:i+ln+10].split(' ')[0]
    response_times[addr] = int(time_str) / 1000.0
    response_count += 1
    print "Received response for " + addr + " in " + elapsed + " s"

def main(): 
    global response_count
    global response_times

    for client_count in CLIENT_COUNTS:
        print "Testing with " + `client_count` + " clients"
        response_count = 0
        response_times = {}
        for i in range(0, client_count):
            addr = ADDR_PREFIX + `START_IP_NUMBER + i`
            threading.Thread(target=thread_runner, args=(addr,)).start()
        while response_count < client_count:
            time.sleep(0.1)
        summed_times = sum(time for _, time in response_times.iteritems())
        avg = summed_times
        print "Average time for " + `client_counts " clients: " + `avg` + " s"

main()
