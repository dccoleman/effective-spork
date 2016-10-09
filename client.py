#!/usr/bin/python
# CS 4404 final project
# Devon Coleman, Kyle McCormick, Christopher Navarro, William Van Rensselaer

import subprocess
import threading
import time

from shared_constants import *

CLIENT_COUNTS = [1, 5, 15, 50, 100]
TRIALS_PER_COUNT = 10

response_count = None
response_times = None

def thread_runner(addr):
    global response_count
    global response_times

    APP_ADDR = "8.8.8.8"
    proc = subprocess.Popen(["dig", "-b", addr, "@" + APP_ADDR, "www.cap.com"], stdout=subprocess.PIPE)
    proc.wait()
    output = proc.stdout.read()
    try:
        i = output.index("Query time: ")
    except ValueError:
        response_times[addr] = None
        return
    ln = len("Query time: ")
    time_str = output[i+ln:i+ln+10].split(' ')[0]
    secs = int(time_str) / 1000.0
    response_times[addr] = secs 
    response_count += 1

def main(): 
    global response_count
    global response_times

    for client_count in CLIENT_COUNTS:
        print "\n"
        print "Testing with " + `client_count` + " clients"
        average_sum = 0
        for trial in range(0, TRIALS_PER_COUNT):
            print "  Trial #" + `trial`
            response_count = 0
            response_times = {}
            for i in range(0, client_count):
                addr = ADDR_PREFIX + `START_CLIENT_IP + i`
                threading.Thread(target=thread_runner, args=(addr,)).start()
            while response_count < client_count:
                time.sleep(0.1)
            times = [t for _, t in response_times.iteritems() if t is not None]
            avg = sum(times) / len(times)
            print "    Average response time: " + `avg` + " s"
            average_sum += avg
        print "  Overall average response time: " + `average_sum / TRIALS_PER_COUNT` + " s"

main()
