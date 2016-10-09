#!/usr/bin/python
# CS 4404 final project
# Devon Coleman, Kyle McCormick, Christopher Navarro, William Van Rensselaer

import subprocess

from shared_constants import *

def main():
    for i in range(0, NUM_CLIENTS):
        addr = ADDR_PREFIX + `START_CLIENT_IP + i`
        subprocess.call(["ifconfig", "eth0:"+`i`, addr])

main()

