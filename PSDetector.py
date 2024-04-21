import sys
import time
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

hostlist = []
detected_scanners = []
file = open('detector.txt', 'wb')

class Host:
    def __init__(self, host):
        self.ip = host
        self.portlist = []

def tcp_monitor_callback(pkt):
    if IP in pkt and TCP in pkt:
        # get the source ip, destination port, and time
        ip_src=pkt[IP].src
        tcp_dport=pkt[TCP].dport
        conn_time = time.time()
        
        # filter SYN messages
        if pkt[TCP].flags == 'S':
            #print(" IP src " + str(ip_src) + " TCP sport " + str(tcp_sport))
            #print(" IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport))
            #print(" IP src " + str(ip_src) + " TCP dport " + str(tcp_dport))

            # check if ip is a new host
            host = None
            for h in hostlist:
                if h.ip == ip_src:
                    host = h

            if host is None:
                host = Host(ip_src)
                hostlist.append(host)

            # add port to host's port list
            host.portlist.append((tcp_dport, conn_time))

            # check if the host is scanning ports
            detect_scanner()
            
def detect_scanner():
    for host in hostlist:
                
        if host.ip not in detected_scanners:
            count = 0
            scanning = False
            init_conn_time = host.portlist[0][1]

            for i in range(1, len(host.portlist)):
                #print('[i]: ' + str(host.portlist[i]))
                #print('[i - 1]: ' + str(host.portlist[i-1]))
                #print('[i - 1]+1: ' + str(host.portlist[i-1]+1))

                count += 1
                
                # check for 15 consecutive connections in 5 minutes
                if host.portlist[i][0] != host.portlist[i-1][0] + 1:
                    count = 0
                    init_conn_time = host.portlist[i][1]
                if count == 15 and (host.portlist[i][1] - init_conn_time)/60 <= 5:
                    scanning = True

                #print('scanning: ' + str(scanning))

            if scanning:
                detected_scanners.append(host.ip)
                file.write(b'Scanner detected. The scanner originated from host ' + (host.ip).encode('utf-8') + b'\n')
                    
if __name__ == '__main__':
    try:
        sniff(iface="lo0", prn=tcp_monitor_callback, store=0)
    except KeyboardInterrupt:
        sys.exit(1)
