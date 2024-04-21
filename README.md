# Port Scanner and Intrusion Detection

## PortScanner.py
A port scanner that can probe all TCP ports on a targeted host and report the ports that accept connections.

## PSDetector.py
A port scanner detector that can listen to incoming connections and report the presence of a scanner if a single machine attempts to connect to 15 or more consecutive ports within a 5 minute window.

## PortScanner2.py
A modified version of PortScanner designed to evade PSDetector. 