import argparse
import socket
import time

PORTS = 65536

def scan(target):

    with open('scanner2.txt', 'wb') as scanner:
        
        # get start time
        start = time.time()
        
        # scan ports from 65535 to 0
        for port in reversed(range(0, PORTS)):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = s.connect_ex((target,port))
            
            if result == 0:
                # get the port service information
                try:
                    service = socket.getservbyport(port)
                except:
                    service = 'NA'
                
                output = '{0} ({1}) was open\n'.format(port, service)

                # write to file
                scanner.write(output.encode('utf-8'))

            # close socket
            s.close()
            
        # get end time
        end = time.time()

        # calculate execution time
        elapsed_time = end - start

        scanner.write(b'time elapsed = ' + str(elapsed_time).encode('utf-8') + b's\n')
        scanner.write(b'time per scan = ' + str(elapsed_time/PORTS).encode('utf-8') + b's\n')
                
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target')
    args = parser.parse_args()

    scan(args.target)
    
if __name__ == '__main__':
    main()
