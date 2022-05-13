from scapy.all import *
from scapy.layers.inet import IP, TCP
def tcp_connect():
    sport = random.randint(10000, 20000)
    print(sport)
    dport = 554
    dst = '124.223.22.108'
    src = '192.168.18.28'
    answer = sr1(IP(dst=dst,src=src)/TCP(sport=sport,dport=dport,seq=22567, flags="S"),timeout=4)
    seq = answer[TCP].ack
    ack = answer[TCP].seq + 1
    print(seq, ack)
    sr1(IP(dst=dst,src=src)/TCP(sport=sport,dport=dport,seq=seq,ack=ack,flags="A"),timeout=3)
    sr1(IP(dst=dst,src=src) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags="PA") / "11111")
tcp_connect()