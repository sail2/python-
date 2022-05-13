# 利用python捕获流量
import re

from scapy.all import *
from scapy.layers.inet import TCP
from scapy.packet import Raw


def do_capture(flow):
    # try:
    #     req = flow[Raw].load.decode().split('\n')
    #     if re.match("or ", req[-1]):
    #        print("sql注入")
    #
    #     else:
    #         print(req[-1])
    #
    # except:
    #     pass
    print(flow.show())


if __name__ == '__main__':
    sniff(filter="tcp and port 80 and host 192.168.18.10", prn=lambda x: do_capture(x))
