"""
--coding:utf-8--
@File: Ping.py
@Author:frank yu
@DateTime: 2020.12.13 10:35
@Contact: frankyu112058@gmail.com
@Description:Implement of Ping
"""
import random
import socket
import struct
import time


def checksum(msg):
    """
    :param msg:icmp message(bytes)
    :return:checksum(bytes)
    """
    check_sum = 0
    n = len(msg)

    def carry_around_add(a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)

    for i in range(0, n, 2):
        w = msg[i] + (msg[i + 1] << 8)
        check_sum = carry_around_add(check_sum, w)
    res = ~check_sum & 0xffff
    res = res >> 8 | (res << 8 & 0xff00)
    return res


def icmp_packet(sequence_number):
    """
    :param sequence_number:
    :return: binary of icmp packet
    """
    icmp_type = 8  # ICMP Echo Request
    icmp_code = 0  # zero
    icmp_checksum = 0  # set to zero first
    icmp_Identifier = 1  # Identifier
    icmp_Sequence_number = sequence_number
    icmp_Data = b'abcdefghijklmnopqrstuvwabcdefghi'  # data
    icmp_message = struct.pack('>2B3H32s', icmp_type, icmp_code, icmp_checksum, icmp_Identifier, icmp_Sequence_number,
                               icmp_Data)
    icmp_checksum = checksum(icmp_message)
    icmp_message = struct.pack('>2B3H32s', icmp_type, icmp_code, icmp_checksum, icmp_Identifier, icmp_Sequence_number,
                               icmp_Data)
    return icmp_message


def icmp_request(dst_addr, pkt, timeout=2):
    """
    send icmp packet and return socket for listening
    :param timeout: timeout
    :param dst_addr: ip of destination address
    :param pkt: packet of icmp
    :return: socket of icmp,time
    """
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_socket.settimeout(timeout)
    icmp_socket.sendto(pkt, (dst_addr, 80))
    send_time = time.time()
    return icmp_socket, send_time


def icmp_reply(icmp_socket, send_time, sequence_num):
    """
    monitor the icmp socket and return how much time spent if receives reply msg
    :param icmp_socket:socket which sent icmp msg before
    :param send_time: time when send icmp request
    :param sequence_num:sequence num
    :return:time and TTL/-1,-1
    """
    try:
        recv_pkt, addr = icmp_socket.recvfrom(1024)
        # print(recv_pkt)
        recv_time = time.time()
        icmpHeader = recv_pkt[20:28]
        type, _, _, _, sequence = struct.unpack(">2B3H", icmpHeader)
        if type == 0 and sequence == sequence_num:
            return recv_time - send_time, recv_pkt[8]
    except socket.timeout:
        return -1, -1


def ping(host):
    """
    :param host:domain name or ip addr
    :return: None
    """
    Sequence_number = random.randint(0, 10 ** 4)
    # ??????ip?????????????????????????????????ip
    try:
        dst_addr = socket.gethostbyname(host)
    except socket.gaierror:
        print(f'something wrong, please check your input.')
        exit(0)
    miss, short, long, alltime = 0, 10 ** 9, 0, []
    print(f"?????? Ping {host} [{dst_addr}] ?????? 32 ???????????????:")
    for i in range(0, 4):
        # ??????icmp?????????
        icmp_pkt = icmp_packet(Sequence_number + i)
        # print(icmp_pkt)
        # ?????????????????????
        icmp_socket, send_time = icmp_request(dst_addr, icmp_pkt)
        # ????????????????????????
        times, TTL = icmp_reply(icmp_socket, send_time, Sequence_number + i)
        if times >= 0:
            print(f"?????? {dst_addr} ?????????: ??????=32 ??????={int(times * 1000)}ms TTL={TTL}")
            if short > times:
                short = times
            if long < times:
                long = times
            alltime.append(times * 1000)
            time.sleep(1)
        else:
            print("???????????????")
            miss += 1
    print()
    print(f'{dst_addr} ??? Ping ????????????:\n'
          f'    ?????????: ????????? = 4???????????? = {4 - miss}????????? = {miss} ({int(miss / 4 * 100)}% ??????)???')
    if miss < 4:
        print('???????????????????????????(??????????????????):\n'
              f'    ?????? = {int(short * 1000)}ms????????? = {int(long * 1000)}ms????????? = {int(sum(alltime) / (4 - miss))}ms')
    return None


if __name__ == '__main__':
    host = input('please input domain name or ip addr:')
    ping(host)
