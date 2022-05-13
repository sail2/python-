import os
from pip import main

def Ddos_query():
    # 查看当前SYNC_REC连接数量
    rec_counts = os.popen('netstat -np | grep SYN_REC | wc -l').read()
    # CPU在1分钟内的平均负载
    Cpu = os.popen("uptime | awk -F ': ' '{print $2}' | awk -F ',' '{print $1}'").read()
    # 查看每个ip跟服务器建立的连接数
    # 显示第5列,-F : 以：分割，显示列，sort 排序，uniq -c统计排序过程中的重复行，sort -rn 按纯数字进行逆序排序
    ip = os.popen(
        "netstat -nat|awk '{print$5}'|awk -F : '{print$1}'|uniq -c|sort -k 1 -r |awk 'NR==1''{print $2}'").read()
    print(ip)
    while True:
        print(f"TCP连接数:{int(counts)},CPU平均负载{float(Cpu)}")
        if int(counts) > 300 and float(Cpu) > 2.0:
            print("TCP连接过多，CPU超过2.0,疑似有DDos攻击")
            denfes = os.popen(f'firewall-cmd --add-rich-rule="rule family=ipv4 source address={ip} drop" ').read()
            if denfes.strip() == "success":
                os.popen(f'service restart httpd ')
                print(f"{ip} IP已经封禁。")
            else:
                print(f"{ip} 没有封禁成功！")


if __name__ == '__main__':
    Ddos_query()




