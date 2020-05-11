#!/usr/bin/python
# coding=utf-8
import nmap
import datetime
import requests
import chardet
import re
import json
import os
import socket
from IPy import IP
from prettytable import PrettyTable
from threadPool import ThreadPool

requests.packages.urllib3.disable_warnings()
import sys

reload(sys)
sys.setdefaultencoding('utf8')

final_domains = []


# 调用masscan
def portscan():
    temp_ports = []  # 设定一个临时端口列表
    ports = []
    print '../masscan/bin/masscan -iL scan_ip.txt -p 1-65535 -oJ masscan.json --rate 2000'
    os.system('../masscan/bin/masscan -iL scan_ip.txt -p 1-65535 -oJ masscan.json --rate 2000')
    # 提取json文件中的端口
    with open('masscan.json', 'r') as f:
        for line in f:
            if line.startswith('{ '):
                temp = json.loads(line)
                temp1 = temp["ports"][0]
                ports.append(str(temp1["port"]) + '|' + temp["ip"])
    return ports


# 获取网站的web应用程序名和网站标题信息
def Title(scan_url_port, service_name):
    try:
        r = requests.get(scan_url_port, timeout=5, verify=False, stream=True)
        # 获取网站的页面编码
        if 'Content-Length' in r.headers.keys() and int(r.headers['Content-Length']) > 50000:  # 有些人特别坏访问端口让你下载个几g的文件
            final_domains.append('[*]主机 ' + scan_url_port + ' 端口服务为：' + service_name + '大文件')
        else:
            r_detectencode = chardet.detect(r.content)
            actual_encode = r_detectencode['encoding']
            response = re.findall(u'<title>(.*?)</title>', r.content, re.S)
            if response == []:
                final_domains.append(
                    scan_url_port + '\t \t' + "".join(service_name.split()) + '\t' + str(r.status_code) + '\t' + str(
                        len(r.content)))
            else:
                # 将页面解码为utf-8，获取中文标题
                res = response[0].decode(actual_encode).decode('utf-8')
                banner = r.headers['server']
                final_domains.append(
                    scan_url_port + '\t' + "".join(banner.split()) + '\t' + ''.join(res.split()) + '\t' + str(
                        r.status_code) + '\t' + str(len(r.content)))
    except Exception as e:
        pass
        # final_domains.append('[*]主机 ' + scan_url_port + ' 端口服务为：' + service_name + '无法访问')


# 调用nmap识别服务
def NmapScan(scan_ip_port, data):
    nm = nmap.PortScanner()
    try:
        scan_ip_port = scan_ip_port.split('|')
        ret = nm.scan(scan_ip_port[1], scan_ip_port[0], arguments='-Pn,-sS')
        service_name = ret['scan'][scan_ip_port[1]]['tcp'][int(scan_ip_port[0])]['name']
        print '[*]主机 ' + scan_ip_port[1] + ' 的 ' + str(scan_ip_port[0]) + ' 端口服务为：' + service_name
        if 'http' in service_name or service_name == 'sun-answerbook':
            if service_name == 'https' or service_name == 'https-alt':
                scan_url_port = 'https://' + scan_ip_port[1] + ':' + str(scan_ip_port[0])
                Title(scan_url_port, service_name)
            else:
                scan_url_port = 'http://' + scan_ip_port[1] + ':' + str(scan_ip_port[0])
                Title(scan_url_port, service_name)
        else:  # 唱跳rap和篮球C+V ,又是嫌弃速度慢了删除这
            scan_url_port = 'http://' + scan_ip_port[1] + ':' + str(scan_ip_port[0])  # <--
            Title(scan_url_port, service_name)  # <--
        final_domains.append(scan_ip_port[1] + ':' + str(scan_ip_port[0]) + '\t' + service_name)
    except Exception as e:
        print e
        pass


'''127.0.0.1-255,     127.0       127.0.0'''


def get_ip_list(ip):
    print ip
    ip_list_tmp = []

    def iptonum(x):
        return sum([256 ** j * int(i)
                    for j, i in enumerate(x.split('.')[::-1])])

    def numtoip(x):
        return '.'.join(
            [str(x / (256 ** i) % 256) for i in range(0, -1, -1)])

    if '-' in ip:
        ip_range = ip[ip.rfind('.') + 1:].split('-')
        ip_start = long(iptonum(ip_range[0]))
        ip_end = long(iptonum(ip_range[1]))
        ip_count = ip_end - ip_start
        if ip_count >= 0 and ip_count <= 255:
            for ip_num in range(ip_start, ip_end + 1):
                ip_list_tmp.append(ip[:ip.rfind('.')] + '.' + numtoip(ip_num))
        else:
            print 'IP format error' + ip
    elif '/' in ip:
        ip = IP(ip, make_net=1)  # 直接用库吧
        for i in ip:
            ip_list_tmp.append(i)
    else:
        ip_split = ip.split('.')
        net = len(ip_split)
        if net == 2:
            for b in range(1, 255):
                for c in range(1, 255):
                    ip = "%s.%s.%d.%d" % (ip_split[0], ip_split[1], b, c)
                    ip_list_tmp.append(ip)
        elif net == 3:
            for c in range(1, 255):
                ip = "%s.%s.%s.%d" % (
                    ip_split[0], ip_split[1], ip_split[2], c)
                ip_list_tmp.append(ip)
        elif net == 4:
            ip_list_tmp.append(ip)
        else:
            print "IP format error" + ip
    return ip_list_tmp


def main():
    try:
        f = open(r'ip.txt', 'rb')
        ip = ''
        for line in f.readlines():
            final_ip = line.strip('\n')
            for i in get_ip_list(final_ip):
                print i
                ip += str(i).strip() + '\n'
        with open(r'scan_ip.txt', 'w') as ff:
            ff.write(ip)
        data = []
        items = portscan()  # 进行masscan跑端口
        dataList = {}

        for i in items:
            i = i.split('|')
            if i[1] not in dataList:
                dataList[str(i[1])] = []
            dataList[str(i[1])].append(i[0])
        for i in dataList:
            if len(dataList[i]) >= 50:
                for port in dataList[i]:
                    items.remove(str(port) + '|' + str(i))  # 删除超过50个端口的
        pool = ThreadPool(20, 1000)
        pool.start(NmapScan, items, data, )
    except Exception as e:
        print e
        print 'Ip.Txt A Certain Line Format Error'
        pass


if __name__ == '__main__':
    start_time = datetime.datetime.now()
    main()
    tmp_domians = []
    for tmp_domain in final_domains:
        if tmp_domain not in tmp_domians:
            tmp_domians.append(tmp_domain)
    domain = {}
    sortDomain = {}
    result = {}
    resultSortDomain = {}
    for url in tmp_domians:
        if "[*]" in url:
            domain[url] = '255.255.255.255'
        elif "://" in url:
            result[url] = url[url.index("//") + 2:url.find(":", url.index(":") + 1)]
        else:
            domain[url] = url.split(':')[0]
    for key in (sorted(list(set(domain.values())), key=socket.inet_aton)):
        for i in domain:
            if key in domain[i]:
                if key not in sortDomain.keys():
                    sortDomain[key] = []
                sortDomain[key].append(i)

    for key in (sorted(list(set(result.values())), key=socket.inet_aton)):
        for i in result:
            if key in result[i]:
                if key not in resultSortDomain.keys():
                    resultSortDomain[key] = []
                resultSortDomain[key].append(i)

    with open(r'scan_url_port.txt', 'ab+') as ff:
        for i in (sorted(sortDomain.keys(), key=socket.inet_aton)):
            for data in sortDomain[i]:
                ff.write(data + '\n')

        x = PrettyTable(["URL", "容器", "标题", "状态", "返回包长度"])

        for i in (sorted(resultSortDomain.keys(), key=socket.inet_aton)):
            for data in resultSortDomain[i]:
                data = data.split("\t")
                x.add_row([data[0], data[1], data[2], data[3], data[4]])
        ff.write(str(x) + '\n')

    spend_time = (datetime.datetime.now() - start_time).seconds
    print '程序共运行了： ' + str(spend_time) + '秒'
