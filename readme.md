## 简介

基于masscan和nmap的快速端口扫描和指纹识别工具  
整个项目都是抄袭来的  
抄袭https://github.com/hellogoldsnakeman/masnmapscan-V1.0  
能抄袭就抄袭,因为菜

由于使用的时候遇到一些问题，比较蜜汁就自己拼凑了一下  
增加ip处理,多线程处理,过滤防火墙ip,获取http请求标题

有问题和需求请Issues  

## 安装使用

安装(建议把masscan编译在这个masscan_to_nmap目录下,这样就不用修改代码了)

1. Centos 安装 Masscan (版本GIT version: 1.0.5-86-ga025970,版本低会导致-oJ masscan.json格式出现偏差导致报错)
    >yum install git gcc make libpcap-devel  
    yum install nmap(如果没安装请安装)  
    git clone https://github.com/7dog7/masscan_to_nmap.git  
    git clone https://github.com/robertdavidgraham/masscan  
    cd masscan  
    make  

2. python依赖
    >pip install -r requirements.txt
    
使用说明

1. ip.txt文件
    >127.0 (自动填充)  
    127.0.1 (自动填充)  
    127.0.0.1-254  
    127.0.0.1/24  
2. scan_ip.txt (生成IP文件，方便导出)  

3. scan_url_port.txt (扫描结果,追加写入)  

4. 扫描启动
   >python scan.py

  
## 2019.8.8 更新如下:结果排序、状态、与返回包大小:  
## 2019.9.9 更新如下:表格
文件:scan_url_port.txt
```
+------------------------------+-------------------------------------------------+------------------------------------------+------+------------+
|             URL              |                       标题                      |                   服务                   | 状态 | 返回包长度 |
+------------------------------+-------------------------------------------------+------------------------------------------+------+------------+
|    http://127.0.0.1:80    |                                                 |                   http                   | 200  |    131     |
|   http://127.0.0.1:8083   |                                                 |                  us-srv                  | 200  |     87     |
|   https://127.0.0.1:443    |                                                 |                Loading...                | 200  |    2709    |
|   https://127.0.0.1:443    |                                                 |                Loading...                | 200  |    2709    |
|    http://127.0.0.1:80     |                                                 |                   http                   | 200  |    6867    |
```

## 建议扫描完毕后使用python -m SimpleHTTPServer 8033,来启动web服务来访问  
## 浏览器安装Charset插件,使用Unicode(UTF-8)显示中文
