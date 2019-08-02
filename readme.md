## 简介

基于masscan和nmap的快速端口扫描和指纹识别工具  
整个项目都是抄袭来的  
抄袭https://github.com/hellogoldsnakeman/masnmapscan-V1.0  
能抄袭就抄袭,因为菜

由于使用的时候遇到一些问题，比较蜜汁就自己拼凑了一下  
增加ip处理,多线程处理,过滤防火墙ip,获取http请求标题

有问题和需求请Issues  

## 安装使用

安装

1. Centos 安装 Masscan
    >yum install git gcc make libpcap-devel  
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
2. scan_ip.txt (生成IP文件，方便导出)  

3. scan_url_port.txt (扫描结果,追加写入)  

4. 扫描启动
   >python scan.py



