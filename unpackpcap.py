#coding=utf8
import struct
import os
import re, collections, dpkt, zlib, sys, time
from imp import reload
#import pandas as pd #draw picture lib

reload(sys)


#定义消息的大小
#MSG_HEADER_FMT="!LL"
#MSG_HEADER_SIZE = struct.calcsize(MSG_HEADER_FMT)
#MSG_TRAILER_SIZE = 4


#此处用于抓包的消息体，放在common.py中，此处最好不要全转为字符
MSG_HEADER_FMT="!6s4s6s16s128s"
MSG_HEADER_SIZE = struct.calcsize(MSG_HEADER_FMT)
MSG_TRAILER_SIZE = 0

TIME_ZOME = "Asia/Shanghai"

def pcap_packet_generator(pcap_file):
    protocol_type=""
    with open(pcap_file, 'rb') as f:
        cap = dpkt.pcap.Reader(f)

        remains = ""
        sport = 0
        dport = 0
        for ts, payload in cap:
            if not len(payload)>0:
                continue

            eth = dpkt.ethernet.Ethernet(payload)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
        
            if type(ip.data) == dpkt.tcp.TCP:
                tcp = ip.data
                data = tcp.data
                protocol_type = "tcp"
                if not len(data) > 0:
                    continue

                sport = tcp.sport
                dport = tcp.dport
            else:
                udp = ip.data
                data = udp.data
                protocol_type = "udp"
                if not len(data) > 0:
                    continue

                sport = udp.sport
                dport = udp.dport


            #packet_time = pd.to_datetime(ts*1000000000).tz_localize('UTC').tz_convert(TIME_ZOME)
            packet_time = 0
            if protocol_type == "tcp":
                yield packet_time, protocol_type, (ip.src, sport, ip.dst, dport, tcp.seq), data, len(data)
            elif protocol_type == "udp":
                yield packet_time, protocol_type, (ip.src, sport, ip.dst, dport), data, len(data)

def pcap_generator(pcap_file):
    remains = collections.defaultdict(str)
    counter = 0
    for packet_time, protocol_type, peers, data, data_len in pcap_packet_generator(pcap_file):
        remain = remains[peers]
        print("protocol_type =", protocol_type)
        if len(remain) > 0:
            data = remain + data
            remains[peers] = str()

        pos = 0
        while True:
            if pos + MSG_HEADER_SIZE > len(data):
                break

            msg_len,msg_code,record_len, msg_no, verify_data = struct.unpack(MSG_HEADER_FMT, data[pos:pos+MSG_HEADER_SIZE])
            print("record_len type=", type(record_len))
            if pos+MSG_HEADER_SIZE+int(record_len.decode().rstrip('\x00'))+MSG_TRAILER_SIZE > len(data):
                break

            yield packet_time, protocol_type, msg_no, data[pos+MSG_HEADER_SIZE : pos+MSG_HEADER_SIZE+int(record_len.decode().rstrip('\x00'))]
            pos += MSG_HEADER_SIZE +int(record_len.decode().rstrip('\x00')) + MSG_TRAILER_SIZE

        if protocol_type == "tcp":
            if pos < len(data):
                peers = list(peers)
                peers[4] = peers[4] + data_len
                peers = tuple(peers)
                remains[peers] = data[pos:]
        else:
        # udp 解包,udp.data前22个字节为协议信息，后面的才是data数据
            pass

if __name__ == "__main__":
    load_pcap = pcap_generator
    for packet_time, protocol_type, msg_no, body in load_pcap("file.cap"):
        if len(body) == 0:
            continue

        #根据你的消息结构进行，从body中将消息的各部分解出来
        print("unpack msg =",msg_no, body)
