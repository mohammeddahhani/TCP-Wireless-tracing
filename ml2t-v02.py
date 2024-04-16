#! /usr/bin/env python3
"""
 If the specified wlan_type is mgt, then valid wlan_subtypes are:
              assoc-req,  assoc-resp,  reassoc-req,  reassoc-resp,  probe-req,
              probe-resp, beacon, atim, disassoc, auth and deauth.

              If the specified wlan_type is ctl, then valid wlan_subtypes are:
              ps-poll, rts, cts, ack, cf-end and cf-end-ack.

              If the specified wlan_type is  data,  then  valid  wlan_subtypes
              are:  data,  data-cf-ack,  data-cf-poll, data-cf-ack-poll, null,
              cf-ack, cf-poll, cf-ack-poll,  qos-data,  qos-data-cf-ack,  qos-
              data-cf-poll, qos-data-cf-ack-poll, qos, qos-cf-poll and qos-cf-
              ack-poll.

mlfilter= lambda r: (Dot11 in r and r[Dot11].type == 1 and\
      r[Dot11].subtype == 9) or (TCP in r)

"""

import math
from scapy.all import *
from collections import namedtuple

def shift_mac_acks(i):
    return mac_ack._replace(
        timestamp=mac_ack.timestamp[i:],
        seq=mac_ack.seq[i:],
        bitmap=mac_ack.bitmap[i:],
        last_rcv=mac_ack.last_rcv[i:],
        rcv_count=mac_ack.rcv_count[i:]
        )

def tcp_segment_handler(pkt):
    tmp = pkt[IP].payload
    seq = tmp.seq
    length = len(tmp.payload)

    tcp_seg.timestamp.append(pkt.time)
    tcp_seg.seq.append(seq+length-1)
    tcp_seg.length.append(length)    

def tcp_ack_handler(pkt):
    tcp_ack.timestamp.append(pkt.time)
    tcp_ack.seq.append(pkt[IP].payload.ack)    
#   length = len(tmp.payload)

def bitmap_hanlder(bitm):
    last_rcv,rcv_count= 0,0
    bytelist=[]
    for byte in bitm:
        b = '0'
        if byte != 0: b= bin(byte)[2:].zfill(8)
        bytelist.append(b)  
        rcv_count+=int(math.log(byte+1,2))
        while byte != 0:
            byte = byte >> 1
            last_rcv+=1
    return (last_rcv,rcv_count,bytelist)

def mac_ack_handler(pkt):
    back = raw(pkt)[34:]
    start_seq = int.from_bytes(back[2:4],byteorder='little') >> 4
    bitm = back[4:]
    last_rcv,rcv_count,bitmlist = bitmap_hanlder(bitm)

    mac_ack.timestamp.append(pkt.time)
    mac_ack.bitmap.append(bitmlist)
    mac_ack.seq.append(start_seq)        
    mac_ack.rcv_count.append(rcv_count)
    mac_ack.last_rcv.append(start_seq+last_rcv-1)

def packet_handler(pkt) :
    if IP in pkt and pkt[IP].proto == 6:
        #all_frames.append(pkt)              
        tmp=pkt[IP]
        if tmp.src == sender.ip and tmp.payload.sport == sender.port:
        # and tmp.addr2 == sender.mac 

            # TCP segment
            all_tcp_segments.append(pkt)    # TCP segments
            tcp_segment_handler(pkt)

            # MAC info
            all_frames.append(pkt)          # all mac data frames
            mac_frame.seq.append(pkt[Dot11].SC >> 4)
            mac_frame.timestamp.append(pkt.time)
           
        elif tmp.src == receiver.ip and tmp.payload.dport == sender.port: 
            # TCP acks
            all_tcp_acks.append(pkt)        # TCP acks
            tcp_ack_handler(pkt)
 
    elif (Dot11 in pkt and pkt.type ==1 and pkt.subtype == 9 \
          and pkt[Dot11].addr2=='04:ce:14:0b:7e:69'):
        all_mac_acks.append(pkt)            # mac ack - block acks
        mac_ack_handler(pkt)

            
Endpoint = namedtuple('tcp',['id','ip','mac','port'])
TCP = namedtuple('tcp',['timestamp','seq','length'])
MAC = namedtuple('mac',['timestamp','seq','bitmap','last_rcv','rcv_count'])

tcp_seg = TCP([],[],[])
tcp_ack = TCP([],[],[])
mac_frame = MAC([],[],[],[],[])
mac_ack   = MAC([],[],[],[],[])

all_mac_acks=[]
all_frames=[]
all_tcp_segments=[]
all_tcp_acks=[]

sndip='192.168.100.1'
rcvip='192.168.100.10'
sndmac='04:ce:14:0a:9c:68'
rcvmac='04:ce:14:0b:7e:69'
sport=56706
rport=5201

sender = Endpoint('tx',sndip,sndmac,sport)
receiver = Endpoint('rx',rcvip,rcvmac,rport)

mfilter='(type data subtype qos-data or type ctl) and not \
            (subtype ps-poll or subtype rts or subtype cts or\
            subtype ack or subtype cf-end or subtype cf-end-ack)'              

all = sniff(offline='pcap/original.pcap',filter=mfilter, prn=packet_handler)

# shift by initial value and skip TCP handshake
tmp = [s-tcp_seg.seq[0] for s in tcp_seg.seq]
tcp_seg = tcp_seg._replace(seq=tmp)

tmp=[s-tcp_ack.seq[0]+1 for s in tcp_ack.seq]
tcp_ack=tcp_ack._replace(seq=tmp)

# crop mac acks starting TCP handshake
off=0
for i in range(min(len(mac_ack.seq),len(tcp_seg.seq))):
    if mac_ack.timestamp[i] >= tcp_seg.timestamp[0]: 
        off=i
        break

mac_ack = shift_mac_acks(off)


for i in range(10):
    print (tcp_seg.seq[i],tcp_ack.seq[i])

print ("Now MAC:")

for i in range(10):
    print (mac_frame.seq[i],mac_ack.last_rcv[i])


for i in range(20):
    print(mac_frame.seq[i],':',mac_ack.seq[i],"-",mac_ack.last_rcv[i],"(",mac_ack.rcv_count[i],")",str(''.join(str(mac_ack.bitmap[i]))))
print(len(all_mac_acks))
print(len(all_frames))
print(len(all_mac_acks))
print(len(all_frames))
print(len(all_tcp_segments))
print(len(tcp_seg.timestamp))
for p in all:
    wrpcap('pcap/filtered.pcap',p,append=False)

