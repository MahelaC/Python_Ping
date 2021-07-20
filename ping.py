#!/usr/bin/python

import socket
import struct
import os
import array
import sys
import time
import datetime

ICMP_CODE = socket.getprotobyname('icmp')
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

def checksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res = res + (res >> 16)

    return ((~res) & 0xffff)

 
   #pack and send ICMP
def send_icmp_packet(dst_ip, seq, socket):
    icmp_type = 8 
    icmp_code = 0 
    icmp_chsum= 0 
    icmp_pid  = os.getpid()
    icmp_seq  = seq

    chsum_packet = struct.pack('BBHHH', icmp_type, icmp_code, int(icmp_chsum), icmp_pid, icmp_seq)

    data = ("1 2 3 4 5 6 7 8 9 10").encode()

    icmp_checksum = checksum( chsum_packet + data )
    
    icmp = struct.pack('BBHHH', icmp_type, icmp_code, int(icmp_checksum), icmp_pid, icmp_seq)
    
    finalize_icmp_pak = (icmp + data)

    sock.sendto(finalize_icmp_pak, (dst_ip, 0)) 
    



def recv_packet():
    raw_pak = sock.recvfrom(65535)[0]
    ip_pak = struct.unpack('! BBHHHBBH4s4s', raw_pak[:20])
    icmp_pak = struct.unpack('BBHHH', raw_pak[20:28] )
    global src_ip , ttl , code , seq_num
    src_ip = socket.inet_ntoa(ip_pak[8])
    ttl = ip_pak[5]
    code = icmp_pak[1]
    seq_num = int((hex(icmp_pak[4])), 16)
    



try:
    for i in range(4):

        #Send the ping request
        s_time = datetime.datetime.now()
        ip = sys.argv[1]
        send_icmp_packet(ip, i, sock)

        time.sleep(1)

        #Receive the ping reply
        recv_packet()
        e_time = datetime.datetime.now()

        t = ((s_time - e_time).microseconds / 10000)
        tm = "{:.2f}".format(t)
    
        print(f'64 bytes from {src_ip}: icmp_seq={seq_num} ttl={ttl} time={tm} ms')


except KeyboardInterrupt:
    print("\nKeyboard interrupt exception caught")
    
except Exception as e:
    print(e)

    
