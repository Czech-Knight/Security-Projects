from scapy.all import sniff
from detector import process_packet

def start_sniffing():
    print("Starting Live ARP Monitoring...\n")
    sniff(filter="arp",prn=process_packet,store=False)
    