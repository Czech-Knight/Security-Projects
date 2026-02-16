from scapy.all import ARP 
from utils import alert,info

arp_table ={}

def process_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        MAC= packet[ARP].hwsrc
        if ip in arp_table:
            if arp_table[ip] != MAC:
                alert(f"ARP Spoofing Detected! IP: {ip} | Old MAC: {arp_table[ip]} | New MAC: {MAC}")
        else:
               info(f"New device detected: {ip} -> {MAC}")
        
        arp_table[ip] = MAC