from scapy.all import ARP
from detector import process_packet

def run_simulation():
    print(f"\nRunning ARP Spoof Simulation...")
    pkt1 = ARP(op =2 , psrc ="192.168.1.1" ,  hwsrc ="AA.BB.CC.DD.EE.FF")
    pkt2 = ARP(op =2 , psrc ="192.168.1.1" ,  hwsrc ="11.22.33.44.55.66")
    process_packet(pkt1)
    process_packet(pkt2)