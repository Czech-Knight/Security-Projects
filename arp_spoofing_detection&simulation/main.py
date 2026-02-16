import sys
from simulator import run_simulation
from sniffer import start_sniffing
from utils import banner

if  len(sys.argv) < 2:
    print(f"Usage : Python main.py simulate")
    sys.exit(1)

if __name__=="__main__":
    
    mode = sys.argv[1]

    if mode == "simulate":
        banner("simulate")
        run_simulation()
    elif mode == "live":
        banner("live")
        start_sniffing()
    else:
        print("Invalid option. Use simulate or live.")
