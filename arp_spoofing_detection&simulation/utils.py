from colorama import Fore,Style,init
from pyfiglet import Figlet

init(autoreset=True)

def banner(mode):
    f = Figlet(font="slant")

    if mode == "simulate":
        print(Fore.CYAN + f.renderText("ARP SPOOF"))
        print(Fore.YELLOW + "Simulation Mode Activated\n")

    elif mode == "live":
        print(Fore.RED + f.renderText("ARP SPOOF"))
        print(Fore.GREEN + "Live Monitoring Mode\n")

def alert(message):
    print(f"{Fore.RED} [ALERT] {message} {Style.RESET_ALL}")

def info(message):
    print(f"{Fore.GREEN} [INFO] {message} {Style.RESET_ALL}")