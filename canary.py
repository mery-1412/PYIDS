import pyshark 
import netifaces
import subprocess
import re
import json
import base64
import requests
import ipaddress
import time
import threading
from datetime import datetime
'''
    PYIDS
    designed to detect inside→inside (lateral) traffic on a LAN.
    ?lateral movement of the insider => already on your LAN moving from host to host to escalate access and reach high-value assets.
'''

# Defining classes
class pckt(object):
    def __init__(self, time_stamp:str='', ipsrc:str='', ipdst:str='',srcport:str='', dstport:str='', transport_layer:str='', highest_layer:str=''):
        self.time_stamp=time_stamp
        self.ipsrc=ipsrc
        self.ipdst=ipdst 
        self.srcport=srcport
        self.dstport=dstport
        self.transport_layer=transport_layer
        self.highest_layer=highest_layer


class apiServer(object):
    def __init__(self, ip:str, port:str):
        self.ip=ip
        self.port=port
        
# defining variables we are going to use further
reports_buffer=[]
save_int=3600 # saving reports each 1h
log_file_dir="./reports"
    
server=apiServer('127.0.0.1', '8080') # private address of the reporter server


# Defining interfaces
output=subprocess.check_output(["tshark", "-D"], text=True)
wifi_guid=re.search(r"\{([A-F0-9\-]+)\}.*Wi-Fi*", output)

if wifi_guid:
    int=rf"\Device\NPF_{{{wifi_guid.group(1)}}}"# NPF is the Windows packet capture driver that gives your program raw access to the network interface.
else:
    int=rf"\Device\NPF_{{{netifaces.gateways()['default'][netifaces.AF_INET][1].strip('{}')}}}"

print(f"Capturing on: ", {int})
capture=pyshark.LiveCapture(interface=int)


# Defining fcts
def is_api_server(packet:capture, server:apiServer)->bool:
    # Determine if we are communication to our remote reporting server
    if (hasattr(packet, 'ip') and hasattr(packet, 'tcp')):
        if ((packet.ip.src==server.ip) or (packet.ip.dst==server.ip)):
            return True
        else:
            return False



def is_priv_ip(ip_add:str)->bool:
    # Determines of the given ip is private
    ip=ipaddress.ip_address(ip_add)
    return ip.is_private


# encode the message in base64 and formatting the message as JSON object
def report(message: pckt):
    try:
        payload=message.__dict__
    except Exception:
        payload=dict()
    payload.setdefault("reported_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    reports_buffer.append(payload)
    url=f"http://{server.ip}:{server.port}/api/"
    headers={"Content-Type":"application/json"}
    
    for attempt in range(3):
        try:
            res=requests.post(url, json=payload, headers=headers, timeout=5)
            res.raise_for_status()
            print("Report sent, server replies:", res.status_code, res.text)
            return True
        except requests.exceptions.RequestException as err:
            print(f"Report attempt {attempt+1} failed: ", err)
            time.sleep(1)
        

def filter(packet:capture):
    # filters packets when sniffing
    # check to see if we are communicating to our reporting server => avoiding the loop
    if is_api_server(packet, server) is True:
        print("API SERVER")
        #bail out
        return 
    if hasattr(packet, 'icmp'):
        # we were pinged => ICMP packet
        print("Checking ICMP packets")
        pack=pckt()
        pack.ipsrc=packet.ip.src
        pack.ipdst=packet.ip.dst
        pack.time_stamp=packet.sniff_timestamp
        pack.highest_layer=packet.highest_layer
        pack.transport_layer=packet.transport_layer
        report(pack)
        print("ICMP PACKET REPORTED")
    print('filter fct')
    if packet.transport_layer == "TCP" or packet.transport_layer == "UDP":
        pack=pckt()
        if hasattr(packet, 'ipv6'):
            # Ipv6 not treated
            return None
        if hasattr(packet, 'ip'):
            if (is_priv_ip(packet.ip.src) is True) and (is_priv_ip(packet.ip.dst) is True):
                pack.ipsrc=packet.ip.src
                pack.ipdst=packet.ip.dst
                pack.time_stamp=packet.sniff_timestamp
                pack.highest_layer=packet.highest_layer
                pack.transport_layer=packet.transport_layer
                if hasattr(packet, 'UDP'): # we got an UDP packet
                    print("Checking UDP packets")
                    pack.dstport=packet.udp.dstport
                    pack.srcport=packet.udp.srcport
                if hasattr(packet, 'TCP'): # we got a TCP packet
                    print("Checking TCP packets")
                    pack.dstport=packet.tcp.dstport
                    pack.srcport=packet.tcp.srcport
                report(pack)
                print("TCP/UDP PACKET REPORTED")


def save_reports():
    while True:
        time.sleep(save_int)
        if reports_buffer:
            data_to_save = reports_buffer.copy()
            reports_buffer.clear()
            timestamp=datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename=f"{log_file_dir}/REPORT_{timestamp}.json"
            try:
                with open(filename, "w") as f:
                    json.dump(data_to_save, f, indent=4)
                    print(f"[+] File Saved {len(data_to_save)} reports tp {filename}")
            except Exception as e:
                print(f"[!] Error saving reports: {e}")

save_thread=threading.Thread(target=save_reports, daemon=True)
save_thread.start()
for packet in capture.sniff_continuously():
    filter(packet)

