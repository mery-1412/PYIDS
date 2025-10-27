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
from sklearn.ensemble import IsolationForest
import numpy as np
import os
'''
    PYIDS
    designed to detect anomalies in TCP/UDP packets inside LAN and send them to the client side, we analyze the lateral movement of the attacker already inside the network
    used signature/anomaly based detection with Isolation Forest algorithm 
'''

# Defining classes
class pckt:
    def __init__(self, time_stamp:str='', ipsrc:str='', ipdst:str='',srcport:str='', dstport:str='', transport_layer:str='', highest_layer:str='', tcp_flags='', window_size=''):
        self.time_stamp=time_stamp
        self.ipsrc=ipsrc
        self.ipdst=ipdst 
        self.srcport=srcport
        self.dstport=dstport
        self.transport_layer=transport_layer
        self.highest_layer=highest_layer
        self.tcp_flags=tcp_flags
        self.window_size=window_size



class apiServer(object):
    def __init__(self, ip:str, port:str):
        self.ip=ip
        self.port=port


class packetCapture():
    def __init__(self):
        self.interface=self.get_interface()
        self.capture=pyshark.LiveCapture(interface=self.interface)


    @staticmethod
    def get_interface():
        # Defining interfaces
        output=subprocess.check_output(["tshark", "-D"], text=True)
        wifi_guid=re.search(r"\{([A-F0-9\-]+)\}.*Wi-Fi*", output)

        if wifi_guid:
            int=rf"\Device\NPF_{{{wifi_guid.group(1)}}}"# NPF is the Windows packet capture driver that gives your program raw access to the network interface.
        else:
            int=rf"\Device\NPF_{{{netifaces.gateways()['default'][netifaces.AF_INET][1].strip('{}')}}}"
        # return the detected interface string (previously missing)
        return int

    def start_capture(self, packet_handler):
        for packet in self.capture.sniff_continuously():
            packet_handler(packet)

    def ret_int(self):
        return self.interface



class reportManager():
    def __init__(self, server: apiServer, save_interval=3600, log_dir="./reports"):
        self.server=server
        self.reports_buffer=[]
        self.save_interval=save_interval
        self.log_dir=log_dir
        # ensure log directory exists
        try:
            os.makedirs(self.log_dir, exist_ok=True)
        except Exception:
            pass
        self._start_saving_thread()

    def _start_saving_thread(self):
        thread=threading.Thread(target=self._save_reports_periodically, daemon=True)
        thread.start()
    
    def _save_reports_periodically(self):
        while True:
            time.sleep(self.save_interval)
            if self.reports_buffer:
                data_to_save=self.reports_buffer.copy()
                self.reports_buffer.clear()
                timestamp=datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                filename = f"{self.log_dir}/REPORT_{timestamp}.json"
                try:
                    with open(filename, "w") as f:
                        json.dump(data_to_save, f, indent=4)
                        print(f"[+] File Saved {len(data_to_save)} reports to {filename}")
                except Exception as e:
                    print(f"[!] Error saving reports: {e}")


    def report(self, pkt:pckt, threat_info=None):
        try:
            payload=pkt.__dict__  #convert packet to a dict 
        except Exception:
            payload=dict() #creating empty dict in case of failure
        payload.setdefault("reported_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

        if threat_info:
            payload['threats'] = threat_info
            payload['is_threat'] = True
        else:
            payload['is_threat'] = False

        self.reports_buffer.append(payload)

        url = f"http://{self.server.ip}:{self.server.port}/api/"
        headers = {"Content-Type": "application/json"}

        for attempt in range(3):
            try:
                res = requests.post(url, json=payload, headers=headers, timeout=5)
                res.raise_for_status()
                print("Report sent, server replies:", res.status_code, res.text)
                return True
            except requests.exceptions.RequestException as err:
                print(f"Report attempt {attempt + 1} failed:", err)
                time.sleep(1)
        return False


class packetFilter:
    def __init__(self, server: apiServer, report_manager: reportManager, anomaly_detector: None):
        self.server=server
        self.report_manager=report_manager
        self.anomaly_detector=anomaly_detector
        self.flow_stats = {}
        self.latest_features=None


    def is_api_server(self, packet):
        # Determine if we are communication to our remote reporting server
        if not hasattr(packet, 'ip'):
            return False
        try:
            return (packet.ip.src == self.server.ip) or (packet.ip.dst == self.server.ip)
        except Exception:
            return False

    @staticmethod
    def is_priv_ip(ip_add):
        # Determines of the given ip is private
        ip=ipaddress.ip_address(ip_add)
        return ip.is_private

    @staticmethod
    def extract_tcp_flags(packet):
        try:
            if hasattr(packet.tcp, 'flags'):
                flags=int(packet.tcp.flags, 16) if isinstance(packet.tcp.flags, str) else int(packet.tcp.flags)
                return flags
        except:
            pass
        return 0

    @staticmethod
    def extract_window_size(packet):
        try:
            if hasattr(packet.tcp, 'window_size_value'):
                return int(packet.tcp.window_size_value)
            elif hasattr(packet.tcp, 'window_size'):
                return int(packet.tcp.window_size)
        except:
            pass
        return 0
    
    def filter(self, packet):
        # filters packets when sniffing
        # ignore traffic to/from the API server to avoid feedback loop
        if self.is_api_server(packet):
            print("API SERVER traffic ignored")
            return

        # ICMP handling
        if hasattr(packet, 'icmp'):
            print("Checking ICMP packets")
            try:
                src_ip = packet.ip.src

                icmp_key=("icmp", src_ip)
                icmp_stats=self.flow_stats.get(icmp_key, {
                    'packet_count':0,
                    'start_time': time.time()
                })
                icmp_stats['packet_count'] += 1

                #packets per sec
                duration=time.time()-icmp_stats['start_time']
                icmp_rate=icmp_stats['packet_count']/duration if duration > 0 else 0

                self.flow_stats[icmp_key]=icmp_stats

                
                # detect DOS: more than 100 ICMP packets/sec
                threats=None
                if icmp_rate>100:
                    threats=[{
                        'type': 'signature',
                        'rule':'icmp_flood',
                        'confidence': 1.0
                    }]

                pack = pckt(
                    time_stamp=packet.sniff_timestamp,
                    ipsrc=packet.ip.src,
                    ipdst=packet.ip.dst,
                    highest_layer=packet.highest_layer,
                    transport_layer=packet.transport_layer,
                )
                self.report_manager.report(pack, threats)
                print("ICMP PACKET REPORTED")
            except Exception as e:
                print(f"[!] Error reporting ICMP packet: {e}")
            return

        # TCP/UDP handling
        if packet.transport_layer in ("TCP", "UDP"):
            # ignore IPv6 for now
            if hasattr(packet, 'ipv6'):
                return None
            if not hasattr(packet, 'ip'):
                return None

            try:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            except Exception:
                return None

            # only inspect private-to-private traffic
            if not (self.is_priv_ip(src_ip) and self.is_priv_ip(dst_ip)):
                return None

            src_port = None
            dst_port = None
            tcp_flags = 0
            window_size = 0

            if packet.transport_layer == 'UDP' and hasattr(packet, 'udp'):
                print("Checking UDP packets")
                src_port =  getattr(packet.udp, 'srcport', None)
                dst_port = getattr(packet.udp, 'dstport', None)
            elif packet.transport_layer == 'TCP' and hasattr(packet, 'tcp'):
                print("Checking TCP packets")
                src_port = getattr(packet.tcp, 'srcport', None)
                dst_port = getattr(packet.tcp, 'dstport', None)
                tcp_flags = self.extract_tcp_flags(packet)
                window_size = self.extract_window_size(packet)
            else:
                return None

            # normalize ports to ints when possible
            try:
                src_port = int(src_port) if src_port is not None else 0
            except Exception:
                src_port = 0
            try:
                dst_port = int(dst_port) if dst_port is not None else 0
            except Exception:
                dst_port = 0

            flow_key = (src_ip, dst_ip, src_port, dst_port) #tuple: unique id of a network cnx
            stats = self.flow_stats.get(flow_key, {  #dect statistics of one FLOW
                'packet_count': 0,
                'byte_count': 0,
                'start_time': None,
                'last_time': None
            })

            # update stats
            stats['packet_count'] += 1
            try:
                stats['byte_count'] += int(packet.length) if hasattr(packet, 'length') else 0
            except Exception:
                pass
            try:
                current_time = float(packet.sniff_timestamp)
            except Exception:
                current_time = time.time()

            if stats['start_time'] is None:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            self.flow_stats[flow_key] = stats #dict with unique keys: maps all flows to their stats

            # compute feature values
            duration = stats['last_time'] - stats['start_time'] if stats['start_time'] else 1
            packet_rate = stats['packet_count'] / duration if duration > 0 else 0
            byte_rate = stats['byte_count'] / duration if duration > 0 else 0

            pack = pckt(
                time_stamp=packet.sniff_timestamp,
                ipsrc=src_ip,
                ipdst=dst_ip,
                srcport=src_port,
                dstport=dst_port,
                highest_layer=packet.highest_layer,
                transport_layer=packet.transport_layer,
                tcp_flags=tcp_flags,
                window_size=window_size
            )

            features = {
                'packet_size': int(packet.length) if hasattr(packet, 'length') else 0,
                'flow_duration': duration,
                'packet_rate': packet_rate,
                'byte_rate': byte_rate,
                'tcp_flags': pack.tcp_flags,
                'window_size': pack.window_size
            }
            self.latest_features = features

            threats = None
            if self.anomaly_detector:
                try:
                    threats = self.anomaly_detector.detect_threats(features)
                    if threats:
                        print(f"[!] THREAT DETECTED in packet from {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                        print(f"    Threats: {threats}")
                except Exception as e:
                    print(f"[!] Error running anomaly detection: {e}")

            self.report_manager.report(pack, threats)
            print("TCP/UDP PACKET REPORTED")


class anomalyDetection:
    def __init__(self, training_period=300): #5min
        self.anomaly_detector=IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )

        self.signature_rules=self.load_signature_rules()
        self.training_data=[]
        self.is_trained=False
        self.training_period=training_period
        self.training_start_time=time.time()
        self.min_training_samples=500

        print(f"[*] Anomaly detector in TRAINING MODE")
        print(f"[*] Will collect {self.min_training_samples} samples or {training_period}s of normal traffic")
        print("[*] ALL packets will be reported as NON-THREATENING during training")


    def load_signature_rules(self):
        return {
            'syn_flood':{
                'condition': lambda features: ( #lambda: anonymous fct
                    features['tcp_flags']==2 and
                    features['packet_rate'] > 100
                )
            },
            'port_scan': {
                'condition' : lambda features: (
                features['packet_size'] < 100 and
                features['packet_rate'] > 50
            )
            }
        }

    def add_training_sample(self, features):
        feature_vector=[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate']
        ]
        self.training_data.append(feature_vector)

        elapsed=time.time()-self.training_start_time
        if len(self.training_data) >= self.min_training_samples or elapsed > self.training_period:
            if len(self.training_data) >= 100:  
                self.train_anomaly_detector(np.array(self.training_data))  

        if len(self.training_data) % 100 == 0:
            print(f"[*] Training samples collected: {len(self.training_data)}")



    def train_anomaly_detector(self, normal_traffic_data):
        if len(normal_traffic_data) > 0:
            self.anomaly_detector.fit(normal_traffic_data)
            self.is_trained = True
            print(f"\n{'='*60}")
            print(f"[+] Anomaly detector TRAINED with {len(normal_traffic_data)} samples")
            print(f"[+] Feature statistics:")
            print(f"    Packet size: min={normal_traffic_data[:, 0].min():.0f}, "
                  f"max={normal_traffic_data[:, 0].max():.0f}, "
                  f"mean={normal_traffic_data[:, 0].mean():.0f}")
            print(f"    Packet rate: min={normal_traffic_data[:, 1].min():.2f}, "
                  f"max={normal_traffic_data[:, 1].max():.2f}, "
                  f"mean={normal_traffic_data[:, 1].mean():.2f}")
            print(f"    Byte rate: min={normal_traffic_data[:, 2].min():.0f}, "
                  f"max={normal_traffic_data[:, 2].max():.0f}, "
                  f"mean={normal_traffic_data[:, 2].mean():.0f}")
            print(f"[+] Anomaly detection: ACTIVE")
            print(f"{'='*60}\n")
        else:
            print("[!] No training data provided")
    
    def detect_threats(self, features):
        if not self.is_trained: 
            self.add_training_sample(features)
            return None 

        threats=[]
        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            try:
                if rule['condition'](features): 
                    threats.append({
                        'type':'signature',
                        'rule': rule_name,
                        'confidence':1.0
                    })
            except Exception as e:
                print(f"[!] Error in signature rule {rule_name}: {e}")

        
        # Anomaly based detection
        if self.is_trained:
            feature_vector=np.array([[
                features['packet_size'],
                features['packet_rate'],
                features['byte_rate']
            ]])

            anomaly_score=self.anomaly_detector.score_samples(feature_vector)[0]
            if anomaly_score<-0.7:
                threats.append({
                    'type': 'anomaly',
                    'score': float(anomaly_score),
                    'confidence': min(1.0, abs(anomaly_score))
                })
        return threats if threats else None


if __name__ == "__main__":
    
    server=apiServer('127.0.0.1', '8080') # private address of the reporter server
    report_manager=reportManager(server)
    anomaly_detector=anomalyDetection(training_period=300)
    packet_filter=packetFilter(server, report_manager, anomaly_detector)
    capture=packetCapture()
    
    print(f"[+] Starting IDS on interface {capture.ret_int()}")
    print("[+] Anomaly detection: ENABLED")
    print("[+] Signature rules loaded:", list(anomaly_detector.signature_rules.keys()))

    capture.start_capture(packet_filter.filter)






