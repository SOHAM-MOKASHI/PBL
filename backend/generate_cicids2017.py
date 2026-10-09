import csv
import random
from datetime import datetime, timedelta

def create_cicids_demo_csv(filename="cicids2017.csv", total_rows=10000):
    # Core CIC-IDS2017 schema required for SOC dashboards and ML models
    headers = [
        "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", 
        "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max", 
        "Fwd Packet Length Min", "Fwd Packet Length Mean", "Bwd Packet Length Mean",
        "Flow Bytes/s", "Flow Packets/s", "FIN Flag Count", "SYN Flag Count", 
        "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "Label"
    ]
    
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        
        # Start timestamp for the simulated live feed
        start_time = datetime.now()
        
        for i in range(total_rows):
            current_time = start_time + timedelta(seconds=i * 2.5)
            timestamp_str = current_time.strftime("%d/%m/%Y %H:%M:%S")
            
            # Distribution: 85% Noise, 15% Real Attacks
            attack_roll = random.random()
            
            if attack_roll < 0.85:
                # BENIGN TRAFFIC (Noise for Stage 1 to filter out)
                src_ip = f"192.168.1.{random.randint(20, 100)}"
                dst_ip = f"10.0.0.{random.randint(1, 50)}"
                src_port = random.randint(10000, 60000)
                dst_port = random.choice([80, 443, 53, 8080])
                protocol = random.choice([6, 17]) # TCP or UDP
                flow_duration = random.randint(100, 50000)
                fwd_pkts, bwd_pkts = random.randint(1, 10), random.randint(1, 10)
                label = "BENIGN"
                flags = [0, 1, 0, 1, 1, 0] # Standard SYN/ACK
                
            elif attack_roll < 0.90:
                # PORT SCAN (Reconnaissance)
                src_ip = "205.174.165.73" # Standard CICIDS external attacker IP
                dst_ip = "192.168.10.50"
                src_port = random.randint(30000, 60000)
                dst_port = random.randint(1, 1024)
                protocol = 6
                flow_duration = random.randint(10, 100)
                fwd_pkts, bwd_pkts = 1, 1
                label = "PortScan"
                flags = [0, 1, 0, 0, 0, 0] # SYN only
                
            elif attack_roll < 0.95:
                # DDoS HULK (Infrastructure Attack)
                src_ip = f"205.174.165.{random.randint(69, 71)}"
                dst_ip = "192.168.10.50"
                src_port = random.randint(1024, 65535)
                dst_port = 80
                protocol = 6
                flow_duration = random.randint(5000000, 100000000) # Massive duration
                fwd_pkts, bwd_pkts = random.randint(500, 2000), random.randint(500, 2000)
                label = "DDoS"
                flags = [0, 1, 0, 1, 1, 0]
                
            else:
                # BRUTE FORCE (Credential Access)
                src_ip = "172.16.0.1" 
                dst_ip = "192.168.10.50"
                src_port = random.randint(40000, 60000)
                dst_port = 22
                protocol = 6
                flow_duration = random.randint(100000, 500000)
                fwd_pkts, bwd_pkts = random.randint(10, 50), random.randint(10, 50)
                label = "Brute Force"
                flags = [0, 1, 0, 1, 1, 0]

            # Generate dependent metrics
            tot_len_fwd = fwd_pkts * random.randint(40, 1500)
            tot_len_bwd = bwd_pkts * random.randint(40, 1500)
            fwd_pkt_max = random.randint(40, 1500)
            fwd_pkt_min = random.randint(0, 40)
            fwd_pkt_mean = (fwd_pkt_max + fwd_pkt_min) / 2
            bwd_pkt_mean = random.randint(40, 1500)
            
            flow_bytes_s = (tot_len_fwd + tot_len_bwd) / (flow_duration / 1000000) if flow_duration > 0 else 0
            flow_pkts_s = (fwd_pkts + bwd_pkts) / (flow_duration / 1000000) if flow_duration > 0 else 0
            
            flow_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"
            
            row = [
                flow_id, src_ip, src_port, dst_ip, dst_port, protocol, timestamp_str,
                flow_duration, fwd_pkts, bwd_pkts, tot_len_fwd, tot_len_bwd,
                fwd_pkt_max, fwd_pkt_min, fwd_pkt_mean, bwd_pkt_mean,
                round(flow_bytes_s, 2), round(flow_pkts_s, 2)
            ] + flags + [label]
            
            writer.writerow(row)
            
    print(f"Successfully generated {filename} with {total_rows} rows.")

if __name__ == '__main__':
    create_cicids_demo_csv()
