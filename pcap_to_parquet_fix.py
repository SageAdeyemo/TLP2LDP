"""
pcap_to_parquet_fix.py
A safe parser that handles out-of-range anomalies (-20) from raw PCAPs 
and cleanly writes out the compliant Parquet file.
"""
from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import time

def safe_pcap_convert(pcap_path: str, output_parquet_path: str):
    print("[*] Initiating resilient PCAP analysis script...")
    print(f"[*] Reading packets from: {pcap_path}")
    
    # Read packets sequentially using scapy to safely capture metadata boundaries
    packets = rdpcap(pcap_path)
    print(f"[+] Loaded {len(packets):,} packet frames. Parsing headers...")
    
    records = []
    
    for idx, pkt in enumerate(packets):
        # Extract base network layer features safely
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # Layer 4 Fallback resolution logic
            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                protocol = "TCP"
            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                protocol = "UDP"
            else:
                src_port = 0
                dst_port = 0
                protocol = "IP_OTHER"
                
            # Handle out-of-range integer values (-20 or negative corrupt entries)
            # Clip them safely into a valid uint16 boundary
            if src_port < 0 or src_port > 65535: src_port = 0
            if dst_port < 0 or dst_port > 65535: dst_port = 0
            
            record = {
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Source Port": int(src_port),
                "Destination Port": int(dst_port),
                "Timestamp": float(pkt.time),
                "Protocol": protocol,
                "Label": "unknown"  # Setup placeholder field to sync with tlp_injector.py
            }
            records.append(record)
            
    # Compile into a pandas dataframe frame matrix
    df = pd.DataFrame(records)
    
    # Export securely to your system workspace path
    df.to_parquet(output_parquet_path, engine="pyarrow")
    print(f"[+] Complete! Successfully saved sanitised dataset array to: {output_parquet_path}")

if __name__ == "__main__":
    # Ensure your python virtual environment has scapy installed: pip install scapy
    # Update these paths to match your disk setup
    INPUT_PCAP = r"C:\Users\A\Downloads\TLP_Project\YOUR_NEW_CAPTURE.pcap"
    OUTPUT_PARQUET = r"C:\Users\A\Downloads\TLP_Project\TESTPARQUETOUTPUT.PARQUET"
    
    try:
        safe_pcap_convert(INPUT_PCAP, OUTPUT_PARQUET)
    except Exception as e:
        print(f"[!] Processing exception occurred: {e}")