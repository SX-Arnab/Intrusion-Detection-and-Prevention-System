import socket
import sys
import os
from parser import process_packet, flush_buffer
from engine.engine import load_production_pipeline, process_live_prediction, start_engine, block_attacker_ip
if os.name != 'nt':
    sys.exit("Error: This script is explicitly configured for Windows systems.")

log_dir = "storage"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Cold Start Safety Hook: Engine crash rokne ke liye starting state empty csv banao
ml_log_file = os.path.join(log_dir, "model_log.csv")
if not os.path.exists(ml_log_file):
    try:
        with open(ml_log_file, "w", encoding="utf-8") as f:
            # Baseline data pattern structure initialization (Optional placeholder row)
            f.write("0,0,0,0,0,0\n")
    except Exception as e:
        print(f"[*] Warning: Initial ML storage validation matrix failed: {e}")

def get_active_interface_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "0.0.0.0"
    finally:
        s.close()
    return ip

host_ip = get_active_interface_ip()
if host_ip == "0.0.0.0":
    sys.exit("Error: Could not determine an active network interface.")

try:
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    raw_socket.bind((host_ip, 0))
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    print(f"[*] Core Network Sniffer Active on interface IP: {host_ip}")
    print("[*] Monitoring streaming data flows... Press Ctrl+C to stop.")
except PermissionError:
    sys.exit("Error: Administrator privileges are required. Run CMD/PowerShell as Administrator.")
except Exception as e:
    sys.exit(f"Windows Driver Hook Failed on {host_ip}: {e}")

packet_count = 0
packet_count = 0

try:
    while True:
        raw_data, _ = raw_socket.recvfrom(65535)
        packet_count += 1
        process_packet(raw_data, packet_count)

except KeyboardInterrupt:
    print("\n[*] Shutdown signal received! Cleaning up system states...")
    
    # 1. Purane textual representation ko save karo dashboard ke liye
    flush_buffer()
    
    # 2. BULLETPROOF EXIT WIDEOUT LOGIC: model_log.csv ko clear karo
    try:
        with open(os.path.join(log_dir, "model_log.csv"), "w", encoding="utf-8") as f:
            f.write("0,0,0,0,0,0\n")  # System resets to safe zero baseline
        print("[*] ML telemetry log wiped and reset to baseline successfully.")
    except Exception as e:
        print(f"[*] Warning: Could not reset ML log on exit: {e}")

    # 3. Windows network driver hook ko release karo
    try:
        raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    except:
        pass
        
    sys.exit("[*] Windows driver hook released. Sniffer stopped gracefully.")


load_production_pipeline()
process_live_prediction()
start_engine()
block_attacker_ip()