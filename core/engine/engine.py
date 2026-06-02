import os
import time
import pickle
import numpy as np

# Storage and assets resolution path mapping
ML_LOG_PATH = r"storage\model_log.csv"
MODEL_PATH = r"ids_ips_production_pipeline.pkl"

# Global System Parameters
ALERT_THRESHOLD = 0.85  # 85% confidence score criteria for threat confirmation

def load_production_pipeline():
    """
    Trained pipeline core setup utility loader.
    """
    if not os.path.exists(MODEL_PATH):
        print(f"[-] Critical Error: Production pipeline bundle '{MODEL_PATH}' not found!")
        return None
        
    try:
        with open(MODEL_PATH, "rb") as f:
            pipeline_bundle = pickle.load(f)
        print("[*] Machine Learning Production Pipeline bundle loaded successfully.")
        return pipeline_bundle
    except Exception as e:
        print(f"[-] Pipeline initialization anomaly caught: {e}")
        return None

def process_live_prediction(pipeline, feature_list):
    """
    Mathematical transformation matrix transformation block.
    """
    try:
        # Array structural conversion to 2D matrix
        raw_matrix = np.array(feature_list).reshape(1, -1)
        
        # Scikit-learn automated pipeline logic: 
        # Scaler scaling mapping matrix auto-injects inside integrated classifiers
        # probability index format array matrix output structure: [[Normal_Prob, Attack_Prob]]
        probabilities = pipeline.predict_proba(raw_matrix)
        attack_risk = probabilities[0][1]
        
        return attack_risk
    except Exception as e:
        print(f"[-] Inference computation failed: {e}")
        return 0.0

def start_engine():
    pipeline = load_production_pipeline()
    if pipeline is None:
        return

    print("[*] Engine Listening Loop Active. Watching telemetry matrix channels...")
    
    while True:
        # Realtime I/O state check routine loop
        if os.path.exists(ML_LOG_PATH) and os.path.getsize(ML_LOG_PATH) > 0:
            raw_line = ""
            
            # Race Condition Control Hook (Safe Access Protocol)
            try:
                with open(ML_LOG_PATH, "r", encoding="utf-8") as f:
                    raw_line = f.read().strip()
            except (PermissionError, IOError):
                # Lock condition catch-up: retry loop iteration channel
                time.sleep(0.005)
                continue

            # Zero padding empty state bypass validation check
            if not raw_line:
                continue

            try:
                # Type transformation mapping operation
                numeric_features = [float(val) for val in raw_line.split(",")]
            except ValueError:
                # Partial string format drop protocol guardrail
                continue

            # Zero Baseline Filter: Startup aur Shutdown markers skip karne ke liye
            if len(numeric_features) < 6 or sum(numeric_features) == 0:
                # Storage stream clearing operation block
                try:
                    open(ML_LOG_PATH, "w").close()
                except:
                    pass
                continue

            # Live Predictive Classification Block execution 
            risk_score = process_live_prediction(pipeline, numeric_features)
            
            # Realtime Notification Metric Data Output terminal mapping
            print(f"[*] Raw Vector: {numeric_features} | Evaluated Threat Risk: {risk_score * 100:.2f}%")
            
            if risk_score >= ALERT_THRESHOLD:
                print(f"[!!!] THREAT DETECTION ENGINE ALERT: Malicious Activity Confirmed ({risk_score*100:.1f}%)")
                # TODO: Trigger Socket Notification or Active Firewall block here for the Dashboard!

            # Stream Wiping Cleanup: Set File size state to 0 bytes instantly 
            try:
                open(ML_LOG_PATH, "w").close()
            except:
                pass

        # Micro-second resource throttling cycle block (Reduces excessive CPU core overhead)
        time.sleep(0.01)

if __name__ == "__main__":
    try:
        start_engine()
    except KeyboardInterrupt:
        print("\n[*] Prediction Engine shut down gracefully.")

import subprocess

def block_attacker_ip(attacker_ip):
    """
    Windows Netsh Advanced Firewall rule factory.
    Attacker ki IP ko inbound traffic se instant drop karne ke liye.
    """
    rule_name = f"IDS_IPS_AUTO_BLOCK_{attacker_ip}"
    
    # Windows native CMD command to push IP blocklist
    command = (
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f'dir=in action=block protocol=ANY remoteip={attacker_ip}'
    )
    
    try:
        # Command silent execution block
        subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[+++] FIREWALL ACTION: Successfully blocked malicious IP {attacker_ip} globally.")
    except Exception as e:
        print(f"[-] Firewall rule enforcement anomaly: {e}")