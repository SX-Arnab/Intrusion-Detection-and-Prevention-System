import csv
import ipaddress
import logging
import os
import platform
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Set, List, Dict, Any

import joblib
import pandas as pd

STORAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "storage")
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ids_ips_production_pipeline.pkl")
os.makedirs(STORAGE, exist_ok=True)

CONFIG = {
    "csv_path": os.path.join(STORAGE, "model_log.csv"),
    "processed_csv_path": os.path.join(STORAGE, "processed_model_log.csv"),
    "detections_log": os.path.join(STORAGE, "detections.log"),
    "blocked_ips_file": os.path.join(STORAGE, "blocked_ips.txt"),
    "poll_interval": 1.0,
    "batch_size": 64,
    "auto_block_enabled": True,
    "detection_threshold": 0.5,
    "whitelist_ips": {"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
}

BENIGN_LABELS = {"BENIGN", "NORMAL"}

detection_logger = logging.getLogger("detections")
detection_logger.setLevel(logging.INFO)
detection_handler = logging.FileHandler(CONFIG["detections_log"], mode="a", encoding="utf-8")
detection_handler.setFormatter(logging.Formatter("%(message)s"))
detection_logger.addHandler(detection_handler)
detection_logger.propagate = False

logger = logging.getLogger("engine")
logger.setLevel(logging.INFO)
console = logging.StreamHandler()
console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(console)

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def is_whitelisted(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        for entry in CONFIG["whitelist_ips"]:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                if addr in net:
                    return True
            except ValueError:
                if entry == str(addr):
                    return True
        return False
    except ValueError:
        return True

def get_os_family():
    system = platform.system().lower()
    return "windows" if system == "windows" else "linux" if system == "linux" else "unknown"

def block_ip_windows(ip):
    rule = f"HackerAI_Block_{ip}"
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule}", "dir=in", "action=block",
             f"remoteip={ip}", "enable=yes", "profile=any"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        logger.error("netsh failed for IP %s", ip)
        return False

def block_ip_linux(ip):
    try:
        result = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        logger.error("iptables failed for IP %s", ip)
        return False

def block_ip(ip):
    family = get_os_family()
    if family == "windows":
        return block_ip_windows(ip)
    elif family == "linux":
        return block_ip_linux(ip)
    logger.warning("Blocking not supported on %s", family)
    return False

def load_blocked_ips():
    path = Path(CONFIG["blocked_ips_file"])
    if not path.exists():
        return set()
    blocked = set()
    try:
        with open(path, "r") as f:
            for line in f:
                ip = line.strip()
                if ip and is_valid_ip(ip):
                    blocked.add(ip)
    except Exception as e:
        logger.error("Load blocked IPs error: %s", e)
    return blocked

def save_blocked_ip(ip):
    try:
        with open(CONFIG["blocked_ips_file"], "a") as f:
            f.write(f"{ip}\n")
    except Exception as e:
        logger.error("Save blocked IP error: %s", e)

class CsvReader:
    def __init__(self, path):
        self._path = path
        self._last_pos = 0
        self._lock = threading.Lock()

    def read_new_rows(self):
        with self._lock:
            path = Path(self._path)
            if not path.exists():
                return []
            try:
                with open(path, "r", newline="") as f:
                    f.seek(self._last_pos)
                    rows = list(csv.DictReader(f))
                    self._last_pos = f.tell()
                return rows
            except Exception as e:
                logger.error("CSV read error: %s", e)
                return []

class CsvArchiver:
    def __init__(self, source, archive):
        self._source = source
        self._archive = archive
        self._lock = threading.Lock()

    def archive_rows(self, rows):
        if not rows:
            return
        with self._lock:
            try:
                fields = list(rows[0].keys())
                needs_header = not Path(self._archive).exists()
                with open(self._archive, "a", newline="") as fa:
                    writer = csv.DictWriter(fa, fieldnames=fields)
                    if needs_header:
                        writer.writeheader()
                    writer.writerows(rows)
                src_path = Path(self._source)
                if src_path.exists():
                    with open(self._source, "r", newline="") as fs:
                        all_rows = list(csv.DictReader(fs))
                    processed_ids = {r.get("flow_id", "") for r in rows}
                    remaining = [r for r in all_rows if r.get("flow_id", "") not in processed_ids]
                    with open(self._source, "w", newline="") as fs:
                        writer = csv.DictWriter(fs, fieldnames=fields)
                        writer.writeheader()
                        writer.writerows(remaining)
            except Exception as e:
                logger.error("Archive error: %s", e)

class FlowTracker:
    def __init__(self, processed_path):
        self._path = processed_path
        self._ids = set()
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        path = Path(self._path)
        if not path.exists():
            return
        try:
            with open(path, "r") as f:
                for row in csv.DictReader(f):
                    fid = row.get("flow_id", "")
                    if fid:
                        self._ids.add(fid)
        except Exception as e:
            logger.error("Load flows error: %s", e)

    def is_processed(self, flow_id):
        with self._lock:
            return flow_id in self._ids

    def mark_processed(self, flow_id):
        with self._lock:
            self._ids.add(flow_id)

class Predictor:
    def __init__(self, model_path):
        logger.info("Loading model...")
        self._pipeline = joblib.load(model_path)
        logger.info("Model loaded.")
        self._has_proba = hasattr(self._pipeline, "predict_proba")
        self._feature_names = getattr(self._pipeline, "feature_names_in_", None)

    def predict_batch(self, df):
        if df.empty:
            return []
        try:
            if self._feature_names is not None:
                for col in self._feature_names:
                    if col not in df.columns:
                        df[col] = 0.0
                df = df[self._feature_names]
            preds = self._pipeline.predict(df)
            if self._has_proba:
                probas = self._pipeline.predict_proba(df)
                classes = list(self._pipeline.classes_)
                results = []
                for i, p in enumerate(preds):
                    label = str(p)
                    if label in BENIGN_LABELS:
                        results.append({"label": label, "confidence": 1.0, "malicious": False})
                    else:
                        idx = classes.index(p) if p in classes else -1
                        conf = float(probas[i][idx]) if idx >= 0 else 1.0
                        results.append({"label": label, "confidence": conf, "malicious": True})
                return results
            else:
                return [
                    {"label": str(p), "confidence": 1.0, "malicious": str(p) not in BENIGN_LABELS}
                    for p in preds
                ]
        except Exception as e:
            logger.error("Predict error: %s", e)
            return []

class IPBlocker:
    def __init__(self, blocked_file, enabled):
        self._file = blocked_file
        self._enabled = enabled
        self._blocked = load_blocked_ips()
        self._lock = threading.Lock()
        logger.info("Loaded %d blocked IPs.", len(self._blocked))

    def block(self, ip):
        if not self._enabled:
            return False
        if not is_valid_ip(ip):
            logger.warning("Invalid IP: %s", ip)
            return False
        if is_whitelisted(ip):
            logger.info("Whitelisted IP skipped: %s", ip)
            return False
        with self._lock:
            if ip in self._blocked:
                return True
            if block_ip(ip):
                self._blocked.add(ip)
                save_blocked_ip(ip)
                logger.info("Blocked IP: %s", ip)
                return True
            logger.error("Block failed for IP: %s", ip)
            return False

class Engine:
    def __init__(self):
        self._reader = CsvReader(CONFIG["csv_path"])
        self._archiver = CsvArchiver(CONFIG["csv_path"], CONFIG["processed_csv_path"])
        self._tracker = FlowTracker(CONFIG["processed_csv_path"])
        self._predictor = Predictor(MODEL_PATH)
        self._blocker = IPBlocker(CONFIG["blocked_ips_file"], CONFIG["auto_block_enabled"])
        self._detect_queue = queue.Queue()
        self._block_queue = queue.Queue()
        self._shutdown = threading.Event()

    def start(self):
        logger.info("Starting engine.")
        threads = [
            threading.Thread(target=self._monitor, daemon=True),
            threading.Thread(target=self._predict, daemon=True),
            threading.Thread(target=self._block_loop, daemon=True),
        ]
        for t in threads:
            t.start()
        logger.info("Engine running.")

    def stop(self):
        logger.info("Stopping engine.")
        self._shutdown.set()

    def _monitor(self):
        while not self._shutdown.is_set():
            try:
                rows = self._reader.read_new_rows()
                if rows:
                    self._detect_queue.put(rows)
            except Exception as e:
                logger.error("Monitor error: %s", e)
            self._shutdown.wait(CONFIG["poll_interval"])

    def _predict(self):
        pending = []
        last_time = time.monotonic()
        while not self._shutdown.is_set():
            try:
                try:
                    rows = self._detect_queue.get(timeout=0.1)
                    pending.extend(rows)
                except queue.Empty:
                    pass
                elapsed = time.monotonic() - last_time
                if len(pending) >= CONFIG["batch_size"] or (pending and elapsed >= 1.0):
                    self._process(pending)
                    pending.clear()
                    last_time = time.monotonic()
            except Exception as e:
                logger.error("Predict loop error: %s", e)

    def _process(self, rows):
        if not rows:
            return
        unprocessed = []
        for row in rows:
            fid = row.get("flow_id", "")
            if fid and not self._tracker.is_processed(fid):
                unprocessed.append(row)
        if not unprocessed:
            return
        df = pd.DataFrame(unprocessed)
        results = self._predictor.predict_batch(df)
        if not results:
            return
        for row, res in zip(unprocessed, results):
            fid = row.get("flow_id", "")
            if not fid:
                continue
            self._tracker.mark_processed(fid)
            if res["malicious"] and res["confidence"] >= CONFIG["detection_threshold"]:
                src = row.get("src_ip", "")
                dst = row.get("dst_ip", "")
                attack = res["label"]
                conf = res["confidence"]
                logger.info("Attack: %s -> %s | %s (%.4f)", src, dst, attack, conf)
                detection_logger.info(
                    "[%s]\nSRC=%s\nDST=%s\nATTACK=%s\nCONFIDENCE=%.4f\nFLOW_ID=%s\n",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    src, dst, attack, conf, fid,
                )
                if src:
                    self._block_queue.put(src)
        self._archiver.archive_rows(unprocessed)

    def _block_loop(self):
        while not self._shutdown.is_set():
            try:
                try:
                    ip = self._block_queue.get(timeout=0.5)
                    self._blocker.block(ip)
                except queue.Empty:
                    pass
            except Exception as e:
                logger.error("Block loop error: %s", e)

if __name__ == "__main__":
    try:
        Engine().start()
        print("Engine running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nEngine stopped.")
        sys.exit(0)