import csv
import os
import time
import math
import threading
import queue
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

FLOW_TIMEOUT = 120.0
ACTIVITY_TIMEOUT = 5.0

STORAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "storage")
os.makedirs(STORAGE, exist_ok=True)

CSV_FILE = os.path.join(STORAGE, "model_log.csv")
LOG_FILE = os.path.join(STORAGE, "logs.txt")

CSV_COLUMNS = [
    "timestamp","flow_id","src_ip","dst_ip","src_port","dst_port","protocol",
    "flow_duration","flow_bytes_per_s","flow_packets_per_s",
    "total_fwd_packets","total_length_fwd_packets",
    "fwd_packet_length_max","fwd_packet_length_min","fwd_packet_length_mean","fwd_packet_length_std",
    "total_bwd_packets","total_length_bwd_packets",
    "bwd_packet_length_max","bwd_packet_length_min","bwd_packet_length_mean","bwd_packet_length_std",
    "flow_iat_mean","flow_iat_std","flow_iat_max","flow_iat_min",
    "fwd_iat_mean","fwd_iat_std","fwd_iat_max","fwd_iat_min",
    "bwd_iat_mean","bwd_iat_std","bwd_iat_max","bwd_iat_min",
    "fin_flag_count","syn_flag_count","rst_flag_count","psh_flag_count",
    "ack_flag_count","urg_flag_count","ece_flag_count","cwr_flag_count",
    "packet_length_min","packet_length_max","packet_length_mean","packet_length_std",
    "average_packet_size","down_up_ratio",
    "subflow_fwd_packets","subflow_fwd_bytes",
    "subflow_bwd_packets","subflow_bwd_bytes",
    "init_fwd_win_bytes","init_bwd_win_bytes",
    "active_mean","active_std","active_max","active_min",
    "idle_mean","idle_std","idle_max","idle_min",
]

def _mean(values):
    return sum(values) / len(values) if values else 0.0

def _std(values):
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return math.sqrt(sum((v - m) ** 2 for v in values) / len(values))

def _safe_div(a, b):
    return a / b if b != 0 else 0.0

@dataclass
class FlowRecord:
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    start_time: float = 0.0
    last_time: float = 0.0
    fwd_lengths: list = field(default_factory=list)
    bwd_lengths: list = field(default_factory=list)
    all_lengths: list = field(default_factory=list)
    fwd_timestamps: list = field(default_factory=list)
    bwd_timestamps: list = field(default_factory=list)
    all_timestamps: list = field(default_factory=list)
    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    ece_count: int = 0
    cwr_count: int = 0
    init_fwd_win: int = -1
    init_bwd_win: int = -1
    active_periods: list = field(default_factory=list)
    idle_periods: list = field(default_factory=list)
    _activity_start: float = 0.0
    _last_active: float = 0.0

    def add_packet(self, pkt, is_forward):
        ts = pkt.timestamp
        length = pkt.packet_length
        if not self.all_timestamps:
            self.start_time = ts
            self._activity_start = ts
            self._last_active = ts
        else:
            gap = ts - self._last_active
            if gap > ACTIVITY_TIMEOUT:
                active_dur = self._last_active - self._activity_start
                if active_dur > 0:
                    self.active_periods.append(active_dur)
                self.idle_periods.append(gap)
                self._activity_start = ts
            self._last_active = ts
        self.last_time = ts
        self.all_timestamps.append(ts)
        self.all_lengths.append(length)
        if is_forward:
            self.fwd_timestamps.append(ts)
            self.fwd_lengths.append(length)
            if self.init_fwd_win == -1 and pkt.tcp_flags & 0x02:
                self.init_fwd_win = getattr(pkt, "window_size", 0)
        else:
            self.bwd_timestamps.append(ts)
            self.bwd_lengths.append(length)
            if self.init_bwd_win == -1 and pkt.tcp_flags & 0x02:
                self.init_bwd_win = getattr(pkt, "window_size", 0)
        flags = pkt.tcp_flags
        if flags & 0x01: self.fin_count += 1
        if flags & 0x02: self.syn_count += 1
        if flags & 0x04: self.rst_count += 1
        if flags & 0x08: self.psh_count += 1
        if flags & 0x10: self.ack_count += 1
        if flags & 0x20: self.urg_count += 1
        if flags & 0x40: self.ece_count += 1
        if flags & 0x80: self.cwr_count += 1

    def _iat_features(self, timestamps):
        if len(timestamps) < 2:
            return 0.0, 0.0, 0.0, 0.0
        iats = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        return _mean(iats), _std(iats), max(iats), min(iats)

    def _finalize_activity(self):
        active_dur = self._last_active - self._activity_start
        if active_dur > 0:
            self.active_periods.append(active_dur)

    def extract_features(self):
        self._finalize_activity()
        duration = max(self.last_time - self.start_time, 1e-9)
        total_pkts = len(self.all_lengths)
        total_bytes = sum(self.all_lengths)
        fwd_count = len(self.fwd_lengths)
        bwd_count = len(self.bwd_lengths)
        fwd_bytes = sum(self.fwd_lengths)
        bwd_bytes = sum(self.bwd_lengths)
        fwd_max = max(self.fwd_lengths) if self.fwd_lengths else 0
        fwd_min = min(self.fwd_lengths) if self.fwd_lengths else 0
        fwd_mean = _mean(self.fwd_lengths)
        fwd_std = _std(self.fwd_lengths)
        bwd_max = max(self.bwd_lengths) if self.bwd_lengths else 0
        bwd_min = min(self.bwd_lengths) if self.bwd_lengths else 0
        bwd_mean = _mean(self.bwd_lengths)
        bwd_std = _std(self.bwd_lengths)
        flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = self._iat_features(self.all_timestamps)
        fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = self._iat_features(self.fwd_timestamps)
        bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = self._iat_features(self.bwd_timestamps)
        pkt_len_min = min(self.all_lengths) if self.all_lengths else 0
        pkt_len_max = max(self.all_lengths) if self.all_lengths else 0
        pkt_len_mean = _mean(self.all_lengths)
        pkt_len_std = _std(self.all_lengths)
        avg_pkt_size = _safe_div(total_bytes, total_pkts)
        down_up_ratio = _safe_div(bwd_bytes, fwd_bytes) if fwd_bytes > 0 else 0.0
        active_mean = _mean(self.active_periods)
        active_std = _std(self.active_periods)
        active_max = max(self.active_periods) if self.active_periods else 0.0
        active_min = min(self.active_periods) if self.active_periods else 0.0
        idle_mean = _mean(self.idle_periods)
        idle_std = _std(self.idle_periods)
        idle_max = max(self.idle_periods) if self.idle_periods else 0.0
        idle_min = min(self.idle_periods) if self.idle_periods else 0.0
        flow_id = f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"
        return {
            "timestamp": round(self.start_time, 6),
            "flow_id": flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "flow_duration": round(duration * 1e6, 3),
            "flow_bytes_per_s": round(_safe_div(total_bytes, duration), 6),
            "flow_packets_per_s": round(_safe_div(total_pkts, duration), 6),
            "total_fwd_packets": fwd_count,
            "total_length_fwd_packets": fwd_bytes,
            "fwd_packet_length_max": fwd_max,
            "fwd_packet_length_min": fwd_min,
            "fwd_packet_length_mean": round(fwd_mean, 6),
            "fwd_packet_length_std": round(fwd_std, 6),
            "total_bwd_packets": bwd_count,
            "total_length_bwd_packets": bwd_bytes,
            "bwd_packet_length_max": bwd_max,
            "bwd_packet_length_min": bwd_min,
            "bwd_packet_length_mean": round(bwd_mean, 6),
            "bwd_packet_length_std": round(bwd_std, 6),
            "flow_iat_mean": round(flow_iat_mean * 1e6, 3),
            "flow_iat_std": round(flow_iat_std * 1e6, 3),
            "flow_iat_max": round(flow_iat_max * 1e6, 3),
            "flow_iat_min": round(flow_iat_min * 1e6, 3),
            "fwd_iat_mean": round(fwd_iat_mean * 1e6, 3),
            "fwd_iat_std": round(fwd_iat_std * 1e6, 3),
            "fwd_iat_max": round(fwd_iat_max * 1e6, 3),
            "fwd_iat_min": round(fwd_iat_min * 1e6, 3),
            "bwd_iat_mean": round(bwd_iat_mean * 1e6, 3),
            "bwd_iat_std": round(bwd_iat_std * 1e6, 3),
            "bwd_iat_max": round(bwd_iat_max * 1e6, 3),
            "bwd_iat_min": round(bwd_iat_min * 1e6, 3),
            "fin_flag_count": self.fin_count,
            "syn_flag_count": self.syn_count,
            "rst_flag_count": self.rst_count,
            "psh_flag_count": self.psh_count,
            "ack_flag_count": self.ack_count,
            "urg_flag_count": self.urg_count,
            "ece_flag_count": self.ece_count,
            "cwr_flag_count": self.cwr_count,
            "packet_length_min": pkt_len_min,
            "packet_length_max": pkt_len_max,
            "packet_length_mean": round(pkt_len_mean, 6),
            "packet_length_std": round(pkt_len_std, 6),
            "average_packet_size": round(avg_pkt_size, 6),
            "down_up_ratio": round(down_up_ratio, 6),
            "subflow_fwd_packets": fwd_count,
            "subflow_fwd_bytes": fwd_bytes,
            "subflow_bwd_packets": bwd_count,
            "subflow_bwd_bytes": bwd_bytes,
            "init_fwd_win_bytes": max(self.init_fwd_win, 0),
            "init_bwd_win_bytes": max(self.init_bwd_win, 0),
            "active_mean": round(active_mean * 1e6, 3),
            "active_std": round(active_std * 1e6, 3),
            "active_max": round(active_max * 1e6, 3),
            "active_min": round(active_min * 1e6, 3),
            "idle_mean": round(idle_mean * 1e6, 3),
            "idle_std": round(idle_std * 1e6, 3),
            "idle_max": round(idle_max * 1e6, 3),
            "idle_min": round(idle_min * 1e6, 3),
        }

class FlowTable:
    def __init__(self):
        self._flows = {}
        self._lock = threading.Lock()

    def _make_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        fwd = (src_ip, dst_ip, src_port, dst_port, protocol)
        bwd = (dst_ip, src_ip, dst_port, src_port, protocol)
        with self._lock:
            if fwd in self._flows:
                return fwd, True
            if bwd in self._flows:
                return bwd, False
        return fwd, True

    def get_or_create(self, pkt):
        key, is_fwd = self._make_key(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        with self._lock:
            if key not in self._flows:
                self._flows[key] = FlowRecord()
                self._flows[key].src_ip = key[0]
                self._flows[key].dst_ip = key[1]
                self._flows[key].src_port = key[2]
                self._flows[key].dst_port = key[3]
                self._flows[key].protocol = key[4]
        return self._flows[key], is_fwd, key

    def expire(self, current_time, timeout):
        expired = []
        with self._lock:
            keys = [k for k, v in self._flows.items() if (current_time - v.last_time) >= timeout]
            for k in keys:
                expired.append(self._flows.pop(k))
        return expired

    def expire_by_rst_fin(self, key):
        with self._lock:
            return self._flows.pop(key, None)

    def flush_all(self):
        with self._lock:
            records = list(self._flows.values())
            self._flows.clear()
        return records

class FlowManager:
    def __init__(self, packet_queue, flow_timeout=FLOW_TIMEOUT):
        self.packet_queue = packet_queue
        self.flow_timeout = flow_timeout
        self.flow_table = FlowTable()
        self._csv_lock = threading.Lock()
        self._log_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._expire_interval = min(flow_timeout / 4, 30.0)
        self._init_csv()

    def _init_csv(self):
        write_header = not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0
        if write_header:
            with open(CSV_FILE, "a", newline="") as f:
                csv.DictWriter(f, fieldnames=CSV_COLUMNS).writeheader()

    def _write_csv(self, record):
        with self._csv_lock:
            with open(CSV_FILE, "a", newline="") as f:
                csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore").writerow(record)

    def _write_log(self, record):
        with self._log_lock:
            with open(LOG_FILE, "a") as f:
                f.write(f"[Flow Processed]\n")
                f.write(f"Timestamp     : {record['timestamp']}\n")
                f.write(f"Flow ID       : {record['flow_id']}\n")
                f.write(f"Source        : {record['src_ip']}:{record['src_port']}\n")
                f.write(f"Destination   : {record['dst_ip']}:{record['dst_port']}\n")
                f.write(f"Protocol      : {record['protocol']}\n")
                f.write(f"Duration      : {record['flow_duration']} us\n")
                f.write(f"Total Packets : {record['total_fwd_packets'] + record['total_bwd_packets']}\n")
                f.write(f"Total Bytes   : {record['total_length_fwd_packets'] + record['total_length_bwd_packets']}\n")
                f.write(f"Fwd Packets   : {record['total_fwd_packets']}\n")
                f.write(f"Bwd Packets   : {record['total_bwd_packets']}\n")
                f.write(f"Flow Bytes/s  : {record['flow_bytes_per_s']}\n")
                f.write(f"Flow Pkts/s   : {record['flow_packets_per_s']}\n")
                f.write("---\n")

    def _handle_packet(self, pkt):
        record, is_fwd, key = self.flow_table.get_or_create(pkt)
        record.add_packet(pkt, is_fwd)
        flags = pkt.tcp_flags
        if flags & 0x04:
            expired = self.flow_table.expire_by_rst_fin(key)
            if expired:
                self._flush_record(expired)
        elif (flags & 0x01) and record.fin_count >= 2:
            expired = self.flow_table.expire_by_rst_fin(key)
            if expired:
                self._flush_record(expired)

    def _flush_record(self, record):
        if not record.all_timestamps:
            return
        features = record.extract_features()
        self._write_csv(features)
        self._write_log(features)

    def _expire_loop(self):
        while not self._stop_event.is_set():
            time.sleep(self._expire_interval)
            now = time.time()
            for record in self.flow_table.expire(now, self.flow_timeout):
                self._flush_record(record)

    def run(self):
        expire_thread = threading.Thread(target=self._expire_loop, daemon=True)
        expire_thread.start()
        while not self._stop_event.is_set():
            try:
                pkt = self.packet_queue.get(timeout=1.0)
                self._handle_packet(pkt)
            except queue.Empty:
                continue
            except Exception:
                continue
        expire_thread.join(timeout=5)

    def stop(self):
        self._stop_event.set()
        for record in self.flow_table.flush_all():
            self._flush_record(record)