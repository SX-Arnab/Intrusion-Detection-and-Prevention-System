import logging
import queue
import threading
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("sniffer")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _console = logging.StreamHandler()
    _console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(_console)


@dataclass
class PacketInfo:
    """Normalised packet record passed from Sniffer → FlowManager."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packet_length: int
    tcp_flags: int       # raw TCP flag bitmask (0 for non-TCP)
    window_size: int     # TCP window size (0 for non-TCP)


class Sniffer:
    """
    Live packet capture using scapy.

    Parses each captured IP packet into a PacketInfo and puts it onto
    an internal queue that FlowManager drains.

    Usage:
        sniffer = Sniffer(iface="eth0")   # omit iface to sniff all interfaces
        queue   = sniffer.get_queue()
        sniffer.start()   # blocks; run in a daemon thread
        ...
        sniffer.stop()
    """

    def __init__(self, iface: Optional[str] = None, queue_maxsize: int = 10_000):
        self._iface = iface
        self._pkt_queue: queue.Queue = queue.Queue(maxsize=queue_maxsize)
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_queue(self) -> queue.Queue:
        """Return the packet queue consumed by FlowManager."""
        return self._pkt_queue

    def start(self) -> None:
        """Begin capturing packets (blocking).  Run inside a daemon thread."""
        iface_label = f" on {self._iface}" if self._iface else " on all interfaces"
        logger.info("Sniffer starting%s.", iface_label)
        try:
            from scapy.all import sniff  # type: ignore
            sniff(
                iface=self._iface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except Exception as exc:
            logger.error("Sniffer fatal error: %s", exc)

    def stop(self) -> None:
        """Signal the capture loop to stop."""
        logger.info("Sniffer stopping.")
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _process_packet(self, pkt) -> None:
        """Scapy callback: convert a raw packet to PacketInfo and enqueue it."""
        try:
            from scapy.layers.inet import IP, TCP, UDP  # type: ignore

            if not pkt.haslayer(IP):
                return

            ip = pkt[IP]
            src_ip: str = ip.src
            dst_ip: str = ip.dst
            proto: int  = ip.proto
            ts: float   = float(pkt.time)
            length: int = len(pkt)

            src_port:    int = 0
            dst_port:    int = 0
            tcp_flags:   int = 0
            window_size: int = 0

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port    = tcp.sport
                dst_port    = tcp.dport
                tcp_flags   = int(tcp.flags)
                window_size = tcp.window
            elif pkt.haslayer(UDP):
                udp      = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport

            info = PacketInfo(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                packet_length=length,
                tcp_flags=tcp_flags,
                window_size=window_size,
            )

            try:
                self._pkt_queue.put_nowait(info)
            except queue.Full:
                logger.warning("Packet queue full — dropping packet.")

        except Exception as exc:
            logger.error("Packet processing error: %s", exc)
