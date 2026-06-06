import os
import sys
import signal
import threading
import time

from core.sniffer import Sniffer
from core.parser import FlowManager
from core.engine.engine import Engine


def main():
    sniffer_mgr = Sniffer()
    flow_mgr = FlowManager(sniffer_mgr.get_queue())
    engine = Engine()

    threads = [
        threading.Thread(target=sniffer_mgr.start, daemon=True),
        threading.Thread(target=flow_mgr.run, daemon=True),
        threading.Thread(target=engine.start, daemon=True),
    ]

    for t in threads:
        t.start()

    print("IDS/IPS running. Press Ctrl+C to stop.")

    def stop(sig, frame):
        print("\nStopping...")
        sniffer_mgr.stop()
        flow_mgr.stop()
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
