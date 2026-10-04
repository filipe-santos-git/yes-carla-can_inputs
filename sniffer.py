import can
import csv
import time
from pathlib import Path
from can_network import VCAN_CHANNEL, CAN_INTERFACE

LOG_DIR = Path("traffic_logs")
LOG_FILE = LOG_DIR / "can_sniffer.csv"


def capture_traffic(duration=None):
    print("start sniffing module")
    bus = can.interface.Bus(
        channel=VCAN_CHANNEL,
        bustype=CAN_INTERFACE
    )

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    start_time = time.time()

    with open(LOG_FILE, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "timestamp",
            "arbitration_id",
            "dlc",
            "data",
            "is_extended_id"
        ])

        while True:
            if duration is not None:
                elapsed = time.time() - start_time

                if elapsed >= duration:
                    break

            msg = bus.recv(timeout=0.1)

            if msg is None:
                continue

            writer.writerow([
                msg.timestamp,
                msg.arbitration_id,
                msg.dlc,
                msg.data.hex().upper(),
                msg.is_extended_id
            ])

    bus.shutdown()

def main():
    try:
        capture_traffic()
        print("shutdown_sniffer_Module")

    except KeyboardInterrupt:
        print("sniffer stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        bus.shutdown()

if __name__ == "__main__":
    main()