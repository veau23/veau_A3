import re
import sys
import time
from datetime import datetime
from easysnmp import Session

# SNMP OIDs for polling router information
SYSUPTIME_OID = "1.3.6.1.2.1.1.3.0"
ARP_MAC_OID = "1.3.6.1.2.1.4.22.1.2"
ARP_TYPE_OID = "1.3.6.1.2.1.4.22.1.4"

# Stores ARP polling result
class ARPSnapshot:
    def __init__(self):
        self.timestamp = datetime.now()
        self.arp_table = {}
        self.sysuptime = None
        self.reset_detected = False

# Stores previous router monitoring data
class RouterState:
    def __init__(self, router_id):

        self.router_id = router_id
        self.previous_snapshot = {}
        self.previous_uptime = None
        self.last_poll_time = None

    def update_state(
        self,
        snapshot,
        uptime
    ):
        self.previous_snapshot = snapshot
        self.previous_uptime = uptime
        self.last_poll_time = datetime.now()
    def print_state(self):

        print("\n[ROUTER STATE]")
        print(
            f"Router ID: "
            f"{self.router_id}"
        )
        print(
            f"Previous Snapshot Size: "
            f"{len(self.previous_snapshot)}"
        )
        print(
            f"Previous Uptime: "
            f"{self.previous_uptime}"
        )
        print(
            f"Last Poll Time: "
            f"{self.last_poll_time}"
        )
# Stores router states using router IP as key
router_states = {}

# Create new router state object
def create_router_state(router_id):
    print(
        f"[DEBUG] Creating state for router: "
        f"{router_id}"
    )
    state = RouterState(router_id)
    router_states[router_id] = state
    return state
# Return existing router state or create a new one
def get_router_state(router_id):
    if router_id not in router_states:
        return create_router_state(router_id)
    return router_states[router_id]

# Read input arguments meant for runtime
def parse_input_arguments(argv):

    print("[DEBUG] Parsing input arguments")

    if len(argv) < 3:
        raise ValueError(
            "Usage: python arpwatch.py "
            "<interval> <ip:port:community> "
            "[ip:port:community ...]"
        )

    interval = float(argv[1])

    devices = []

    ipv4_pattern = (
        r'^('
        r'(25[0-5]|2[0-4][0-9]|'
        r'[01]?[0-9][0-9]?)\.'
        r'){3}'
        r'(25[0-5]|2[0-4][0-9]|'
        r'[01]?[0-9][0-9]?)$'
    )

    for device_string in argv[2:]:

        connection_parts = device_string.split(":")

        if len(connection_parts) != 3:
            raise ValueError(
                f"Invalid device format: {device_string}"
            )

        ip, port_str, community = [
    part.strip()
    for part in connection_parts
]

        if not re.match(ipv4_pattern, ip):
            raise ValueError(f"Invalid IP address: {ip}")

        device_config = {
            "ip": ip,
            "port": int(port_str),
            "community": community.strip()
        }

        print(f"[DEBUG] Loaded device: {device_config}")

        devices.append(device_config)

    return {
        "interval": interval,
        "devices": devices
    }

# Create EasySNMP session with router
def create_snmp_session(config):
    print("[DEBUG] Creating SNMP session")
    session = Session(
        hostname=config["ip"],
        community=config["community"],
        version=2,
        remote_port=config["port"],
        timeout=2,
        retries=1
    )
    print("[DEBUG] SNMP session created")
    return session

# Poll router uptime and detect reboot
def fetch_sysuptime(session, previous_uptime=None):
    print("[DEBUG] Fetching sysUpTime")
    try:
        response = session.get(SYSUPTIME_OID)
        current_uptime = int(response.value)
        print(f"[DEBUG] Current sysUpTime: {current_uptime}")
    except Exception as e:
        print(f"[ERROR] Failed to fetch sysUpTime: {e}")
        return {
            "uptime": None,
            "reset_detected": False
        }
    reset_detected = False
    if previous_uptime is not None:
        print(f"[DEBUG] Previous sysUpTime: {previous_uptime}")
        if current_uptime < previous_uptime:
            reset_detected = True
            print("[DEBUG] RESET EVENT DETECTED: Uptime decreased")
    return {
        "uptime": current_uptime,
        "reset_detected": reset_detected
    }
# Convert MAC addresses into readable format
def normalize_mac(mac_raw):
    mac_raw = str(mac_raw)
    if mac_raw.startswith("0x"):
        hex_string = mac_raw.replace("0x", "")
        if len(hex_string) % 2 != 0:
            hex_string = "0" + hex_string
        mac = ":".join(
            hex_string[i:i + 2]
            for i in range(0, len(hex_string), 2)
        )
        return mac.lower()
    mac = ":".join(
        f"{ord(x):02x}"
        for x in mac_raw
    )
    return mac.lower()
# Retrieve and parse ARP table entries
def fetch_arp_table(session):

    print("[DEBUG] Fetching ARP table")

    try:

        mac_entries = session.walk(ARP_MAC_OID)

        type_entries = session.walk(ARP_TYPE_OID)

    except Exception as e:

        print(f"[ERROR] Failed to walk ARP table: {e}")

        return {}

    print(f"[DEBUG] Retrieved {len(mac_entries)} MAC entries")

    print(f"[DEBUG] Retrieved {len(type_entries)} TYPE entries")
# Match MAC entries with their ARP type values
    type_lookup = {}

    for entry in type_entries:

        full_oid = entry.oid

        oid_parts = full_oid.split(".")

        suffix = ".".join(
            oid_parts[-5:]
        )

        type_lookup[suffix] = int(
            entry.value
        )
# Store valid ARP entries using IP as dictionary key
    arp_table = {}

    for entry in mac_entries:

        full_oid = entry.oid

        oid_parts = full_oid.split(".")

        suffix_parts = oid_parts[-5:]

        if len(suffix_parts) < 5:

            continue
# Get interface index from OID
        if_index = int(suffix_parts[0])
# Build device IP address from OID suffix
        ip = ".".join(suffix_parts[1:5])
        suffix = ".".join(suffix_parts)
        entry_type = type_lookup.get(suffix)

        print(
            f"[DEBUG] ENTRY TYPE FOR {ip}: "
            f"{entry_type}"
        )

        if entry_type == 2:

            print(
                f"[DEBUG] Skipping invalid ARP entry for {ip}"
            )

            continue
# Convert raw MAC value into standard format
        mac = normalize_mac(entry.value)

        parsed_entry = {
            "ip": ip,
            "mac": mac,
            "ifIndex": if_index,
            "type": entry_type
        }

        print(
            f"[DEBUG] Parsed Entry: "
            f"{parsed_entry}"
        )

        arp_table[ip] = parsed_entry

    print(
        f"\n[DEBUG] Final ARP table size: "
        f"{len(arp_table)}"
    )

    return arp_table
# Compare old and new ARP snapshots
def compare_snapshots(old_snapshot, new_snapshot):
    events = {
        "new_hosts": [],
        "gone_hosts": [],
        "mac_changes": [],
        "status": "unchanged"
    }
# Collect IPs from both snapshots
    old_ips = set(old_snapshot.arp_table.keys()) if old_snapshot else set()
    new_ips = set(new_snapshot.arp_table.keys())
# Detect newly discovered hosts
    new_hosts = new_ips - old_ips
    for ip in new_hosts:
        events["new_hosts"].append({
            "ip": ip,
            "mac": new_snapshot.arp_table[ip]["mac"],
            "timestamp": new_snapshot.timestamp
        })
        print(f"[DEBUG] NEW_HOST: {ip} -> {new_snapshot.arp_table[ip]['mac']}")
# Detect hosts that disappeared
    gone_hosts = old_ips - new_ips
    for ip in gone_hosts:
        events["gone_hosts"].append({
            "ip": ip,
            "mac": old_snapshot.arp_table[ip]["mac"],
            "timestamp": new_snapshot.timestamp
        })
        print(f"[DEBUG] GONE_HOST: {ip} -> {old_snapshot.arp_table[ip]['mac']}")
# Compare MAC addresses for existing hosts
    common_ips = old_ips & new_ips
    for ip in common_ips:
        old_mac = old_snapshot.arp_table[ip]["mac"]
        new_mac = new_snapshot.arp_table[ip]["mac"]
        if old_mac != new_mac:
            events["mac_changes"].append({
                "ip": ip,
                "old_mac": old_mac,
                "new_mac": new_mac,
                "timestamp": new_snapshot.timestamp
            })
            print(f"[DEBUG] MAC_CHANGE: {ip} {old_mac} -> {new_mac}")
# Update snapshot status if changes were detected
    if events["new_hosts"] or events["gone_hosts"] or events["mac_changes"]:
        events["status"] = "changed"
    else:
        print("[DEBUG] Snapshot unchanged")

    return events
# Print detected network events
def print_events(events):
    if events["status"] == "unchanged":
        return

    print(f"\n[EVENTS] {events['status'].upper()} - {datetime.now()}")
    for new_host in events["new_hosts"]:
        print(
            f"  [NEW_HOST] "
            f"{new_host['ip']} -> "
            f"{new_host['mac']}"
        )
    for gone_host in events["gone_hosts"]:
        print(
            f"  [GONE_HOST] "
            f"{gone_host['ip']} -> "
            f"{gone_host['mac']}"
        )
    for mac_change in events["mac_changes"]:
        print(
            f"  [MAC_CHANGE] "
            f"{mac_change['ip']} changed "
            f"from {mac_change['old_mac']} "
            f"to {mac_change['new_mac']}"
        )
# Main polling loop
def main_loop(config):
    session = create_snmp_session(config)
    state = get_router_state(config["ip"])
    previous_snapshot = None
    iteration = 0
    MAX_ITERATIONS = 3
    
    print(f"\n[MONITOR] Starting ARP monitoring")
    print(f"[MONITOR] Polling every {config['interval']} seconds")
    print(f"[MONITOR] Press Ctrl+C to stop\n")
    
    while iteration < MAX_ITERATIONS:
        try:
            iteration += 1
            print(f"\n[ITERATION] #{iteration} - {datetime.now()}")
            
            # Start timer for fixed-rate scheduling
            poll_start_time = time.time()
            
            # Fetch uptime
            uptime_result = fetch_sysuptime(session, state.previous_uptime)
            
            # Handle TIMEOUT
            if uptime_result["uptime"] is None:
                print("[TIMEOUT_EVENT] Router did not respond or polling failed")
                poll_failed = True
            else:
                poll_failed = False
                
                # Handle reset 
                if uptime_result.get("reset_detected"):
                    print("[RESET_EVENT] Router reboot detected. Clearing previous baseline.")
                    previous_snapshot = None  # Discard old baseline
                
                # Fetch ARP table
                current_arp_table = fetch_arp_table(session)
                
                # Build current snapshot
                current_snapshot = ARPSnapshot()
                current_snapshot.arp_table = current_arp_table
                current_snapshot.sysuptime = uptime_result.get("uptime")
                current_snapshot.reset_detected = uptime_result.get("reset_detected")
                
                print(f"[DEBUG] Snapshot created | Timestamp: {current_snapshot.timestamp} | ARP entries: {len(current_arp_table)}")
                
                # Compare snapshots 
                if previous_snapshot and not uptime_result.get("reset_detected"):
                    events = compare_snapshots(previous_snapshot, current_snapshot)
                    print_events(events)
                    total_changes = (
                        len(events["new_hosts"]) +
                        len(events["gone_hosts"]) +
                        len(events["mac_changes"])
                    )
                    if total_changes > 0:
                        print(f"[SUMMARY] Total changes: {total_changes}")
                elif uptime_result.get("reset_detected"):
                    print("[DEBUG] Comparison skipped. Current snapshot establishes new baseline.")
                
                # Store current snapshot as the new baseline for next iteration
                previous_snapshot = current_snapshot
                state.previous_uptime = uptime_result["uptime"]
                
            # Update timestamp and maintain fixed rate regardless of timeout/reset
            state.last_poll_time = datetime.now()
            
            elapsed_time = time.time() - poll_start_time
            remaining_sleep = config["interval"] - elapsed_time
            
            if remaining_sleep > 0:
                time.sleep(remaining_sleep)
            else:
                print(
                    f"[WARNING] Poll took {elapsed_time:.2f}s, "
                    f"exceeding the {config['interval']}s interval. "
                    f"Skipping sleep to maintain cadence."
                )
                
        except KeyboardInterrupt:
            print(f"\n[STOP] Stopping ARP monitor after {iteration} iterations")
            break
        except Exception as e:
            print(f"[ERROR] Iteration failed: {e}")
            time.sleep(config["interval"])
# Program entry point
if __name__ == "__main__":

    if len(sys.argv) < 3:
        print(
            "Usage: python arpwatch.py "
            "<interval_seconds> "
            "<ip:port:community> "
            "[ip:port:community ...]"
        )

        print(
            "Example: python arpwatch.py "
            "5.0 "
            "192.168.1.1:161:public "
            "192.168.1.2:161:public"
        )

        sys.exit(1)

    print(f"[DEBUG] Runtime Input: {sys.argv[1:]}")

    try:

        config = parse_input_arguments(sys.argv)

        # Run script in test mode
        if "--test" in sys.argv:

            for device in config["devices"]:

                print(
                    f"\n[TEST] Running test for "
                    f"{device['ip']}"
                )

                device_config = {
                    "interval": config["interval"],
                    "ip": device["ip"],
                    "port": device["port"],
                    "community": device["community"]
                }

                session = create_snmp_session(device_config)

                uptime_result = fetch_sysuptime(session)

                print("\n[INFO] sysUpTime Result")
                print(uptime_result)

                arp_entries = fetch_arp_table(session)

                print("\n[INFO] FINAL ARP TABLE")

                for ip, entry in arp_entries.items():

                    print(
                        f"IP: {entry['ip']}, "
                        f"MAC: {entry['mac']}, "
                        f"Interface: {entry['ifIndex']}, "
                        f"Type: {entry['type']}"
                    )

        else:

            # Start monitoring for all devices
            for device in config["devices"]:

                device_config = {
                    "interval": config["interval"],
                    "ip": device["ip"],
                    "port": device["port"],
                    "community": device["community"]
                }

                print(
                    f"\n[MONITOR] Starting monitor for "
                    f"{device['ip']}"
                )

                main_loop(device_config)

    except Exception as e:

        print(f"[FATAL] Error: {e}")

        sys.exit(1)