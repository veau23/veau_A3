import re
import sys
import time
from datetime import datetime
from easysnmp import Session
import threading

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

        self.session = None

        self.previous_snapshot = None

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
        print(f"Router ID: "f"{self.router_id}")
        print(f"Previous Uptime: "f"{self.previous_uptime}")
        print(f"Last Poll Time: "f"{self.last_poll_time}")
# Stores router states using router IP as key
router_states = {}

# Create new router state object
def create_router_state(router_id):
    #print(f" Creating state for router: "f"{router_id}")
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
        devices.append(device_config)

    return {
        "interval": interval,
        "devices": devices
    }

# Create EasySNMP session with router
def create_snmp_session(config):
    session = Session(
        hostname=config["ip"],
        community=config["community"],
        version=2,
        remote_port=config["port"],
        timeout=2,
        retries=1
    )
    return session

# Poll router uptime and detect reboot
def fetch_sysuptime(session, previous_uptime=None):
    #print(" Fetching sysUpTime")
    try:
        response = session.get(SYSUPTIME_OID)
        current_uptime = int(response.value)
        #print(f" Current sysUpTime: {current_uptime}")
    except Exception as e:
        #print(f"[ERROR] Failed to fetch sysUpTime: {e}")
        return {
            "uptime": None,
            "reset_detected": False
        }
    reset_detected = False
    if previous_uptime is not None:
        #print(f" Previous sysUpTime: {previous_uptime}")
        if current_uptime < previous_uptime:
            reset_detected = True
            #print(" RESET EVENT DETECTED: Uptime decreased")
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

    try:

        mac_entries = session.walk(ARP_MAC_OID)

        type_entries = session.walk(ARP_TYPE_OID)

    except Exception as e:
        print(f"[ERROR] Failed to walk ARP table: {e}")
        return None

    type_lookup = {}

    for entry in type_entries:

        suffix = ".".join(
            entry.oid.split(".")[-5:]
        )

        type_lookup[suffix] = int(
            entry.value
        )

    arp_table = {}

    for entry in mac_entries:

        suffix_parts = (
            entry.oid.split(".")[-5:]
        )

        if len(suffix_parts) < 5:
            continue

        if_index = int(
            suffix_parts[0]
        )

        ip = ".".join(
            suffix_parts[1:5]
        )

        suffix = ".".join(
            suffix_parts
        )

        entry_type = type_lookup.get(
            suffix
        )

        if entry_type == 2:
            continue

        arp_table[ip] = {
            "ip": ip,
            "mac": normalize_mac(
                entry.value
            ),
            "ifIndex": if_index,
            "type": entry_type
        }

    return arp_table


# Compare old and new ARP snapshots
def compare_snapshots(router_ip, old_snapshot, new_snapshot):

    old_ips = set(old_snapshot.arp_table.keys()) if old_snapshot else set()
    new_ips = set(new_snapshot.arp_table.keys())

    # NEW HOSTS
    for ip in new_ips - old_ips:
        mac = new_snapshot.arp_table[ip]["mac"]

        print(
            f"EVENT|NEW_HOST|{router_ip}|{ip}|{mac}",
            flush=True
        )

    # HOST GONE
    for ip in old_ips - new_ips:
        mac = old_snapshot.arp_table[ip]["mac"]

        print(
            f"EVENT|HOST_GONE|{router_ip}|{ip}|{mac}",
            flush=True
        )

    # MAC CHANGES
    for ip in old_ips & new_ips:

        old_mac = old_snapshot.arp_table[ip]["mac"]
        new_mac = new_snapshot.arp_table[ip]["mac"]

        if old_mac != new_mac:

            print(
                f"EVENT|MAC_CHANGED|"
                f"{router_ip}|"
                f"{ip}|"
                f"{old_mac}|"
                f"{new_mac}",
                flush=True
            )

# Main polling loop
def poll_router(config):

    router_ip = config["ip"]

    state = get_router_state(router_ip)

    try:

        if state.session is None:

            state.session = create_snmp_session(
                config
            )

        session = state.session

        uptime_result = fetch_sysuptime(
            session,
            state.previous_uptime
        )

        #
        # TIMEOUT
        #
        if uptime_result["uptime"] is None:

            print(
                f"EVENT|TIMEOUT|{router_ip}",
                flush=True
            )

            return

        #
        # RESET
        #
        if (
            state.previous_uptime is not None
            and uptime_result["reset_detected"]
        ):

            print(
                f"EVENT|RESET|{router_ip}",
                flush=True
            )

            state.previous_snapshot = None

        #
        # ARP TABLE
        #
        arp_table = fetch_arp_table(session)

        if arp_table is None:

            print(
                f"EVENT|TIMEOUT|{router_ip}",
                flush=True
            )

            return

        #
        # CURRENT SNAPSHOT
        #
        current_snapshot = ARPSnapshot()

        current_snapshot.arp_table = arp_table

        current_snapshot.sysuptime = (
            uptime_result["uptime"]
        )

        #
        # COMPARE AGAINST PREVIOUS
        #
        if state.previous_snapshot is not None:

            compare_snapshots(
                router_ip,
                state.previous_snapshot,
                current_snapshot
            )

        #
        # STORE STATE
        #
        state.update_state(
            current_snapshot,
            uptime_result["uptime"]
        )

    except Exception as e:

        #
        # Force session recreation next poll
        #
        state.session = None

        print(
            f"EVENT|TIMEOUT|{router_ip}",
            flush=True
        )

        print(
            f"[ERROR] {router_ip}: {e}",
            file=sys.stderr
        )

def monitor_router(config):

    interval = config["interval"]

    next_poll = time.time()

    while True:

        poll_router(config)

        next_poll += interval

        sleep_time = (
            next_poll - time.time()
        )

        if sleep_time > 0:

            time.sleep(sleep_time)

        else:

            print(
                f"[WARNING] "
                f"{config['ip']} poll exceeded "
                f"interval",
                file=sys.stderr
            )

            #
            # Re-anchor schedule
            #
            next_poll = time.time()

            
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

    #print(f" Runtime Input: {sys.argv[1:]}")

    try:
        args = [arg for arg in sys.argv if arg != "--test"]
        config = parse_input_arguments(args)
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

            print(
            "\n[MONITOR] Starting monitoring"
            )

        device_configs = []

        for device in config["devices"]:

            device_configs.append(
                {
                    "interval": config["interval"],
                    "ip": device["ip"],
                    "port": device["port"],
                    "community": device["community"]
                }
            )

        threads = []

        for device in device_configs:

            thread = threading.Thread(
                target=monitor_router,
                args=(device,),
            )

            thread.start()

            threads.append(thread)

        try:

            while True:
                time.sleep(1)

        except KeyboardInterrupt:

            print(
                "\nStopping arpwatch..."
            )


    except Exception as e:

        print(
            f"[FATAL] Error: {e}"
        )

        sys.exit(1)