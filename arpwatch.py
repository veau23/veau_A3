import re
import sys
import time
from datetime import datetime
from easysnmp import Session

DEBUG = False

def debug_print(message):
    if DEBUG:
        print(message, flush=True)

# SNMP OIDs for polling router information
SYSUPTIME_OID = "1.3.6.1.2.1.1.3.0"
ARP_MAC_OID = "1.3.6.1.2.1.4.22.1.2"
ARP_TYPE_OID = "1.3.6.1.2.1.4.22.1.4"
# VLAN-aware forwarding database
VLAN_FDB_PORT_OID = "1.3.6.1.2.1.17.7.1.2.2.1.2"

# Stores ARP polling result
class ARPSnapshot:
    def __init__(self):
        self.timestamp = datetime.now()
        self.arp_table = {}
        self.vlan_mac_table = {}
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
        
        self.snmp_version = None

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

def print_event(
    router_ip,
    event_type,
    ip_address="—",
    mac_address="—",
    note=""
):
    timestamp = int(time.time())

    print(
        f"{timestamp} | "
        f"{router_ip} | "
        f"{event_type:<11} | "
        f"{ip_address:<11} | "
        f"{mac_address:<17} | "
        f"{note}",
        flush=True
    )    

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

        connection_parts = device_string.split(":", 2)

        if len(connection_parts) != 3:
            raise ValueError(
                f"Invalid device format: {device_string}"
            )

        ip = connection_parts[0].strip()
        port_str = connection_parts[1].strip()
        community = connection_parts[2].strip()

        if not re.match(
            ipv4_pattern,
                                ip
            ):
            raise ValueError(
                f"Invalid IP address: {ip}"
            )

        if not port_str.isdigit():
            raise ValueError(
                f"Invalid SNMP port: {port_str}"
            )

        port = int(port_str)

        if not 1 <= port <= 65535:
            raise ValueError(
                f"Invalid SNMP port: {port}"
            )

        if not community:
            raise ValueError(
                "SNMP community cannot be empty"
            )

        devices.append(
            {
                "ip": ip,
                "port": port,
                "community": community
            }
        )

    return {
        "interval": interval,
        "devices": devices
    }
# Create EasySNMP session with router

def create_snmp_session(config, version):

    return Session(
        hostname=config["ip"],
        community=config["community"],
        version=version,
        remote_port=config["port"],
        timeout=2,
        retries=1
    )
def detect_snmp_version(config, state):

    #
    # Already detected
    #
    if state.snmp_version is not None:

        return create_snmp_session(
            config,
            state.snmp_version
        )

    #
    # Prefer v2c because the original
    # implementation always used v2c.
    #
    for version in (2, 1):

        try:

            session = create_snmp_session(
                config,
                version
            )

            session.get(
                SYSUPTIME_OID
            )

            state.snmp_version = version

            print(
                f"[INFO] {config['ip']} "
                f"detected SNMPv{version}",
                flush=True
            )

            return session

        except Exception as e:

            debug_print(
                f"[DEBUG] {config['ip']} "
                f"SNMPv{version} failed: {e}"
            )

    raise RuntimeError(
        f"No SNMP version works "
        f"for {config['ip']}"
    )
# Poll router uptime and detect reboot
def fetch_sysuptime(session, previous_uptime=None):

    try:
        response = session.get(SYSUPTIME_OID)
        current_uptime = int(response.value)

    except Exception as e:

        print(
            f"SYSUPTIME ERROR: {e}",
            file=sys.stderr
        )

        return {
            "uptime": None,
            "reset_detected": False
        }

    reset_detected = False

    if previous_uptime is not None:

        if current_uptime < previous_uptime:
            reset_detected = True

    return {
        "uptime": current_uptime,
        "reset_detected": reset_detected
    }
# Convert MAC addresses into readable format
def normalize_mac(mac_raw):

    if isinstance(mac_raw, bytes):

        if len(mac_raw) != 6:
            raise ValueError(
                f"Unexpected MAC byte length: {len(mac_raw)}"
            )

        return ":".join(
            f"{byte:02x}"
            for byte in mac_raw
        )

    mac_raw = str(mac_raw).strip()

    if mac_raw.startswith("0x"):

        hex_string = mac_raw[2:]

        if len(hex_string) != 12:
            raise ValueError(
                f"Unexpected hexadecimal MAC format: {mac_raw!r}"
            )

        if not re.fullmatch(
            r"[0-9a-fA-F]{12}",
            hex_string
        ):
            raise ValueError(
                f"Invalid hexadecimal MAC format: {mac_raw!r}"
            )

        return ":".join(
            hex_string[i:i + 2].lower()
            for i in range(0, 12, 2)
        )

    if re.fullmatch(
        r"[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}",
        mac_raw
    ):

        parts = re.split(
            r"[:-]",
            mac_raw
        )

        return ":".join(
            part.lower()
            for part in parts
        )

    if re.fullmatch(
        r"[0-9a-fA-F]{12}",
        mac_raw
    ):

        return ":".join(
            mac_raw[i:i + 2].lower()
            for i in range(0, 12, 2)
        )

    if len(mac_raw) == 6:

        return ":".join(
            f"{ord(byte):02x}"
            for byte in mac_raw
        )

    raise ValueError(
        f"Unexpected MAC address format: {mac_raw!r}"
    )
# Retrieve and parse ARP table entries

def fetch_arp_table(session):

    try:

        mac_entries = session.walk(
            ARP_MAC_OID
        )

        type_entries = session.walk(
            ARP_TYPE_OID
        )

    except Exception as e:

        print(
            f"ARP WALK ERROR: {e}",
            file=sys.stderr
        )

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

        suffix_parts = entry.oid.split(".")[-5:]

        if len(suffix_parts) != 5:
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

        # Ignore invalid ARP entries
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

# Retrieve MAC addresses learned on each VLAN
def fetch_vlan_mac_table(session):

    try:

        fdb_entries = session.walk(
            VLAN_FDB_PORT_OID
        )

        print(
            f"[INFO] VLAN/FDB entries retrieved: "
            f"{len(fdb_entries)}",
            flush=True
        )

    except Exception as e:

        print(
            f"[INFO] VLAN/FDB table unavailable: {e}",
            flush=True
        )

        return None

    vlan_mac_table = {}

    for entry in fdb_entries:

        debug_print(
            f"[DEBUG] FDB OID: {entry.oid} | VALUE: {entry.value}"
        )

        oid_parts = entry.oid.split(".")

        if len(oid_parts) < 7:
            continue

        suffix_parts = oid_parts[-7:]

        if not all(
            part.isdigit()
            for part in suffix_parts
        ):
            debug_print(
                f"[DEBUG] Unexpected FDB OID format: {entry.oid}"
            )
            continue

        vlan_id = int(suffix_parts[0])

        if not 1 <= vlan_id <= 4094:
            debug_print(
                f"[DEBUG] Invalid VLAN ID: {vlan_id}"
            )
            continue

        mac_parts = suffix_parts[1:7]

        if len(mac_parts) != 6:
            debug_print(
                f"[DEBUG] Invalid FDB MAC index: {entry.oid}"
            )
            continue

        if not all(
            0 <= int(part) <= 255
            for part in mac_parts
        ):
            debug_print(
                f"[DEBUG] Invalid MAC bytes in OID: {entry.oid}"
            )
            continue

        mac = ":".join(
            f"{int(part):02x}"
            for part in mac_parts
        )

        try:
            bridge_port = int(entry.value)
        except (TypeError, ValueError):
            debug_print(
                f"[DEBUG] Unexpected bridge-port value: {entry.value!r}"
            )
            continue

        if vlan_id not in vlan_mac_table:
            vlan_mac_table[vlan_id] = []

        vlan_mac_table[vlan_id].append(
            {
                "vlan": vlan_id,
                "mac": mac,
                "bridge_port": bridge_port
            }
        )

    return vlan_mac_table

# Compare old and new ARP snapshots
def compare_snapshots(router_ip, old_snapshot, new_snapshot):

    old_ips = (
        set(old_snapshot.arp_table.keys())
        if old_snapshot
        else set()
    )

    new_ips = set(
        new_snapshot.arp_table.keys()
    )

    # NEW HOSTS
    for ip in new_ips - old_ips:

        mac = new_snapshot.arp_table[ip]["mac"]

        print_event(
            router_ip,
            "NEW HOST",
            ip,
            mac
        )

    # HOST GONE
    for ip in old_ips - new_ips:

        mac = old_snapshot.arp_table[ip]["mac"]

        print_event(
            router_ip,
            "HOST GONE",
            ip,
            mac
        )

    # MAC CHANGES
    for ip in old_ips & new_ips:

        old_mac = old_snapshot.arp_table[ip]["mac"]
        new_mac = new_snapshot.arp_table[ip]["mac"]

        if old_mac != new_mac:

            print_event(
                router_ip,
                "MAC CHANGED",
                ip,
                new_mac,
                f"was {old_mac}"
            )

def poll_router(config):

    router_ip = config["ip"]

    state = get_router_state(
        router_ip
    )

    try:

        #
        # Create or recreate session
        #
        if state.session is None:

            state.session = detect_snmp_version(
                config,
                state
            )

        session = state.session

        uptime_result = fetch_sysuptime(
            session,
            state.previous_uptime
        )

        if uptime_result["uptime"] is None:

            state.session = None

            print_event(
                router_ip,
                "TIMEOUT"
            )

            return

        if (
            state.previous_uptime is not None
            and
            uptime_result["reset_detected"]
        ):

            print_event(
                router_ip,
                "RESET"
            )

            state.previous_snapshot = None

        #
        # Fetch ARP table
        #
        arp_table = fetch_arp_table(
            session
        )

        if arp_table is None:

            state.session = None

            print_event(
                router_ip,
                "TIMEOUT"
            )

            return

        #
        # Fetch VLAN/MAC forwarding table
        #
        vlan_mac_table = fetch_vlan_mac_table(
            session
        )

        if vlan_mac_table is None:

            print(
                f"[INFO] {router_ip} VLAN/FDB table unavailable",
                flush=True
            )

        else:

            print(
                f"[INFO] {router_ip} VLAN/FDB table retrieved",
                flush=True
            )

            for vlan_id, entries in vlan_mac_table.items():

                for entry in entries:

                    print_event(
                        router_ip,
                        "VLAN MAC",
                        "-",
                        entry["mac"],
                        f"VLAN {vlan_id}, bridge port {entry['bridge_port']}"
                    )

        #
        # Create current snapshot
        #
        current_snapshot = ARPSnapshot()

        current_snapshot.arp_table = arp_table

        current_snapshot.vlan_mac_table = vlan_mac_table

        current_snapshot.sysuptime = (
            uptime_result["uptime"]
        )

        #
        # Compare with previous snapshot
        #
        if state.previous_snapshot is None:

            #
            # First poll:
            # treat every discovered host as NEW_HOST.
            #
            for ip, entry in current_snapshot.arp_table.items():

                print_event(
                    router_ip,
                    "NEW HOST",
                    ip,
                    entry["mac"]
                )

        else:

            compare_snapshots(
                router_ip,
                state.previous_snapshot,
                current_snapshot
            )

        #
        # Store current state
        #
        state.update_state(
            current_snapshot,
            uptime_result["uptime"]
        )

    except Exception as e:

        state.session = None

        print(
            f"[ERROR] {router_ip}: {type(e).__name__}: {e}",
            flush=True
        )

        print_event(
            router_ip,
            "TIMEOUT"
        )
            
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
        

        DEBUG = "-d" in sys.argv or "--debug" in sys.argv

        args = [
            arg for arg in sys.argv
            if arg not in ("--test", "-d", "--debug")
        ]

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

                test_state = RouterState(
                    device["ip"]
                )

                session = detect_snmp_version(
                    device_config,
                    test_state
                )

                print(
                    f"[INFO] Using SNMPv{test_state.snmp_version}"
                )

                arp_entries = fetch_arp_table(
                    session
                )

                print(
                    f"[INFO] Retrieved "
                    f"{len(arp_entries) if arp_entries else 0} "
                    f"ARP entries"
                )

                uptime_result = fetch_sysuptime(
                    session
                )
                

                print("\n[INFO] FINAL ARP TABLE")

                for ip, entry in arp_entries.items():

                    print_event(
                        device["ip"],
                        "NEW HOST",
                        entry["ip"],
                        entry["mac"]
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

        while True:

            cycle_start = time.time()

            for device in device_configs:

                poll_router(device)

            elapsed = time.time() - cycle_start

            sleep_time = config["interval"] - elapsed

            if sleep_time > 0:
                time.sleep(sleep_time)

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
