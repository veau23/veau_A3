import re
import sys
import time
from datetime import datetime
from easysnmp import Session


SYSUPTIME_OID = "1.3.6.1.2.1.1.3.0"
ARP_MAC_OID = "1.3.6.1.2.1.4.22.1.2"
ARP_TYPE_OID = "1.3.6.1.2.1.4.22.1.4"


class ARPSnapshot:
    def __init__(self):
        self.timestamp = datetime.now()
        self.arp_table = {}
        self.sysuptime = None
        self.reset_detected = False


def parse_input_arguments(argument_string):
    print("[DEBUG] Parsing input arguments")
    
    argument_string = argument_string.strip()
    parts = argument_string.split(maxsplit=1)
    
    interval_part, connection_part = parts
    
    interval = float(interval_part)
    
    connection_parts = connection_part.split(":")
    
    ip, port_str, community = connection_parts
    
    ipv4_pattern = (
        r'^('
        r'(25[0-5]|2[0-4][0-9]|'
        r'[01]?[0-9][0-9]?)\.'
        r'){3}'
        r'(25[0-5]|2[0-4][0-9]|'
        r'[01]?[0-9][0-9]?)$'
    )
    
    if not re.match(ipv4_pattern, ip):
        raise ValueError(f"Invalid IP address: {ip}")
    
    port = int(port_str)
    community = community.strip()
    
    print(f"[DEBUG] Interval={interval}")
    print(f"[DEBUG] IP={ip}")
    print(f"[DEBUG] Port={port}")
    print(f"[DEBUG] Community={community}")
    
    return {
        "interval": interval,
        "ip": ip,
        "port": port,
        "community": community
    }


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


def fetch_sysuptime(session, previous_uptime=None):
    print("[DEBUG] Fetching sysUpTime")
    
    try:
        response = session.get(SYSUPTIME_OID)
        current_uptime = int(response.value)
    except Exception as e:
        print(f"[ERROR] Failed to fetch sysUpTime: {e}")
        return {
            "uptime": previous_uptime,
            "reset_detected": False,
            "error": str(e)
        }
    
    print(f"[DEBUG] Current sysUpTime: {current_uptime}")
    
    reset_detected = False
    
    if previous_uptime is not None:
        print(f"[DEBUG] Previous sysUpTime: {previous_uptime}")
        
        if current_uptime < previous_uptime:
            reset_detected = True
            print("[DEBUG] RESET EVENT DETECTED")
    
    return {
        "uptime": current_uptime,
        "reset_detected": reset_detected
    }


def normalize_mac(mac_raw):
    mac_raw = str(mac_raw)
    
    #print(f"[DEBUG] RAW MAC VALUE: {repr(mac_raw)}")
    
    if mac_raw.startswith("0x"):
        # Handle hex string format
        hex_string = mac_raw.replace("0x", "")
        
        if len(hex_string) % 2 != 0:
            hex_string = "0" + hex_string
        
        mac = ":".join(
            hex_string[i:i + 2]
            for i in range(0, len(hex_string), 2)
        )
        
        return mac.lower()
    
    # Handle octet string format (binary bytes)
    mac = ":".join(
        f"{ord(x):02x}"
        for x in mac_raw
    )
    
    return mac.lower()


def fetch_arp_table(session):
    print("[DEBUG] Fetching ARP table")
    
    try:
        mac_entries = session.walk(ARP_MAC_OID)
        type_entries = session.walk(ARP_TYPE_OID)
    except Exception as e:
        print(f"[ERROR] Failed to walk ARP table: {e}")
        return []
    
    print(f"[DEBUG] Retrieved {len(mac_entries)} MAC entries")
    print(f"[DEBUG] Retrieved {len(type_entries)} TYPE entries")
    
    print("\n[DEBUG] NORMALIZED MAC ENTRIES")
    for entry in mac_entries:
        print(f"OID={entry.oid}, INDEX={entry.oid_index}, VALUE={normalize_mac(entry.value)}")
    
    print("\n[DEBUG] RAW TYPE ENTRIES")
    for entry in type_entries:
        print(f"OID={entry.oid}, INDEX={entry.oid_index}, VALUE={entry.value}")
    
    type_lookup = {}
    for entry in type_entries:
        type_lookup[entry.oid_index] = int(entry.value)
    
    arp_table = {}
    
    for entry in mac_entries:
        suffix = entry.oid_index
        suffix_parts = suffix.split(".")
        
        if len(suffix_parts) < 5:
            continue
        
        if_index = int(suffix_parts[0])
        ip = ".".join(suffix_parts[1:5])
        entry_type = type_lookup.get(suffix)
        
        print(f"[DEBUG] ENTRY TYPE FOR {ip}: {entry_type}")
        
        # Skip invalid ARP entries
        if entry_type == 2:
            print(f"[DEBUG] Skipping invalid ARP entry for {ip}")
            continue
        
        mac = normalize_mac(entry.value)
        
        parsed_entry = {
            "ip": ip,
            "mac": mac,
            "ifIndex": if_index,
            "type": entry_type
        }
        
        print(f"[DEBUG] Parsed Entry: {parsed_entry}")
        
        arp_table[ip] = parsed_entry
    
    print(f"\n[DEBUG] Final ARP table size: {len(arp_table)}")
    
    return arp_table


def compare_snapshots(old_snapshot, new_snapshot):
    """
    Compare two ARP snapshots and detect changes.
    Returns a dictionary of detected events.
    """
    events = {
        "new_hosts": [],
        "gone_hosts": [],
        "mac_changes": [],
        "status": "unchanged"
    }
    
    old_ips = set(old_snapshot.arp_table.keys()) if old_snapshot else set()
    new_ips = set(new_snapshot.arp_table.keys())
    
    # New hosts appeared
    new_hosts = new_ips - old_ips
    for ip in new_hosts:
        events["new_hosts"].append({
            "ip": ip,
            "mac": new_snapshot.arp_table[ip]["mac"],
            "timestamp": new_snapshot.timestamp
        })
    
    # Hosts disappeared
    gone_hosts = old_ips - new_ips
    for ip in gone_hosts:
        events["gone_hosts"].append({
            "ip": ip,
            "mac": old_snapshot.arp_table[ip]["mac"],
            "timestamp": new_snapshot.timestamp
        })
    
    # MAC changes for same IP
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
    
    # Determine overall status
    if events["new_hosts"] or events["gone_hosts"] or events["mac_changes"]:
        events["status"] = "changed"
    
    return events


def print_events(events):
    """Print detected events in a structured format."""
    if events["status"] == "unchanged":
        print("[INFO] No changes detected in ARP table")
        return
    
    print(f"\n[EVENTS] {events['status'].upper()} - {datetime.now()}")
    
    for new_host in events["new_hosts"]:
        print(f"  [NEW_HOST] {new_host['ip']} -> {new_host['mac']}")
    
    for gone_host in events["gone_hosts"]:
        print(f"  [GONE_HOST] {gone_host['ip']} -> {gone_host['mac']}")
    
    for mac_change in events["mac_changes"]:
        print(f"  [MAC_CHANGE] {mac_change['ip']} changed from {mac_change['old_mac']} to {mac_change['new_mac']}")


def main_loop(config):
    """Main monitoring loop."""
    session = create_snmp_session(config)
    
    previous_snapshot = None
    iteration = 0
    
    print(f"\n[MONITOR] Starting ARP monitoring on {config['ip']}")
    print(f"[MONITOR] Polling every {config['interval']} seconds")
    print(f"[MONITOR] Press Ctrl+C to stop\n")
    
    while True:
        try:
            iteration += 1
            print(f"\n[ITERATION] #{iteration} - {datetime.now()}")
            
            # Fetch sysUpTime
            uptime_result = fetch_sysuptime(session, 
                                          previous_snapshot.sysuptime if previous_snapshot else None)
            
            # Check for reset event
            if uptime_result.get("reset_detected"):
                print(f"[RESET_EVENT] Device reset detected at {datetime.now()}")
            
            # Fetch ARP table
            current_arp_table = fetch_arp_table(session)
            
            # Create current snapshot
            current_snapshot = ARPSnapshot()
            current_snapshot.arp_table = current_arp_table
            current_snapshot.sysuptime = uptime_result.get("uptime")
            current_snapshot.reset_detected = uptime_result.get("reset_detected")
            
            # Compare with previous snapshot if available
            if previous_snapshot:
                events = compare_snapshots(previous_snapshot, current_snapshot)
                print_events(events)
                
                # Print summary
                total_changes = (len(events["new_hosts"]) + 
                               len(events["gone_hosts"]) + 
                               len(events["mac_changes"]))
                if total_changes > 0:
                    print(f"[SUMMARY] Total changes: {total_changes}")
            
            # Update previous snapshot
            previous_snapshot = current_snapshot
            
            # Wait for next poll
            time.sleep(config["interval"])
            
        except KeyboardInterrupt:
            print(f"\n[STOP] Stopping ARP monitor after {iteration} iterations")
            break
        except Exception as e:
            print(f"[ERROR] Iteration failed: {e}")
            time.sleep(config["interval"])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python arpwatch.py \"interval_seconds ip:port:community\"")
        print("Example: python arpwatch.py \"5.0 192.168.1.1:161:public\"")
        sys.exit(1)
    
    raw_input_args = " ".join(sys.argv[1:])
    
    print(f"[DEBUG] Runtime Input: {raw_input_args}")
    
    try:
        config = parse_input_arguments(raw_input_args)
        
        # For testing mode, run single shot
        if "--test" in sys.argv:
            session = create_snmp_session(config)
            uptime_result = fetch_sysuptime(session)
            print("\n[INFO] sysUpTime Result")
            print(uptime_result)
            
            arp_entries = fetch_arp_table(session)
            print("\n[INFO] FINAL ARP TABLE")
            for ip, entry in arp_entries.items():
                print(f"IP: {entry['ip']}, MAC: {entry['mac']}, Interface: {entry['ifIndex']}, Type: {entry['type']}")
        else:
            main_loop(config)
            
    except Exception as e:
        print(f"[FATAL] Error: {e}")
        sys.exit(1)