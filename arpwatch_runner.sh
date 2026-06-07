#!/bin/bash
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <interval> <ip:port:community> [ip:port:community ...]"
    exit 1
fi

INTERVAL="$1"
shift

# Track router IP from CLI args initially
CURRENT_IP="${1%%:*}"

PYTHON_SCRIPT="arpwatch.py"

python3 -u "$PYTHON_SCRIPT" "$INTERVAL" "$@" | while IFS= read -r line; do
    
    line="${line%$'\r'}"
    TIMESTAMP=$(date +%s)

    # Update CURRENT_IP when Python announces a new monitor cycle
    if [[ "$line" == *"Starting monitor for"* ]]; then
        CURRENT_IP=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
    fi

    
    IFS='|' read -r PREFIX EVENT ROUTER_IP FIELD1 FIELD2 <<< "$line"

case "$EVENT" in

    TIMEOUT)
        printf "%s | %-15s | TIMEOUT     | - | - |\n" \
            "$TIMESTAMP" \
            "$ROUTER_IP"
        ;;

    RESET)
        printf "%s | %-15s | RESET       | - | - | sysUpTime decreased\n" \
            "$TIMESTAMP" \
            "$ROUTER_IP"
        ;;

    NEW_HOST)
        printf "%s | %-15s | NEW HOST    | %-15s | %s |\n" \
            "$TIMESTAMP" \
            "$ROUTER_IP" \
            "$FIELD1" \
            "$FIELD2"
        ;;

    HOST_GONE)
        printf "%s | %-15s | HOST GONE   | %-15s | %s |\n" \
            "$TIMESTAMP" \
            "$ROUTER_IP" \
            "$FIELD1" \
            "$FIELD2"
        ;;

    MAC_CHANGED)

        OLD_MAC="$FIELD2"

        NEW_MAC=$(echo "$line" | awk -F'|' '{print $6}')

        printf "%s | %-15s | MAC CHANGED | %-15s | %s | was %s\n" \
            "$TIMESTAMP" \
            "$ROUTER_IP" \
            "$FIELD1" \
            "$NEW_MAC" \
            "$OLD_MAC"
        ;;

esac
done