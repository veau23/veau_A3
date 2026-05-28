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

    
    case "$line" in
        *"[TIMEOUT_EVENT]"*)
            printf "%s | %-15s | TIMEOUT     | - | - |\n" "$TIMESTAMP" "$CURRENT_IP"
            ;;
        *"[RESET_EVENT]"*)
            printf "%s | %-15s | RESET       | - | - | sysUpTime decreased\n" "$TIMESTAMP" "$CURRENT_IP"
            ;;
        *"[NEW_HOST]"*)
            HOST_IP=$(echo "$line" | awk '{print $2}')
            HOST_MAC=$(echo "$line" | awk '{print $4}')
            printf "%s | %-15s | NEW HOST    | %-15s | %s |\n" "$TIMESTAMP" "$CURRENT_IP" "$HOST_IP" "$HOST_MAC"
            ;;
        *"[GONE_HOST]"*)
            HOST_IP=$(echo "$line" | awk '{print $2}')
            HOST_MAC=$(echo "$line" | awk '{print $4}')
            printf "%s | %-15s | HOST GONE   | %-15s | %s |\n" "$TIMESTAMP" "$CURRENT_IP" "$HOST_IP" "$HOST_MAC"
            ;;
        *"[MAC_CHANGE]"*)
            HOST_IP=$(echo "$line" | awk '{print $2}')
            OLD_MAC=$(echo "$line" | awk '{print $5}')
            NEW_MAC=$(echo "$line" | awk '{print $7}')
            printf "%s | %-15s | MAC CHANGED | %-15s | %s | was %s\n" "$TIMESTAMP" "$CURRENT_IP" "$HOST_IP" "$NEW_MAC" "$OLD_MAC"
            ;;
    esac
done