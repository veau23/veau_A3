#!/bin/bash

if [ "$#" -lt 2 ]; then
    echo "Usage:"
    echo "  $0 <interval> <ip:port:community:version> [more devices]"
    exit 1
fi

INTERVAL="$1"
shift

PYTHON_SCRIPT="arpwatch1.py"

python3 -u "$PYTHON_SCRIPT" "$INTERVAL" "$@" 2>&1 |
while IFS= read -r line
do
    line="${line%$'\r'}"

    TIMESTAMP=$(date +%s)

    #
    # Only parse structured event lines.
    #
    if [[ "$line" != EVENT\|* ]]; then
        echo "$line"
        continue
    fi

    IFS='|' read -r PREFIX EVENT ROUTER_IP FIELD1 FIELD2 FIELD3 <<< "$line"

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
            NEW_MAC="$FIELD3"

            printf "%s | %-15s | MAC CHANGED | %-15s | %s | was %s\n" \
                "$TIMESTAMP" \
                "$ROUTER_IP" \
                "$FIELD1" \
                "$NEW_MAC" \
                "$OLD_MAC"
            ;;

        *)

            echo "$line"
            ;;

    esac

done