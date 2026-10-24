#!/usr/bin/env python3

import json
import ipaddress
import argparse
import subprocess
import time
from pathlib import Path

ALERT_FILE = Path("/var/log/suricata/eve.json")
TARGET_SIGNATURE = 1000101

PROTECTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.230.167.0/24"),
    ipaddress.ip_network("192.168.122.0/24"),
    ipaddress.ip_network("10.0.0.42/32"),
]

# Only this reserved test IP may be blocked during initial testing.
TEST_ATTACKER_IP = "10.250.250.2"


def is_protected(ip):
    address = ipaddress.ip_address(ip)

    return (
        not address.is_global
        or any(address in network for network in PROTECTED_NETWORKS)
    )


def block_ip(ip):
    command = [
        "/usr/sbin/nft",
        "add", "element",
        "inet", "project2_soar", "blocked_ipv4",
        "{", ip, "timeout", "5m", "}"
    ]

    try:
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True
        )
        print(f"[BLOCKED] {ip} - Added to nftables for 5 minutes", flush=True)

    except subprocess.CalledProcessError as error:
        print(f"[ERROR] Firewall update failed: {error.stderr}", flush=True)


def process_alert(event, enforce=False):
    if event.get("event_type") != "alert":
        return

    alert = event.get("alert", {})

    if alert.get("signature_id") != TARGET_SIGNATURE:
        return

    source_ip = event.get("src_ip")

    if not source_ip:
        return

    try:
        address = ipaddress.ip_address(source_ip)

        if address.version != 4:
            print(f"[SKIPPED] {source_ip} - IPv6 not supported")
            return

        if source_ip != TEST_ATTACKER_IP and is_protected(source_ip):
            print(f"[PROTECTED] {source_ip} - Blocking skipped", flush=True)
            return

    except ValueError:
        print(f"[INVALID IP] {source_ip}")
        return

    if source_ip != TEST_ATTACKER_IP:
        print(f"[NOT APPROVED] {source_ip} - Blocking skipped", flush=True)
        return

    if enforce:
        block_ip(source_ip)
    else:
        print(f"[DRY RUN] Would block {source_ip}", flush=True)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--file", default=str(ALERT_FILE))
    parser.add_argument("--follow", action="store_true")
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Enable nftables blocking for approved test IP"
    )

    args = parser.parse_args()

    mode = "ENFORCEMENT" if args.enforce else "DRY RUN"
    print(f"========== PROJECT2 SOAR {mode} ==========", flush=True)

    with open(args.file, "r") as logfile:
        if args.follow:
            logfile.seek(0, 2)
            print("[MONITORING] Waiting for new Suricata alerts...", flush=True)

        while True:
            line = logfile.readline()

            if not line:
                if args.follow:
                    time.sleep(0.5)
                    continue
                break

            try:
                process_alert(json.loads(line), args.enforce)
            except json.JSONDecodeError:
                continue


if __name__ == "__main__":
    main()
