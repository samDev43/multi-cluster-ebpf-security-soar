
#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

TARGET_NAMESPACE = "default"
TARGET_POD = "web-test"

EVIDENCE_DIR = Path.home() / "project2" / "evidence"
QUARANTINE_POLICY = (
    Path.home() / "project2" / "policies" / "pod-quarantine.yaml"
)

K3S_KUBECTL = "/usr/local/bin/k3s"

# Prevent repeated quarantine actions during this SOAR session.
QUARANTINE_ACTIVE = False

MONITORED_POLICIES = {
    "shell-execution-monitor": "MEDIUM",
    "sensitive-file-monitor": "HIGH",
    "capability-monitor": "MEDIUM",
}


def save_evidence(evidence):
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    filename = f"{evidence['incident_id']}.json"
    evidence_path = EVIDENCE_DIR / filename

    with evidence_path.open("w", encoding="utf-8") as file:
        json.dump(evidence, file, indent=4)

    return evidence_path


def quarantine_pod():
    """Apply and verify the Cilium quarantine policy."""

    if not QUARANTINE_POLICY.is_file():
        return False, "Quarantine policy file not found"

    try:
        apply_result = subprocess.run(
            [
                K3S_KUBECTL,
                "kubectl",
                "apply",
                "-f",
                str(QUARANTINE_POLICY),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if apply_result.returncode != 0:
            return False, apply_result.stderr.strip()

        verify_result = subprocess.run(
            [
                K3S_KUBECTL,
                "kubectl",
                "get",
                "ciliumnetworkpolicy",
                "pod-quarantine",
                "-n",
                TARGET_NAMESPACE,
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if verify_result.returncode != 0:
            return False, verify_result.stderr.strip()

        policy_data = json.loads(verify_result.stdout)
        conditions = policy_data.get("status", {}).get("conditions", [])

        valid = any(
            condition.get("type") == "Valid"
            and condition.get("status") == "True"
            for condition in conditions
        )

        if not valid:
            return False, "Policy applied but validity was not confirmed"

        return True, "Cilium quarantine policy is valid"

    except subprocess.TimeoutExpired:
        return False, "Kubernetes command timed out"

    except (OSError, json.JSONDecodeError) as error:
        return False, str(error)


def process_event(event):
    """Inspect, record and respond to Tetragon events."""

    global QUARANTINE_ACTIVE

    probe = event.get("process_kprobe")

    if not isinstance(probe, dict):
        return

    policy = probe.get("policy_name")

    if policy not in MONITORED_POLICIES:
        return

    process = probe.get("process") or {}
    pod = process.get("pod") or {}

    namespace = pod.get("namespace")
    pod_name = pod.get("name")

    if namespace != TARGET_NAMESPACE or pod_name != TARGET_POD:
        return

    alert_level = MONITORED_POLICIES[policy]
    binary = process.get("binary", "Unknown")
    pid = process.get("pid", "Unknown")
    function = probe.get("function_name", "Unknown")

    captured_arguments = []

    for argument in probe.get("args", []):
        file_info = argument.get("file_arg") or {}
        label = argument.get("label")

        if not label and file_info:
            label = "file"

        if not label:
            continue

        value = argument.get("int_arg")

        if value is None:
            value = file_info.get("path", "Unknown")

        captured_arguments.append({
            "label": label,
            "value": value,
        })

    evidence = {
        "incident_id": str(uuid.uuid4()),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "event_time": event.get("time", "Unknown"),
        "alert_level": alert_level,
        "policy": policy,
        "namespace": namespace,
        "pod": pod_name,
        "process": binary,
        "pid": pid,
        "kernel_function": function,
        "captured_arguments": captured_arguments,
        "response_mode": "PENDING",
    }

    evidence_path = save_evidence(evidence)

    print("\n========== TETRAGON SECURITY EVENT ==========")
    print(f"Time:       {evidence['event_time']}")
    print(f"Alert:      {alert_level}")
    print(f"Policy:     {policy}")
    print(f"Namespace:  {namespace}")
    print(f"Pod:        {pod_name}")
    print(f"Process:    {binary}")
    print(f"PID:        {pid}")
    print(f"Function:   {function}")
    print(f"Evidence:   {evidence_path}")

    if alert_level == "HIGH":

        if QUARANTINE_ACTIVE:
            evidence["response_mode"] = "ALREADY QUARANTINED"
            print("[SOAR] Pod is already quarantined.")
            print("[SOAR] Duplicate quarantine action skipped.")

        else:
            print("[SOAR] HIGH alert detected. Starting quarantine...")

            success, message = quarantine_pod()

            if success:
                QUARANTINE_ACTIVE = True
                evidence["response_mode"] = "AUTOMATED QUARANTINE"
                print("[SOAR] QUARANTINE SUCCESSFUL")
            else:
                evidence["response_mode"] = "QUARANTINE FAILED"
                print(f"[SOAR] QUARANTINE FAILED: {message}")

            print(f"[SOAR] {message}")

    else:
        evidence["response_mode"] = "LOG ONLY"
        print("[SOAR] MEDIUM alert recorded. No quarantine triggered.")

    save_evidence(evidence)

    print(f"Response:   {evidence['response_mode']}")
    print("============================================")


def main():
    parser = argparse.ArgumentParser(
        description="Tetragon runtime security and SOAR processor"
    )

    parser.add_argument(
        "--file",
        help="Read Tetragon JSON events from a file",
    )

    args = parser.parse_args()

    print("========== TETRAGON SOAR ==========")
    print("Mode: AUTOMATED RESPONSE ENABLED")
    print(f"Target: {TARGET_NAMESPACE}/{TARGET_POD}")
    print(f"Evidence directory: {EVIDENCE_DIR}")
    print("HIGH alerts: Automatic quarantine")
    print("MEDIUM alerts: Evidence collection only")
    print("Duplicate quarantine: Prevented during this session")
    print("Waiting to process Tetragon events...")
    print("==================================")

    if args.file:
        source = open(args.file, "r", encoding="utf-8")
    else:
        source = sys.stdin

    try:
        for line in source:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
                process_event(event)

            except json.JSONDecodeError:
                print("[SKIPPED] Invalid JSON event", file=sys.stderr)

    finally:
        if args.file:
            source.close()


if __name__ == "__main__":
    main()
