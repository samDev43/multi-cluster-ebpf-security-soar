# Multi-Cluster eBPF Security and Live SOAR Automation

## Project Overview

This project demonstrates a multi-cluster Kubernetes security
environment using Cilium, eBPF, WireGuard, Hubble, Suricata,
and automated security response.

The objective is to secure communication between Kubernetes
clusters, enforce network security policies, detect suspicious
network traffic, and automatically block approved simulated
attackers.

## Technologies Used

- Kali Linux
- Kubernetes (K3s)
- Cilium and eBPF
- Cilium ClusterMesh
- WireGuard Encryption
- Hubble Network Observability
- Cilium L3/L4 and L7 Network Policies
- Suricata IDS
- Python SOAR Automation
- nftables Firewall

## Implementation

### 1. Multi-Cluster Kubernetes

Configured two Kubernetes clusters named East and West
and connected them using Cilium ClusterMesh.

### 2. WireGuard Encryption

Enabled transparent WireGuard encryption for communication
between the Kubernetes clusters.

### 3. Network Microsegmentation

Implemented Cilium network policies to control communication
between workloads.

### 4. L7 API Protection

Tested HTTP-based security policies that permit authorized
requests and deny restricted API operations.

### 5. Network Observability

Used Hubble to observe network communication and security
events across the Kubernetes environment.

### 6. Suricata Intrusion Detection

Configured a custom Suricata detection rule and verified
that it detected real HTTP traffic from an isolated
simulated attacker.

### 7. Live SOAR Automation

Developed a Python SOAR script that reads Suricata alerts
and automatically updates an nftables firewall set.

The automation includes protections to prevent unintended
blocking of production or cluster network addresses.

## Verified Results

- Kubernetes clusters operational
- ClusterMesh connectivity established
- WireGuard encryption enabled
- Cross-cluster HTTP communication successful
- L3/L4 microsegmentation verified
- L7 API access restrictions verified
- Hubble network visibility confirmed
- Suricata HTTP detection successful
- SOAR automatically blocked the simulated attacker
- Firewall verification showed 100% packet loss

## Repository Structure

- docs/ - Project documentation
- policies/ - Cilium network security policies
- soar/ - Python security automation
- suricata/rules/ - Suricata detection rules

## Security Notice

This project was implemented in an isolated cybersecurity
lab environment for educational and defensive security
testing purposes.

Private credentials, internal infrastructure evidence,
and generated security logs are excluded from this repository.

## Author

GitHub: samDev43
