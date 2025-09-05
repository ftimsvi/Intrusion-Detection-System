# Intrusion Detection System

An Intrusion Detection System implemented in P4. It performs **stateless signature matching** on the packet payload to detect threats.

## Getting Started: P4 Environment Setup

To run this project, you need a P4 development environment. The easiest way is to use the pre-configured virtual machine (VM).

### Recommended Method: P4-Learning VM
1.  **Download the VM:** Use the VM provided by the P4-Learning project, which is perfect for this IDPS example.
    *   **Link:** [P4-Learning VM](https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md)
2.  **Import and Launch:** Use VirtualBox/VMware to import the downloaded image. All tools are pre-installed.

### Alternative Method: Native Installation
For advanced users, you can install the tools directly on a Linux system. Follow the official guide:
*   **Link:** [P4.org Installation Guide](https://github.com/p4lang/behavioral-model#dependencies)

**Clone this repository** into your chosen environment to begin.

## How to Run the Project

Open **three terminal windows**.

### Terminal 1: Start the Network
Builds the network topology, compiles the P4 program, and loads initial rules.
```bash
sudo python3 network.py
```
You will enter the Mininet CLI (`mininet>`).

### Terminal 2: Start the IDS Monitor
Listens for malicious packets redirected by the switch and prints alerts.
```bash
python3 controller.py s1-cpu-eth0
```

### Terminal 3 (Optional): Read Statistics
Reads the register counters to see how many packets were dropped per flow.
```bash
python3 ids_stats.py
```

### Generate Test Traffic
From the Mininet CLI in **Terminal 1**, run the traffic generator on host `h1`:
```bash
mininet> h1 python3 send_traffic.py 10.0.2.2
```
