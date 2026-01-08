# EX4 — Network Layer Lab (C)

This project implements a suite of network tools in **C** using **Raw Sockets** to explore the fundamentals of the Network Layer, ICMP protocols, IP header manipulation, and network scanning techniques.

## Components

- **ping.c**: A connectivity tool that sends `ICMP ECHO REQUEST` packets.
    - Supports `-c <count>` for specific packet amounts.
    - Supports `-f` (Flood mode) for rapid transmission.
    - Calculates RTT statistics (min/avg/max/mdev) and packet loss.
    - Implements a 10-second timeout mechanism for unresponsive hosts.
- **traceroute.c**: Traces the path to a remote host.
    - Manually manipulates the TTL (Time To Live) field in the IP header to identify intermediate hops.
    - Sends 3 probes per hop and displays timing and IP for each router.
- **port_scanning.c**: A multi-threaded scanner for identifying open services.
    - **TCP SYN Scan**: Performs a "half-open" scan to detect TCP ports without completing a full handshake.
    - **UDP Scan**: Identifies open UDP ports by analyzing ICMP unreachable responses.
- **discovery.c**: A tool to map active hosts within a subnet.
    - Calculates IP ranges based on CIDR notation.
    - Pings every address in the subnet to find live hosts.
- **tunnel.c**: A demonstration of data exfiltration (ICMP Tunneling).
    - Reads data from `secret.txt` and encapsulates it within the payload of standard ICMP Echo packets.
- **makefile**: Standard build script to compile all utilities using `gcc`.

## Quick Start

### Compilation
To compile all tools at once, run:
```bash
make all
```

### Running the Tools

> **Note:** Since these tools use Raw Sockets, they must be run with `sudo` privileges.

**1. Ping a host:**

```bash
sudo ./ping -a 8.8.8.8 -c 4
```

**2. Trace a route:**

```bash
sudo ./traceroute -a 8.8.8.8
```

**3. Scan ports (TCP or UDP):**

```bash
sudo ./port_scanning -a 127.0.0.1 -t TCP
```

**4. Discover hosts in a subnet:**

```bash
sudo ./discovery -a 192.168.1.0 -c 24
```

**5. Run the ICMP Tunnel:**
*(Ensure `secret.txt` exists in the directory)*

```bash
sudo ./tunnel
```

## Implementation Details

* **Raw Sockets**: All tools bypass the standard transport layer and construct headers manually (IP/ICMP/TCP/UDP).
* **Checksum Calculation**: Implements the Internet Checksum algorithm (RFC 1071) to ensure packet integrity.
* **Multithreading**: The `port_scanning` utility utilizes `pthread` to separate sender and receiver logic, ensuring high-speed scanning without missing responses.

---

*Developed as part of the Communication Networks Course.*
