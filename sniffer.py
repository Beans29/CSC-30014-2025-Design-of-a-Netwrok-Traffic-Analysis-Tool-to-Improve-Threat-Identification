import time                                                     # Native time manipulation for sliding-window DoS detection
import os                                                       # OS interactions for database and file pathing
import sqlite3                                                  # Lightweight, serverless local database (Ensures Data Sovereignty)
import logging                                                  # Standardised event logging for system health
import platform                                                 # OS detection for adaptive interface configuration
import threading                                                # Multithreading to prevent packet loss during DB writes
import queue                                                    # Thread-safe memory buffer for asynchronous DB queues
from collections import defaultdict, deque                      # Highly efficient data structures for high-speed packet parsing
from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, conf     # Core packet manipulation library (Metadata extraction only, No DPI)

def get_gateway_ip():                                           # Maps the local network's default gateway 
    """Dynamically find the default gateway IP using Scapy's routing table."""
    try:                                                        # Prevents hardcoding IPs, allowing plug-and-play functionality across different network environments (Home, Office, Public Wi-Fi)
        # conf.route.route("0.0.0.0") returns (network, netmask, gateway, interface, address, metric)
        return conf.route.route("0.0.0.0")[2]                   # Queries Scapy's internal routing table for the gateway IP 
    except Exception:
        return None                                             # Fallback if the testbed is completely isolated (Air-gapped)

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))           # Resolves absolute path for reliable cronjob execution and data storage
DB_NAME = os.path.join(BASE_DIR, "nids_logs.db")                # Resolves database path ensuring data never leaves the local Pi
IFACE_SNIFF = "en0" if platform.system() == "Darwin" else "eth0"# Adapts interface based on Host OS 
GATEWAY_IP = get_gateway_ip()                                   # Stores gateway IP to establish an ARP baseline
BLACKLIST_FILE = os.path.join(BASE_DIR, "blacklist.txt")        # External threat intelligence file for Reputation Filtering 

def load_blacklist():                                           # Loads the blacklist into a set for O(1) lookups during packet processing
    if not os.path.exists(BLACKLIST_FILE):                      # Failsafe if the threat feed is missing, ensuring the NIDS still functions with core capabilities (Except Reputation Filtering)
        return {"8.8.8.8"}                                      # Default fallback IP (Google DNS, Commonly Used in DDoS Attacks) to demonstrate functionality without a custom blacklist
    with open(BLACKLIST_FILE, "r") as f:                        # Reads the external feed, ignoring empty lines and comments (Lines starting with #), and stores valid IPs in a set for fast access during packet processing
        return {line.strip() for line in f if line.strip() and not line.startswith("#")} # Converts to a Set for O(1) constant-time lookups

BLACKLIST_IPS = load_blacklist()                                # Initialises Reputation-based detection rules

# State tracking (In-Memory structures for rapid evaluation on resource-constrained hardware)
packet_volume = defaultdict(lambda: deque())                    # Deque for highly efficient sliding-window Volumetric Anomaly Detection
arp_cache = {}                                                  # Maps IP to MAC for Stateful ARP Spoofing (MitM) detection
host_last_update = {}                                           # Tracks last update time for each host to throttle database writes (Prevents performance degradation on busy networks) 
port_scan_tracker = defaultdict(set)                            # Tracks unique ports hit per IP for Reconnaissance Detection
port_scan_start = defaultdict(float)                            # Tracks start time of port scan window per IP for accurate sliding-window analysis

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Async DB Worker Setup
db_queue = queue.Queue()                                        # Thread-safe buffer decoupling packet sniffing from slow disk I/O

def db_worker():                                                # Dedicated daemon thread for database interaction
    """Worker thread to handle database writes asynchronously."""
    with sqlite3.connect(DB_NAME) as conn:                      # Establishes connection to local SQLite file
        conn.execute('PRAGMA journal_mode=WAL;')                # Enforces Write-Ahead Logging. Prevents database locks when sniffer.py writes concurrently
        while True:                                             # Infinite loop listening for new alerts
            query, args = db_queue.get()                        # Blocks until a new alert is added to the queue by the main packet processing thread
            try:
                conn.execute(query, args)                       # Executes the database write safely within the worker thread, ensuring that packet sniffing is never blocked by disk I/O, which is crucial for maintaining high packet capture rates and preventing loss of critical security events.
                conn.commit()                                   # Commits the transaction to ensure data integrity and durability, while the main thread continues to process incoming packets without interruption.    
            except Exception as e:
                logging.error(f"DB Worker Error: {e}")          # Failsafe logging to prevent thread death
            db_queue.task_done()                                # Signals that the queued task is complete, allowing for proper queue management and graceful shutdown if needed in the future.

def init_db():                                                  # Builds the database schema dynamically on first boot
    """Initialize SQLite database with the required schema."""
    with sqlite3.connect(DB_NAME) as conn:                      # Establishes connection to local SQLite file 
        cursor = conn.cursor()
        cursor.execute('''                                      
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                alert_type TEXT,
                description TEXT
            )                                                   
        ''')                                                    # Creates the 'alerts' table to store detected security events with relevant metadata for later retrieval and analysis by the dashboard
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                last_seen TEXT
            )
        ''')                                                    # Creates the table mapping connected IoT endpoints
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        # Record start time
        cursor.execute('INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)', ('start_time', str(time.time())))
        conn.commit()

def log_alert(src_ip, dst_ip, protocol, alert_type, description):# Formats threat events for the dashboard
    """Insert alert into database."""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')              # Standardised timestamp format for consistent display on the dashboard and accurate sorting during retrieval
    logging.warning(f"ALERT [{alert_type}]: {description}")     # Outputs to standard terminal for headless debugging
    
    query = '''
        INSERT INTO alerts (timestamp, src_ip, dst_ip, protocol, alert_type, description)
        VALUES (?, ?, ?, ?, ?, ?)
    '''                                                          # Prepares the SQL query for inserting a new alert into the database
    db_queue.put((query, (timestamp, src_ip, dst_ip, protocol, alert_type, description))) # Pushes to Async worker thread

def clean_old_logs():                                           # GDPR Compliance: Storage Limitation (Article 5)
    """GDPR Compliance: Delete logs older than 7 days."""
    try:
        with sqlite3.connect(DB_NAME) as conn:                  # Establishes connection to local SQLite file
            cursor = conn.cursor()
            cursor.execute("DELETE FROM alerts WHERE timestamp < date('now', '-7 days')") # Automatically purges old logs
            conn.commit()                                       # Ensures no personal data is retained indefinitely
    except Exception as e:
        logging.error(f"Cleanup Error: {e}")                    # Failsafe to prevent crash if database is locked

def detect_volume_spike(src_ip):                                # IoT Botnet & Denial of Service (DoS) detection logic
    """Check if IP exceeds 500 packets in 10 seconds."""
    current_time = time.time()                                  # Captures the exact UNIX time of the packet arrival for precise sliding-window analysis
    timestamps = packet_volume[src_ip]                          # Retrieves the specific deque memory for this Source IP
    timestamps.append(current_time)                             # Adds new packet timestamp to the right of the queue

    # Remove timestamps older than 10 seconds
    while timestamps and timestamps[0] < current_time - 10:     # Removes old timestamps from the left (Sliding-window algorithm)
        timestamps.popleft()

    if len(timestamps) > 500:                                   # Threshold trigger: >500 packets in 10 seconds
        # Clear to prevent spamming alerts every packet after 500
        packet_volume[src_ip].clear()                           # Resets queue to prevent database alert spamming
        return True                                             # Returns True to trigger an alert in the main packet processing function
    return False

def update_host_db(ip, mac):                                    # Maintains situational awareness of connected devices
    """Update host last seen time, throttled to once per minute per host."""
    now = time.time()                                           # Captures the current time to compare against the last update time for this host
    if ip in host_last_update and (now - host_last_update[ip] < 60): # Throttles DB writes to once per minute per host to prevent performance degradation on busy networks
        return                                                  # If the host was updated less than 60 seconds ago, skip the database update to reduce unnecessary writes and improve performance

    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')              # Formats timestamp for database storage
    host_last_update[ip] = now                                  # Updates in-memory throttle cache
    query = 'INSERT OR REPLACE INTO hosts (ip, mac, last_seen) VALUES (?, ?, ?)'
    db_queue.put((query, (ip, mac, timestamp)))                 # Pushes host discovery to Async DB worker

def process_packet(packet):                                     # Core inspection engine. Enforces Data Minimisation (Metadata Only)   
    """Callback function for every captured packet."""
    
    # 1. ARP Spoofing Detection
    if ARP in packet and packet[ARP].op == 2:                   # Inspects stateful ARP layer for unsolicited 'Reply' packets, which are a common indicator of ARP spoofing attacks used
        psrc = packet[ARP].psrc                                 # Extracts claimed IP address
        hwsrc = packet[ARP].hwsrc                               # Extracts claimed MAC address 
        
        if psrc == GATEWAY_IP:                                  # Checks if packet claims to be the Default Gateway (Router)
            if psrc in arp_cache and arp_cache[psrc] != hwsrc:  # Evaluates if the MAC differs from the known baseline
                log_alert(psrc, "Broadcast", "ARP", "Critical", 
                          f"ARP Spoofing Detected! Gateway MAC changed from {arp_cache[psrc]} to {hwsrc}")
            arp_cache[psrc] = hwsrc                             # Updates memory with the current known Gateway MAC

    # 2. IP Layer Analysis
    if IP in packet:                                            # Verifies IP layer exists (ignores unroutable traffic)
        src_ip = packet[IP].src                                 # Extracts Source IP header
        dst_ip = packet[IP].dst                                 # Extracts Destination IP header
        proto_num = packet[IP].proto                            # Extracts Protocol integer (e.g., 6 for TCP, 17 for UDP, 1 for ICMP)
        protocol = "OTHER"                                      # Default protocol label for unsupported types

        # Track Host
        if Ether in packet:                                     # Parses Data Link layer for MAC address extraction to enhance asset discovery and contextual awareness on the dashboard
            update_host_db(src_ip, packet[Ether].src)           # Logs MAC address of newly discovered network hosts
        
        # Determine Protocol
        if proto_num == 6: protocol = "TCP"                     # Translates protocol integers to human-readable strings for dashboard display and more intuitive alert descriptions
        elif proto_num == 17: protocol = "UDP"
        elif proto_num == 1: protocol = "ICMP"

        # 3. Blacklist Check
        if dst_ip in BLACKLIST_IPS:                             # O(1) lookup to detect communication with known Malware C2s or other malicious endpoints, which is a critical indicator of compromise in many attack scenarios, including data exfiltration and botnet activity.
            log_alert(src_ip, dst_ip, protocol, "Critical", f"Connection to Blacklisted IP: {dst_ip}")

        # 4. Volume Spike Check
        if detect_volume_spike(src_ip):                         # Evaluates traffic velocity against Botnet threshold logic, which is essential for early detection of volumetric attacks such as DDoS or the rapid scanning behavior of worms and bots, allowing for timely alerts before the attack can fully manifest.
            log_alert(src_ip, dst_ip, protocol, "Investigative", f"Volume Spike: >500 packets/10s from {src_ip}")

        # 5. Insecure Protocols (TCP)
        if TCP in packet:                                       # Inspects TCP Transport layer
            dport = packet[TCP].dport                           # Extracts Destination Port 
            sport = packet[TCP].sport                           # Extracts Source Port
            flags = packet[TCP].flags                           # Extracts TCP Flags for anomaly detection (e.g., Null/Xmas scans) which are commonly used in reconnaissance phases of attacks to identify open ports and services without completing a full TCP handshake, thus evading some traditional IDS signatures.
            
            if dport == 23 or sport == 23:                      # Flags legacy plaintext protocols highly vulnerable to IoT Botnets
                log_alert(src_ip, dst_ip, "TCP", "Warning", "Insecure Telnet Traffic Detected")
            elif dport == 21 or sport == 21:                    # Flags unencrypted file transfers
                log_alert(src_ip, dst_ip, "TCP", "Warning", "Insecure FTP Traffic Detected")

            # 6. TCP Flag Anomalies (Null & Xmas Scans)
            if flags == 0:                                      # Detects stealth Null scans attempting to bypass firewalls by sending packets with no flags set, which can be a strong indicator of reconnaissance activity as attackers use this technique to probe for open ports without completing a full TCP handshake, thus avoiding some traditional IDS signatures.
                log_alert(src_ip, dst_ip, "TCP", "Warning", "Null Scan Detected (No Flags)")
            elif (flags & 0x29) == 0x29:                        # Bitwise AND detects Xmas Scans (FIN, PSH, URG set simultaneously)
                log_alert(src_ip, dst_ip, "TCP", "Warning", "Xmas Scan Detected (FIN, PSH, URG)")

            # 7. Land Attack (Source == Destination)
            if src_ip == dst_ip and sport == dport:             # Detects self-referential DoS exploit where the attacker sends packets with the same source and destination IP and port, which can cause some systems to crash or become unresponsive due to improper handling of such anomalous traffic, making it a critical alert for potential DoS conditions.
                log_alert(src_ip, dst_ip, "TCP", "Critical", "Land Attack Detected (Self-Connection)")

            # 8. Port Scan Detection (Horizontal)
            # Logic: > 15 unique ports in 10 seconds
            now = time.time()
            if now - port_scan_start[src_ip] > 10:              # Resets scan tracking window every 10 seconds
                port_scan_tracker[src_ip].clear()
                port_scan_start[src_ip] = now
            
            port_scan_tracker[src_ip].add(dport)                # Adds unique destination ports to the tracking set
            if len(port_scan_tracker[src_ip]) > 15:             # Trigger: Hitting >15 unique ports in 10s indicates an Nmap sweep
                log_alert(src_ip, "Multiple", "TCP", "Warning", "Port Scan Detected (>15 ports/10s)")
                port_scan_tracker[src_ip].clear()               # Reset to avoid spamming the database 

if __name__ == "__main__":                                       # Main Execution Block
    init_db()                                                    # Prepares local SQLite architecture
    clean_old_logs()                                             # Executes GDPR storage limitation purge on boot 
    logging.info(f"Starting Passive NIDS on {IFACE_SNIFF}...")
    
    # Start DB Worker Thread
    t = threading.Thread(target=db_worker, daemon=True)          # Initialises background asynchronous database writer to ensure that packet processing is never blocked by disk I/O, which is crucial for maintaining high packet capture rates and preventing loss of critical security events.
    t.start()                                                    # Starts the thread

    # store=0 prevents Scapy from keeping packets in memory (Privacy/Performance)
    try:
        # store=0 strictly enforces Privacy by Design by dropping raw payloads from RAM after processing, ensuring that no sensitive data is retained in memory, while also improving performance on resource-constrained hardware by freeing up memory immediately after use.
        sniff(iface=IFACE_SNIFF, prn=process_packet, store=0) # Commences out-of-band packet interception
    except PermissionError:                                   # Promiscuous mode requires root network privileges  
        logging.error("Root privileges required. Run with sudo.")