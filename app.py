from flask import Flask, render_template, jsonify                       # Flask abstracts complex HTTP routing into a lightweight edge-server
import sqlite3                                                          # Database driver to read threat intelligence locally (Data Sovereignty)
import os                                                               # OS interactions to resolve dynamic file paths
import time 
# Native time library for uptime metrics
app = Flask(__name__)                                                   # Initialise the Flask WSGI application instance
BASE_DIR = os.path.dirname(os.path.abspath(__file__))                   # Resolves absolute path to guarantee reliable cronjob execution
DB_NAME = os.path.join(BASE_DIR, "nids_logs.db")                        # Resolves database path ensuring data never leaves the local Pi

def get_db_connection():                                                # Establishes localised connections for the UI
    conn = sqlite3.connect(DB_NAME)                                     
    conn.row_factory = sqlite3.Row                                      # Allows accessing columns by dictionary name rather than tuple index
    conn.execute('PRAGMA journal_mode=WAL;')                            # Enforces Write-Ahead Logging. Prevents database locks when sniffer.py writes concurrently
    return conn

@app.route('/')                                                         # Default web route (The User Entry Point)
def index():
    return render_template('index.html')                                # Renders the HTML template for the dashboard, which will then make AJAX calls to fetch dynamic data

@app.route('/api/alerts')                                               # API endpoint for fetching recent alerts (Consumed by AJAX in index.html)
def get_alerts():
    """Returns the last 50 entries."""
    conn = get_db_connection()
    alerts = conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 50').fetchall() # Limits query to 50 to prevent client-side memory exhaustion 
    conn.close()
    return jsonify([dict(ix) for ix in alerts])                         # Converts SQLite rows to a list of dictionaries for JSON serialization

@app.route('/api/stats')                                                # REST API Endpoint for Chart.js aggregations  
def get_stats():
    """Returns stats for charts."""
    conn = get_db_connection()
    
    
    # Alert Type Counts
    type_counts = conn.execute('''
        SELECT alert_type, COUNT(*) as count 
        FROM alerts 
        GROUP BY alert_type
    ''').fetchall()                                                     # Aggregates severity levels (Critical, Warning, Investigative)
    
    # Protocol Counts (For Pie Chart)
    proto_counts = conn.execute('''
        SELECT protocol, COUNT(*) as count 
        FROM alerts 
        GROUP BY protocol
    ''').fetchall()                                                     # Aggregates protocol distribution (TCP, UDP, ICMP) 

    # Top Source IPs (Top Attackers)
    top_sources = conn.execute('''
        SELECT src_ip, COUNT(*) as count 
        FROM alerts 
        GROUP BY src_ip 
        ORDER BY count DESC 
        LIMIT 5
    ''').fetchall()

    # Host Count
    host_count = conn.execute('SELECT COUNT(*) as count FROM hosts').fetchone()['count'] # Tallies active connected IoT devices for Asset Discovery

    # Uptime Calculation
    uptime_seconds = 0                                                   # Default to 0 if start_time is not found or invalid  
    try:
        start_time_row = conn.execute("SELECT value FROM metadata WHERE key='start_time'").fetchone()
        if start_time_row:
            start_time = float(start_time_row['value'])
            uptime_seconds = int(time.time() - start_time)               # Compares current time vs initialisation time
    except Exception:
        pass                                                             # Failsafe: Ensures dashboard still loads even if uptime metadata is missing
    
    conn.close()
                                                                         
    return jsonify({                                                     # Returns a structured JSON object containing all the aggregated statistics needed to update the dashboard's charts and metrics in a single API call, optimizing performance and reducing client-server communication overhead.
        "types": {row['alert_type']: row['count'] for row in type_counts},
        "protocols": {row['protocol']: row['count'] for row in proto_counts},
        "top_sources": {row['src_ip']: row['count'] for row in top_sources},
        "host_count": host_count,
        "uptime": uptime_seconds
    })

@app.route('/api/hosts')                                                # REST API Endpoint for Asset Discovery module   
def get_hosts():
    conn = get_db_connection()
    hosts = conn.execute('SELECT * FROM hosts ORDER BY last_seen DESC').fetchall() # Fetches all devices observed by the passive monitor
    conn.close()
    return jsonify([dict(ix) for ix in hosts])

    
if __name__ == '__main__':
    # Host 0.0.0.0 binds to all Pi network interfaces (wlan0/eth0), making the dashboard seamlessly accessible across the entire local network
    app.run(host='0.0.0.0', port=8880, debug=False)                     # Runs the web server on port 8880 with debug off for production security
