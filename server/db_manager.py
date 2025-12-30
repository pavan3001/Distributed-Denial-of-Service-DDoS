# server/db_manager.py

import mysql.connector
from mysql.connector import Error
import threading
import time
import sys

# --- MySQL Configuration ---
# !!! UPDATE THESE CREDENTIALS FOR YOUR SETUP !!!
DB_CONFIG = {
    'host': 'localhost',
    'database': 'ddos_monitor',
    'user': 'root', # Use your MySQL username
    'password': 'Sailesh@1035' # Use your MySQL password
}

# Use a local queue for batch insertion to minimize connection overhead
DB_WRITE_QUEUE = queue.Queue(maxsize=5000)

def create_db_connection():
    """Creates a connection to the MySQL database."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print(f"[DB ERROR] Error connecting to MySQL: {e}", file=sys.stderr)
        return None

def db_writer_loop():
    """Continuously reads the queue and writes data to the database in batches."""
    print("[*] Starting database writer loop...")
    
    while True:
        time.sleep(2) # Wait 2 seconds between batch writes
        
        if DB_WRITE_QUEUE.empty():
            continue
            
        data_to_insert = []
        while not DB_WRITE_QUEUE.empty():
            data_to_insert.append(DB_WRITE_QUEUE.get_nowait())
            if len(data_to_insert) >= 100: # Batch size limit
                break

        if not data_to_insert:
            continue
            
        conn = create_db_connection()
        if not conn:
            continue

        cursor = conn.cursor()
        
        # SQL query to insert multiple rows
        sql = """
        INSERT INTO ip_traffic (
            timestamp_unix, ip_address, risk_score, flow_count, 
            status, ddos_type, packet_type, packets_per_second, bits_per_second
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        # Format data for executemany
        records_to_insert = [
            (
                item['timestamp'], item['ip'], item['risk'], item['flow_count'], 
                item['status'], item['ddos_type'], item['packet_type'], 
                item['pps'], item['bps']
            ) for item in data_to_insert
        ]

        try:
            cursor.executemany(sql, records_to_insert)
            conn.commit()
            print(f"[DB] Successfully inserted {len(records_to_insert)} flow records.")
        except Error as e:
            conn.rollback()
            print(f"[DB ERROR] Failed to insert data: {e}", file=sys.stderr)
        finally:
            cursor.close()
            conn.close()

# Start the dedicated database writer thread
db_writer_thread = threading.Thread(target=db_writer_loop, daemon=True)
db_writer_thread.start()