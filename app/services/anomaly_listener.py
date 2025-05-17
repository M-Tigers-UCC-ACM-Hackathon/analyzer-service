import psycopg2
import select
import os
from dotenv import load_dotenv
import json
import app.services.anomaly_log as anomaly_log

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("PG_HOST"),
    "port": os.getenv("PG_PORT"),
    "user": os.getenv("PG_USER"),
    "password": os.getenv("PG_PASSWORD"),
    "dbname": os.getenv("PG_DB"),
}
# from app.services.anomaly_log import detect_anomalies
# from app.db import get_connection


def listen_for_new_logs():
    # Ensure the trigger is set up
    conn = psycopg2.connect(**DB_CONFIG, sslmode="require")
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    cur.execute("LISTEN new_nginx_log;")
    print("Listening for new logs...")

    while True:
        if select.select([conn], [], [], 5) == ([], [], []):
            continue
        conn.poll()
        while conn.notifies:
            notify = conn.notifies.pop(0)
            log_row = notify.payload
            print(anomaly_log.check_behavior_deviation(log_row, conn))
            print(f"New log row inserted: {log_row}")

            # detect_anomalies(new_id)  # your logic for preprocessing + 3 checks


def main():
    listen_for_new_logs()


if __name__ == "__main__":
    main()
