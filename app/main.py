from fastapi import FastAPI
from app.db import get_connection
from app.services.anomaly_listener import listen_for_new_logs
from threading import Thread
import psycopg2

app = FastAPI()


@app.on_event("startup")
def start_listener_thread():
    t = Thread(target=listen_for_new_logs)
    t.daemon = True
    t.start()
    print("Analyzer listener started in background.")


@app.get("/")
def health_check():
    return {"status": "analyzer-service running"}


@app.get("/test-db")
def test_db_connection():
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        result = cur.fetchone()
        cur.close()
        conn.close()
        return {"db_status": "connected", "result": result[0]}
    except psycopg2.Error as e:
        return {"db_status": "failed", "error": str(e)}
