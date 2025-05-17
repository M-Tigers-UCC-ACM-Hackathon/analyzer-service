from fastapi import FastAPI
from app.db import get_connection
import psycopg2

app = FastAPI()


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
