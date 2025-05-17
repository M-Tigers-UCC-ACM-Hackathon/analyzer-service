from datetime import timedelta
from app.models.queries import insert_analyzed_log, update_analyzed_flag, insert_alert


VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT"}


def detect_anomalies(log_row, conn):
    # Step 1: Insert a copy into nginx_logs_analyzed with default flag 0
    insert_analyzed_log(conn, log_row, flag=0)

    # Step 2: Run all anomaly checks and flag accordingly
    if check_error_burst(log_row, conn):
        update_analyzed_flag(conn, log_row["id"], flag=1)
        insert_alert(
            conn,
            alert_type="Error Burst",
            severity=2,
            offender_ip=log_row["ip"],
            reason="20+ 5xx errors in 1 minute",
            explanation="A spike of server errors indicates instability.",
        )
    elif check_ip_spike(log_row, conn):
        update_analyzed_flag(conn, log_row["id"], flag=2)
        insert_alert(
            conn,
            alert_type="IP Spike",
            severity=2,
            offender_ip=log_row["ip"],
            reason="100+ requests from same IP in 1 minute",
            explanation="This IP sent unusually high traffic in a short window.",
        )
    elif check_behavior_deviation(log_row, conn):
        update_analyzed_flag(conn, log_row["id"], flag=3)
        insert_alert(
            conn,
            alert_type="Behavior Deviation",
            severity=1,
            offender_ip=log_row["ip"],
            reason="Unusual request behavior",
            explanation="Request method, path or size deviated from expected patterns.",
        )
    else:
        # No anomalies, flag stays 0
        pass


def check_error_burst(row, conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*) FROM nginx_logs
            WHERE log_time >= TIMESTAMP %s - INTERVAL '1 minute'
              AND status >= 300
        """,
            (row["log_time"],),
        )
        count = cur.fetchone()[0]
        return count >= 20


def check_ip_spike(row, conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*) FROM nginx_logs
            WHERE ip = %s AND log_time >= TIMESTAMP %s - INTERVAL '1 minute'
        """,
            (row["ip"], row["log_time"]),
        )
        count = cur.fetchone()[0]
        return count >= 100


def check_behavior_deviation(row, conn):
    if is_invalid_method(row["method"]):
        return True
    if is_suspicious_path(row["path"]):
        return True
    if is_path_spammy(row, conn):
        return True
    if is_bytes_extreme(row, conn):
        return True
    return False


def is_invalid_method(method):
    return method.upper() not in VALID_METHODS


def is_suspicious_path(path):
    suspicious_patterns = [
        "/xmlrpc.php",
        "/wp-cron.php",
        "/wp-json",
        ".php",
        "?cmd=",
        "/admin",
        "/login",
        "base64",
        "eval(",
        "../",
    ]
    return any(p in path.lower() for p in suspicious_patterns)


def is_path_spammy(row, conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*) FROM nginx_logs
            WHERE ip = %s AND path = %s AND log_time >= TIMESTAMP %s - INTERVAL '1 minute'
        """,
            (row["ip"], row["path"], row["log_time"]),
        )
        count = cur.fetchone()[0]
        return count > 50


def is_bytes_extreme(row, conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT AVG(bytes) FROM nginx_logs
            WHERE log_time >= TIMESTAMP %s - INTERVAL '10 minutes'
        """,
            (row["log_time"],),
        )
        avg_bytes = cur.fetchone()[0] or 1  # avoid division by zero
    deviation = abs(row["bytes"] - avg_bytes) / avg_bytes
    return deviation > 2.0  # more than 200% deviation
