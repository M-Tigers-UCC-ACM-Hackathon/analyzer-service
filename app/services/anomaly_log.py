from datetime import timedelta
from app.models.queries import insert_analyzed_log, update_analyzed_flag, insert_alert
import json


VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT"}


def detect_anomalies(log_row, conn):
    print(log_row)
    log_row = json.loads(log_row)
    print(log_row)
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
            reason=f"Multiple 4xx errors in 1 minute, path: {log_row['path']}",
            explanation=(
                "A burst of client/server errors (status >= 400) was detected in the past minute. "
                "This may indicate application bugs, misconfigured endpoints, or automated scanning. "
                "Consider reviewing logs for repetitive failing requests, especially from automated clients or crawlers."
            ),
            log_time=log_row["log_time"],
        )
        return True
    elif check_ip_spike(log_row, conn):
        update_analyzed_flag(conn, log_row["id"], flag=2)
        insert_alert(
            conn,
            alert_type="IP Spike",
            severity=2,
            offender_ip=log_row["ip"],
            reason="Multiple requests from same IP in 1 minute",
            explanation=(
                f"The IP {log_row['ip']} sent an unusually high number of requests "
                "within a 1-minute window. This could indicate scraping, brute force activity, "
                "or an overactive service. Monitor for DDoS-like patterns and rate-limit if needed."
            ),
            log_time=log_row["log_time"],
        )
        return True
    elif check_behavior_deviation(log_row, conn):
        update_analyzed_flag(conn, log_row["id"], flag=3)
        insert_alert(
            conn,
            alert_type="Behavior Deviation",
            severity=1,
            offender_ip=log_row["ip"],
            reason=f"Unusual request behavior: method={log_row['method']}, path={log_row['path']}",
            explanation=(
                "This request used a non-standard method or suspicious path, which deviates from typical traffic. "
                "Examples include admin probes, script injections, or unusual API misuse. "
                "Check for payload anomalies, or access to sensitive routes (e.g. wp-login.php, .env files)."
            ),
            log_time=log_row["log_time"],
        )
        return True
    else:
        # No anomalies, flag stays 0
        return False


def check_error_burst(row, conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*) FROM nginx_logs
            WHERE log_time >= TIMESTAMP %s - INTERVAL '1 minute'
              AND log_time < TIMESTAMP %s
              AND status >= 400
        """,
            (row["log_time"], row["log_time"]),
        )
        count = cur.fetchone()[0]
        return count >= 7


def check_ip_spike(row, conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*) FROM nginx_logs
            WHERE ip = %s
              AND log_time >= TIMESTAMP %s - INTERVAL '1 minute'
              AND log_time < TIMESTAMP %s
        """,
            (row["ip"], row["log_time"], row["log_time"]),
        )
        count = cur.fetchone()[0]
        return count >= 6


def check_behavior_deviation(row, conn):
    if is_invalid_method(row["method"]):
        return True
    if is_suspicious_path(row["path"]):
        return True
    if is_path_spammy(row, conn):
        return True
    print("No anomalies detected for:", row)
    return False


def is_invalid_method(method):
    return method.upper() not in VALID_METHODS


def is_suspicious_path(path):
    suspicious_patterns = [
        "?cmd=",
        "/admin",
        "base64",
        "eval(",
        "../",
        "etc",
        ".git",
        ".env",
        "wp-admin",
        "wp-login",
        "cron"
    ]
    return any(p in path.lower() for p in suspicious_patterns)


def is_path_spammy(row, conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*) FROM nginx_logs
            WHERE ip = %s AND path = %s
              AND log_time >= TIMESTAMP %s - INTERVAL '1 minute'
              AND log_time < TIMESTAMP %s
        """,
            (row["ip"], row["path"], row["log_time"], row["log_time"]),
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
