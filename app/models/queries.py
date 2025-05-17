from psycopg2.extras import RealDictCursor


def insert_analyzed_log(conn, log_row, flag=0):
    pass


def update_analyzed_flag(conn, log_id, flag):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE nginx_logs SET flag = %s WHERE id = %s
        """,
            (flag, log_id),
        )
        conn.commit()


def insert_traffic_metrics(
    conn, start_time, end_time, ip, total_requests, error_rate, flag
):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO traffic_metrics (start_time, end_time, ip, total_requests, error_rate, flag)
            VALUES (%s, %s, %s, %s, %s, %s)
        """,
            (start_time, end_time, ip, total_requests, error_rate, flag),
        )
        conn.commit()


def insert_alert(conn, alert_type, severity, offender_ip, reason, explanation):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts (alert_type, severity, offender_ip, reason, explanation)
            VALUES (%s, %s, %s, %s, %s)
        """,
            (alert_type, severity, offender_ip, reason, explanation),
        )
        conn.commit()
