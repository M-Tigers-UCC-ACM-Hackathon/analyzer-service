from app.db import get_connection

TRIGGER_SQL = """
CREATE OR REPLACE FUNCTION notify_new_log()
RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('new_nginx_log', NEW.id::TEXT);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_notify_new_log ON nginx_logs;

CREATE TRIGGER trigger_notify_new_log
AFTER INSERT ON nginx_logs
FOR EACH ROW
EXECUTE FUNCTION notify_new_log();
"""


def setup_trigger():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(TRIGGER_SQL)
    conn.commit()
    print("Trigger and function created.")
    cur.close()
    conn.close()
