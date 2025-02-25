# this script is used to import the schedules data from the database and then save them in a json file named schedules.json
# the script uses psycopg2 library to connect to the database and fetch the data

import psycopg2
import json
from datetime import datetime

# Database connection details
DB_HOST = "192.168.2.62"
DB_NAME = "dlp_new"
DB_USER = "postgres"
DB_PASSWORD = "root"
TABLE_NAME = "general_scheduler"

# Custom JSON serializer for datetime
def json_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

# Database connection helper
def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )

# Fetch the latest schedule by recurrence type
def get_latest_schedule(recurrence_type):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Adjust query to properly fetch 'cron' schedules when recurrence is NULL
        if recurrence_type is None:
            query = f"""
                SELECT * FROM {TABLE_NAME}
                WHERE recurrence IS NULL
                ORDER BY updated_at DESC
                LIMIT 1;
            """
        else:
            query = f"""
                SELECT * FROM {TABLE_NAME}
                WHERE recurrence = %s
                ORDER BY updated_at DESC
                LIMIT 1;
            """

        cursor.execute(query, (recurrence_type,) if recurrence_type else ())
        row = cursor.fetchone()

        if row:
            colnames = [desc[0] for desc in cursor.description]
            return dict(zip(colnames, row))
        else:
            print(f"No {recurrence_type if recurrence_type else 'cron'} schedule found.")
            return None

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def save_schedules_to_file():
    schedules = {
        "weekly": get_latest_schedule("Weekly"),
        "daily": get_latest_schedule("Daily"),
        "cron": get_latest_schedule(None)
    }
    with open("schedules.json", "w") as f:
        json.dump(schedules, f, default=json_serializer, indent=4)
    print("Schedules saved to schedules.json")

if __name__ == "__main__":
    save_schedules_to_file()
