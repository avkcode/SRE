#!/usr/bin/env python3
"""
Test connection to Aurora PostgreSQL database
"""
import sys
import time
try:
    import psycopg2
    from psycopg2 import OperationalError, Error
except ImportError:
    print("psycopg2 not installed. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psycopg2-binary"])
    import psycopg2
    from psycopg2 import OperationalError, Error

# Database connection parameters from db_credentials.txt
DB_HOST = "aurora-postgres-cluster.cluster-ct2i4esmu82t.eu-central-1.rds.amazonaws.com"
DB_PORT = "5432"
DB_NAME = "postgres"
DB_USER = "root"
DB_PASSWORD = "Cv=kfa*OQ(?[4K}F"

def test_connection(max_retries=3, retry_delay=5):
    """
    Test connection to the database with retry logic
    """
    print(f"Attempting to connect to database at {DB_HOST}...")
    
    connection = None
    for attempt in range(max_retries):
        try:
            # Establish connection
            connection = psycopg2.connect(
                host=DB_HOST,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD,
                port=DB_PORT,
                connect_timeout=10
            )
            
            # Create a cursor
            cursor = connection.cursor()
            
            # Execute a test query
            cursor.execute("SELECT version();")
            
            # Fetch the result
            version = cursor.fetchone()
            
            print("\n✅ CONNECTION SUCCESSFUL")
            print(f"Connected to: {DB_HOST}:{DB_PORT}/{DB_NAME}")
            print(f"User: {DB_USER}")
            print(f"Database version: {version[0]}")
            
            # Check if we can create and drop a test table
            print("\nTesting database write permissions...")
            try:
                cursor.execute("CREATE TABLE connection_test (id serial PRIMARY KEY, test_date timestamp DEFAULT now());")
                cursor.execute("INSERT INTO connection_test (test_date) VALUES (now());")
                cursor.execute("SELECT * FROM connection_test;")
                test_data = cursor.fetchall()
                print(f"Created test record: {test_data}")
                cursor.execute("DROP TABLE connection_test;")
                print("Successfully created and dropped test table")
                connection.commit()
            except Error as e:
                print(f"Note: Could not perform write operations: {e}")
                connection.rollback()
            
            break
            
        except OperationalError as e:
            if "timeout" in str(e).lower():
                error_type = "Connection timeout"
            elif "could not connect" in str(e).lower():
                error_type = "Connection refused"
            else:
                error_type = "Operational error"
                
            print(f"❌ {error_type}: {e}")
            
            if attempt < max_retries - 1:
                print(f"Retrying in {retry_delay} seconds... (Attempt {attempt + 1}/{max_retries})")
                time.sleep(retry_delay)
            else:
                print("Maximum retry attempts reached. Connection failed.")
                print("\nTROUBLESHOOTING TIPS:")
                print("1. Check if the database endpoint is correct")
                print("2. Verify that the security group allows access from your IP")
                print("3. Ensure that database credentials are correct")
                print("4. Check if the database is running and accepting connections")
                return False
                
        except Exception as e:
            print(f"❌ ERROR: {e}")
            print("\nFailed to connect to the database. Please check your connection parameters.")
            return False
            
        finally:
            if connection is not None:
                connection.close()
                
    return True

if __name__ == "__main__":
    test_connection()

