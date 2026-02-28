#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import traceback
import json
import time

# Try to import zxJDBC for Jython environment
try:
    from com.ziclix.python.sql import zxJDBC
    USE_ZXJDBC = True
except ImportError:
    import sqlite3
    USE_ZXJDBC = False

class DatabaseManager:
    def __init__(self, db_path="autorize_traffic.db"):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        
        # Determine database path relative to this file (e.g., Autorize/db/../autorize_traffic.db)
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            # Save DB in the parent directory of 'db' folder, i.e., in 'Autorize' root
            plugin_root = os.path.dirname(current_dir)
            self.db_path = os.path.join(plugin_root, db_path)
            print("Calculated database path: " + self.db_path)
            
            # Ensure lib jars are in sys.path (in case Autorize.py didn't pick them up or hot reload issues)
            if USE_ZXJDBC:
                lib_dir = os.path.join(plugin_root, "lib")
                if os.path.exists(lib_dir):
                    for jar in os.listdir(lib_dir):
                        if jar.endswith(".jar"):
                            jar_path = os.path.join(lib_dir, jar)
                            
                            # Method 1: sys.path.append (Standard Python)
                            if jar_path not in sys.path:
                                sys.path.append(jar_path)
                                print("Added to sys.path: " + jar_path)
                            
                            # Method 2: sys.add_package (Jython specific, sometimes needed)
                            try:
                                import sys
                                if hasattr(sys, 'add_package'):
                                    sys.add_package(jar_path)
                            except:
                                pass
                                
                            # Method 3: java.net.URLClassLoader (Java specific, forceful loading)
                            try:
                                from java.io import File
                                from java.net import URL, URLClassLoader
                                from java.lang import ClassLoader
                                
                                method = URLClassLoader.getDeclaredMethod("addURL", [URL])
                                method.setAccessible(True)
                                method.invoke(ClassLoader.getSystemClassLoader(), [File(jar_path).toURI().toURL()])
                                print("Added to SystemClassLoader: " + jar_path)
                            except Exception as e:
                                print("Failed to add to SystemClassLoader: " + str(e))
                
                # Explicitly load the driver class
                try:
                    from java.lang import Class
                    # Force reload logic
                    try:
                       Class.forName("org.sqlite.JDBC")
                    except:
                       # If failed, try to load using the jar path explicitly via URLClassLoader if not system loader
                       pass
                       
                    print("Loaded org.sqlite.JDBC driver successfully")
                except Exception as e:
                    print("Failed to load org.sqlite.JDBC driver: " + str(e))
                    
        except:
            # Fallback to current working directory if __file__ is not available
            if not os.path.isabs(self.db_path):
                 self.db_path = os.path.join(os.getcwd(), self.db_path)
            print("Fallback database path: " + self.db_path)
             
        self.init_db()

    def get_connection(self):
        try:
            conn = None
            if USE_ZXJDBC:
                jdbc_url = "jdbc:sqlite:" + self.db_path
                driver = "org.sqlite.JDBC"
                conn = zxJDBC.connect(jdbc_url, None, None, driver)
            else:
                conn = sqlite3.connect(self.db_path, timeout=30) # Increased timeout
            
            return conn
        except Exception as e:
            print("Error connecting to database: " + str(e))
            return None

    def execute_query(self, query, params=None, commit=True, retries=5):
        """
        Execute a query with retry mechanism for SQLITE_BUSY errors.
        """
        conn = None
        cursor = None
        attempt = 0
        while attempt < retries:
            try:
                conn = self.get_connection()
                if not conn:
                    return None
                
                cursor = conn.cursor()
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                if commit:
                    conn.commit()
                    
                # Return logic
                if not commit:
                    return cursor # Return cursor for fetching results (caller must close)
                
                # If it was an insert, try to get last ID
                last_id = None
                try:
                    if not USE_ZXJDBC:
                        last_id = cursor.lastrowid
                    else:
                        # For zxJDBC, getting last id might require a separate query in same transaction?
                        # But we just committed.
                        # Usually cursor.lastrowid is not supported in zxJDBC directly.
                        pass
                except:
                    pass
                
                return last_id if last_id else True

            except Exception as e:
                error_msg = str(e)
                if "database is locked" in error_msg or "SQLITE_BUSY" in error_msg:
                    attempt += 1
                    print("[DB] Database locked, retrying {}/{}...".format(attempt, retries))
                    time.sleep(0.5 * attempt) # Exponential backoff
                else:
                    print("[DB] Error executing query: " + error_msg)
                    # traceback.print_exc()
                    return None
            finally:
                if commit and cursor:
                    try: cursor.close()
                    except: pass
                if commit and conn:
                    try: conn.close()
                    except: pass
        
        print("[DB] Failed to execute query after {} retries.".format(retries))
        return None

    def fetch_all(self, query, params=None):
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            if not conn:
                return []
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return cursor.fetchall()
        except Exception as e:
            print("[DB] Error fetching data: " + str(e))
            return []
        finally:
            if cursor:
                try: cursor.close()
                except: pass
            if conn:
                try: conn.close()
                except: pass

    def init_db(self):
        # Using direct execution for init to keep it simple, or migrate to execute_query
        try:
            conn = self.get_connection()
            if conn:
                cursor = conn.cursor()
                
                # Enable WAL mode for better concurrency
                try:
                    cursor.execute("PRAGMA journal_mode=WAL;")
                except:
                    pass
                
                # 1. raw_requests table
                cursor.execute("CREATE TABLE IF NOT EXISTS raw_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, method TEXT, host TEXT, url TEXT, path TEXT, headers TEXT, query_params TEXT, body BLOB, user_identifier TEXT, is_analyzed BOOLEAN DEFAULT 0, analyzed_at DATETIME)")
                
                # Check if analyzed_at column exists (for upgrade)
                try:
                    cursor.execute("SELECT analyzed_at FROM raw_requests LIMIT 1")
                except:
                    # Column likely missing, add it
                    try:
                        cursor.execute("ALTER TABLE raw_requests ADD COLUMN analyzed_at DATETIME")
                        conn.commit()
                        print("Added analyzed_at column to raw_requests")
                    except Exception as e:
                        print("Failed to add analyzed_at column: " + str(e))
                
                # 2. parameter_pool table
                cursor.execute("CREATE TABLE IF NOT EXISTS parameter_pool (id INTEGER PRIMARY KEY AUTOINCREMENT, api_signature TEXT, param_name TEXT, param_value TEXT, location TEXT, user_identifier TEXT, risk_score INTEGER DEFAULT 0, llm_analysis_result TEXT, UNIQUE(api_signature, param_name, user_identifier))")

                # Check if risk_score column exists (for upgrade)
                try:
                    cursor.execute("SELECT risk_score FROM parameter_pool LIMIT 1")
                except:
                    # Column likely missing, add it
                    try:
                        cursor.execute("ALTER TABLE parameter_pool ADD COLUMN risk_score INTEGER DEFAULT 0")
                        cursor.execute("ALTER TABLE parameter_pool ADD COLUMN llm_analysis_result TEXT")
                        conn.commit()
                        print("Added risk_score and llm_analysis_result columns to parameter_pool")
                    except Exception as e:
                        print("Failed to add columns to parameter_pool: " + str(e))

                # 3. attack_queue table (Renamed from burp_generated_requests for clarity in requirements)
                # But let's stick to 'burp_generated_requests' or 'attack_queue'?
                # The requirements said 'attack_queue'. Let's use that.
                cursor.execute("CREATE TABLE IF NOT EXISTS attack_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, original_request_id INTEGER, target_user TEXT, payload_description TEXT, request_data BLOB, status TEXT DEFAULT 'PENDING', response_data BLOB, response_code INTEGER, vulnerability_score INTEGER, llm_verification_result TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(original_request_id) REFERENCES raw_requests(id))")
                
                # Check for new columns in attack_queue
                try:
                    cursor.execute("SELECT response_data, response_code, llm_verification_result FROM attack_queue LIMIT 1")
                except:
                    # Columns might be missing
                    try:
                        cursor.execute("ALTER TABLE attack_queue ADD COLUMN response_data BLOB")
                    except: pass
                    try:
                        cursor.execute("ALTER TABLE attack_queue ADD COLUMN response_code INTEGER")
                    except: pass
                    try:
                        cursor.execute("ALTER TABLE attack_queue ADD COLUMN llm_verification_result TEXT")
                    except: pass
                    conn.commit()
                    print("Added new columns to attack_queue")
                
                conn.commit()
                print("Database initialized successfully at " + self.db_path)
                
                cursor.close()
                conn.close()
        except Exception as e:
            print("Error initializing database: " + str(e))
            traceback.print_exc()

    def save_raw_request(self, method, host, url, path, headers, query_params, body, user_identifier):
        # Prepare params
        headers_json = json.dumps(headers)
        query_json = json.dumps(query_params)
        
        sql = "INSERT INTO raw_requests (method, host, url, path, headers, query_params, body, user_identifier) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        params = [method, host, url, path, headers_json, query_json, body, user_identifier]
        
        return self.execute_query(sql, params)

    def clear_all_data(self):
        try:
            conn = self.get_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM attack_queue")
                cursor.execute("DELETE FROM parameter_pool")
                cursor.execute("DELETE FROM raw_requests")
                cursor.execute("DELETE FROM sqlite_sequence") # Reset auto-increment counters
                conn.commit()
                print("All database data cleared successfully.")
                cursor.close()
                conn.close()
                return True
        except Exception as e:
            print("Error clearing database: " + str(e))
            traceback.print_exc()
            return False
