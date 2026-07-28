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

                                if hasattr(sys, "add_package"):
                                    sys.add_package(jar_path)
                            except:
                                pass

                            # Method 3: java.net.URLClassLoader (Java specific, forceful loading)
                            try:
                                from java.io import File
                                from java.net import URL, URLClassLoader
                                from java.lang import ClassLoader

                                method = URLClassLoader.getDeclaredMethod(
                                    "addURL", [URL]
                                )
                                method.setAccessible(True)
                                method.invoke(
                                    ClassLoader.getSystemClassLoader(),
                                    [File(jar_path).toURI().toURL()],
                                )
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
                # busy_timeout 写进 JDBC URL（xerial sqlite-jdbc 支持 ?busy_timeout= 参数）
                jdbc_url = "jdbc:sqlite:" + self.db_path + "?busy_timeout=5000"
                driver = "org.sqlite.JDBC"
                conn = zxJDBC.connect(jdbc_url, None, None, driver)
            else:
                conn = sqlite3.connect(self.db_path, timeout=30)  # Increased timeout
                # busy_timeout 是连接级，必须每次建连接都设
                try:
                    conn.execute("PRAGMA busy_timeout=5000;")
                except Exception as e_bt:
                    print("[DB] WARN: failed to set busy_timeout on python connection: " + str(e_bt))

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
                    return (
                        cursor  # Return cursor for fetching results (caller must close)
                    )

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
                    print(
                        "[DB] Database locked, retrying {}/{}...".format(
                            attempt, retries
                        )
                    )
                    time.sleep(0.5 * attempt)  # Exponential backoff
                else:
                    print("[DB] Error executing query: " + error_msg)
                    # traceback.print_exc()
                    return None
            finally:
                if commit and cursor:
                    try:
                        cursor.close()
                    except:
                        pass
                if commit and conn:
                    try:
                        conn.close()
                    except:
                        pass

        print("[DB] Failed to execute query after {} retries.".format(retries))
        return None

    def fetch_all(self, query, params=None, retries=5):
        """
        Execute a SELECT query and return rows.
        Returns:
            list: 查询成功（可能为空列表 []）
            None: 查询失败（连接失败、异常、SQLITE_BUSY 重试耗尽）
        调用方应区分 None 与 []：None 不要清空表格；[] 才正常清空。
        """
        # Log query for debugging
        print(
            "[DB] Executing query: "
            + query[:200]
            + ("..." if len(query) > 200 else "")
        )
        if params:
            print("[DB] Query params: " + str(params))

        # Fix for zxJDBC BLOB handling: Replace BLOB columns with CAST to TEXT
        # 这步预处理只需做一次，重试时复用同一个 query
        if USE_ZXJDBC:
            import re as _re

            # List of known BLOB columns that need CAST conversion (only actual BLOB types)
            # headers and response_headers are TEXT, not BLOB
            blob_columns = [
                "response_body",  # Check longer names first to avoid partial matches
                "response_data",
                "request_data",
                "body",
            ]

            for col in blob_columns:
                # Skip if already has CAST for this column
                if "CAST(" + col in query or "CAST(r." + col in query:
                    continue

                # Pattern to match column with optional table prefix (e.g., "r.body" or "body")
                pattern = r"(?<!\w)(\w+\.)?(" + _re.escape(col) + r")\b"

                def replace_func(match):
                    prefix = match.group(1) if match.group(1) else ""
                    col_name = match.group(2)
                    return "CAST(" + prefix + col_name + " AS TEXT) as " + col_name

                # Only replace in SELECT clause (before FROM)
                if " FROM " in query.upper():
                    parts = _re.split(
                        r"\bFROM\b", query, maxsplit=1, flags=_re.IGNORECASE
                    )
                    if len(parts) == 2:
                        parts[0] = _re.sub(pattern, replace_func, parts[0])
                        query = parts[0] + " FROM " + parts[1]
                    else:
                        query = _re.sub(pattern, replace_func, query)
                else:
                    query = _re.sub(pattern, replace_func, query)

        attempt = 0
        while attempt < retries:
            conn = None
            cursor = None
            try:
                conn = self.get_connection()
                if not conn:
                    print("[DB] Failed to get connection")
                    return None  # 连接失败：返回 None，不再伪装成 []
                cursor = conn.cursor()

                # zxJDBC specific execution
                if USE_ZXJDBC:
                    if params:
                        cursor.execute(query, params)
                    else:
                        cursor.execute(query)

                    # Some zxJDBC drivers (like sqlite-jdbc wrapper) might fail on fetchall
                    try:
                        results = cursor.fetchall()
                        print(
                            "[DB] fetchall() returned {} rows".format(
                                len(results) if results else 0
                            )
                        )
                        return results if results else []
                    except Exception as e_fetchall:
                        # "not implemented" 等错误走兜底 BLOB CAST 重试
                        error_str_fetchall = str(e_fetchall).lower()
                        if (
                            "not implemented" not in error_str_fetchall
                            and "java" not in error_str_fetchall
                        ):
                            # 真正的查询异常，交给外层 except 处理
                            raise
                        print(
                            "[DB] fetchall() failed: "
                            + str(e_fetchall)
                            + ", trying iteration..."
                        )
                        # Fallback iteration
                        results = []
                        try:
                            row_count = 0
                            while True:
                                row = cursor.fetchone()
                                if row is None:
                                    break
                                results.append(row)
                                row_count += 1
                            print("[DB] Iteration fetched {} rows".format(row_count))
                            return results
                        except Exception as e_iter:
                            print("[DB] Iteration also failed: " + str(e_iter))
                            # Last resort: try for loop
                            try:
                                for row in cursor:
                                    results.append(row)
                                print(
                                    "[DB] For-loop fetched {} rows".format(
                                        len(results)
                                    )
                                )
                                return results
                            except Exception as e_for:
                                print("[DB] For-loop also failed: " + str(e_for))
                                return results  # 返回已拿到的部分
                else:
                    # Standard sqlite3
                    if params:
                        cursor.execute(query, params)
                    else:
                        cursor.execute(query)
                    results = cursor.fetchall()
                    print(
                        "[DB] Standard sqlite3 returned {} rows".format(
                            len(results) if results else 0
                        )
                    )
                    return results if results else []

            except Exception as e:
                error_msg = str(e)
                error_str = error_msg.lower()
                print("[DB] Exception in fetch_all: " + error_msg)
                print("[DB] Exception type: " + str(type(e)))

                # SQLITE_BUSY / database is locked：关连接重试（finally 会负责 close）
                if (
                    "database is locked" in error_str
                    or "SQLITE_BUSY" in error_str
                ):
                    attempt += 1
                    print(
                        "[DB] fetch_all locked, retrying {}/{}...".format(
                            attempt, retries
                        )
                    )
                    try:
                        time.sleep(0.5 * attempt)
                    except Exception:
                        pass
                    continue

                # zxJDBC "not implemented" 等错误：兜底 BLOB CAST 重试（保留原逻辑）
                if "not implemented" in error_str or "java" in error_str:
                    fallback_result = self._fetch_all_blob_fallback(
                        conn, query, params
                    )
                    if fallback_result is not None:
                        return fallback_result
                    # 兜底失败：返回 None，不再伪装成 []
                    print("[DB] fetch_all BLOB fallback failed, returning None")
                    import traceback

                    traceback.print_exc()
                    return None

                # 非锁、非 BLOB 异常：返回 None
                print("[DB] Error fetching data: " + error_msg)
                import traceback

                traceback.print_exc()
                return None
            finally:
                if cursor:
                    try:
                        cursor.close()
                    except:
                        pass
                if conn:
                    try:
                        conn.close()
                    except:
                        pass

        print("[DB] fetch_all failed after {} retries.".format(retries))
        return None

    def _fetch_all_blob_fallback(self, conn, query, params=None):
        """
        兜底重试：把更多 BLOB 列（含 executed_request_data）转成 CAST(... AS TEXT) 再查一次。
        返回：
            list: 兜底成功（可能为 []）
            None: 兜底失败
        """
        if not conn:
            return None
        try:
            if not USE_ZXJDBC:
                return None

            import re

            retry_query = query
            blob_columns = [
                "executed_request_data",
                "request_data",
                "response_data",
                "response_body",
                "request_data",
                "body",
            ]

            for col in blob_columns:
                if "CAST(" + col in retry_query or "CAST(r." + col in retry_query:
                    continue

                pattern = r"(?<!\w)(\w+\.)?(" + re.escape(col) + r")\b"

                def replace_func(match):
                    prefix = match.group(1) if match.group(1) else ""
                    col_name = match.group(2)
                    return "CAST(" + prefix + col_name + " AS TEXT) as " + col_name

                if " FROM " in retry_query.upper():
                    parts = re.split(
                        r"\bFROM\b", retry_query, maxsplit=1, flags=re.IGNORECASE
                    )
                    if len(parts) == 2:
                        parts[0] = re.sub(pattern, replace_func, parts[0])
                        retry_query = parts[0] + " FROM " + parts[1]
                    else:
                        retry_query = re.sub(pattern, replace_func, retry_query)
                else:
                    retry_query = re.sub(pattern, replace_func, retry_query)

            print("[DB] Retrying with CAST conversion...")
            cursor2 = conn.cursor()
            try:
                if params:
                    cursor2.execute(retry_query, params)
                else:
                    cursor2.execute(retry_query)
                results = []
                while True:
                    row = cursor2.fetchone()
                    if row is None:
                        break
                    results.append(row)
                print("[DB] Retry fetched {} rows".format(len(results)))
                return results
            finally:
                try:
                    cursor2.close()
                except:
                    pass
        except Exception as e2:
            print("[DB] Error fetching data (fallback): " + str(e2))
            import traceback

            traceback.print_exc()
            return None

    def init_db(self):
        # Using direct execution for init to keep it simple, or migrate to execute_query
        try:
            conn = self.get_connection()
            if conn:
                cursor = conn.cursor()

                # Enable WAL mode for better concurrency —— 不再静默吞错
                try:
                    cursor.execute("PRAGMA journal_mode=WAL;")
                    try:
                        wal_result = cursor.fetchone()
                    except Exception:
                        wal_result = None
                    print("[DB] PRAGMA journal_mode=WAL => " + str(wal_result))
                except Exception as e:
                    print("[DB] WARN: failed to set WAL: " + str(e))
                # busy_timeout: 遇到锁时等待 5000ms 再报错，而非立即失败
                try:
                    cursor.execute("PRAGMA busy_timeout=5000;")
                    print("[DB] PRAGMA busy_timeout=5000 set on init connection")
                except Exception as e:
                    print("[DB] WARN: failed to set busy_timeout on init: " + str(e))

                # 1. raw_requests table
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS raw_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, method TEXT, host TEXT, url TEXT, path TEXT, headers TEXT, query_params TEXT, body BLOB, user_identifier TEXT, is_analyzed BOOLEAN DEFAULT 0, analyzed_at DATETIME, response_headers TEXT, response_body BLOB)"
                )

                # Check if analyzed_at column exists (for upgrade)
                try:
                    cursor.execute("SELECT analyzed_at FROM raw_requests LIMIT 1")
                except:
                    # Column likely missing, add it
                    try:
                        cursor.execute(
                            "ALTER TABLE raw_requests ADD COLUMN analyzed_at DATETIME"
                        )
                        conn.commit()
                        print("Added analyzed_at column to raw_requests")
                    except Exception as e:
                        print("Failed to add analyzed_at column: " + str(e))

                # Check if response_headers/response_body columns exist (for upgrade)
                try:
                    cursor.execute(
                        "SELECT response_headers, response_body FROM raw_requests LIMIT 1"
                    )
                except:
                    try:
                        cursor.execute(
                            "ALTER TABLE raw_requests ADD COLUMN response_headers TEXT"
                        )
                    except:
                        pass
                    try:
                        cursor.execute(
                            "ALTER TABLE raw_requests ADD COLUMN response_body BLOB"
                        )
                    except:
                        pass
                    conn.commit()
                    print("Added response columns to raw_requests")

                # 2. parameter_pool table
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS parameter_pool (id INTEGER PRIMARY KEY AUTOINCREMENT, api_signature TEXT, param_name TEXT, param_value TEXT, location TEXT, user_identifier TEXT, risk_score INTEGER DEFAULT 0, llm_analysis_result TEXT, UNIQUE(api_signature, param_name, user_identifier))"
                )

                # Check if risk_score column exists (for upgrade)
                try:
                    cursor.execute("SELECT risk_score FROM parameter_pool LIMIT 1")
                except:
                    # Column likely missing, add it
                    try:
                        cursor.execute(
                            "ALTER TABLE parameter_pool ADD COLUMN risk_score INTEGER DEFAULT 0"
                        )
                        cursor.execute(
                            "ALTER TABLE parameter_pool ADD COLUMN llm_analysis_result TEXT"
                        )
                        conn.commit()
                        print(
                            "Added risk_score and llm_analysis_result columns to parameter_pool"
                        )
                    except Exception as e:
                        print("Failed to add columns to parameter_pool: " + str(e))

                # 3. attack_queue table (Renamed from burp_generated_requests for clarity in requirements)
                # But let's stick to 'burp_generated_requests' or 'attack_queue'?
                # The requirements said 'attack_queue'. Let's use that.
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS attack_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, original_request_id INTEGER, target_user TEXT, payload_description TEXT, request_data BLOB, status TEXT DEFAULT 'PENDING', response_data BLOB, response_code INTEGER, vulnerability_score INTEGER, llm_verification_result TEXT, verified BOOLEAN DEFAULT 0, executed_request_data BLOB, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(original_request_id) REFERENCES raw_requests(id))"
                )

                # Check for new columns in attack_queue
                try:
                    cursor.execute(
                        "SELECT response_data, response_code, llm_verification_result, verified, executed_request_data FROM attack_queue LIMIT 1"
                    )
                except:
                    # Columns might be missing
                    try:
                        cursor.execute(
                            "ALTER TABLE attack_queue ADD COLUMN response_data BLOB"
                        )
                    except:
                        pass
                    try:
                        cursor.execute(
                            "ALTER TABLE attack_queue ADD COLUMN response_code INTEGER"
                        )
                    except:
                        pass
                    try:
                        cursor.execute(
                            "ALTER TABLE attack_queue ADD COLUMN llm_verification_result TEXT"
                        )
                    except:
                        pass
                    try:
                        cursor.execute(
                            "ALTER TABLE attack_queue ADD COLUMN verified BOOLEAN DEFAULT 0"
                        )
                    except:
                        pass
                    try:
                        cursor.execute(
                            "ALTER TABLE attack_queue ADD COLUMN executed_request_data BLOB"
                        )
                    except:
                        pass
                    conn.commit()
                    print("Added new columns to attack_queue")

                # 4. api_metadata table (For LLM risk analysis)
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS api_metadata (api_signature TEXT PRIMARY KEY, is_sensitive BOOLEAN, risk_reason TEXT, analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
                )

                conn.commit()
                print("Database initialized successfully at " + self.db_path)

                cursor.close()
                conn.close()
        except Exception as e:
            print("Error initializing database: " + str(e))
            traceback.print_exc()

    def save_raw_request(
        self,
        method,
        host,
        url,
        path,
        headers,
        query_params,
        body,
        user_identifier,
        response_headers=None,
        response_body=None,
    ):
        # Prepare params
        headers_json = json.dumps(headers)
        query_json = json.dumps(query_params)

        sql = "INSERT INTO raw_requests (method, host, url, path, headers, query_params, body, user_identifier, response_headers, response_body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        params = [
            method,
            host,
            url,
            path,
            headers_json,
            query_json,
            body,
            user_identifier,
            response_headers,
            response_body,
        ]

        return self.execute_query(sql, params)

    def clear_all_data(self):
        try:
            conn = self.get_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM attack_queue")
                cursor.execute("DELETE FROM parameter_pool")
                cursor.execute("DELETE FROM raw_requests")
                cursor.execute("DELETE FROM api_metadata")
                cursor.execute(
                    "DELETE FROM sqlite_sequence"
                )  # Reset auto-increment counters
                conn.commit()
                print("All database data cleared successfully.")
                cursor.close()
                conn.close()
                return True
        except Exception as e:
            print("Error clearing database: " + str(e))
            traceback.print_exc()
            return False
