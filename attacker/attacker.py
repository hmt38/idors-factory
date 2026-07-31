#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from authorization.authorization import apply_user_rules_to_request_components
import time

from helpers.llm_helper import LLMHelper


class AttackEngine:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.llm_helper = None

    def _get_blacklist_params(self):
        # 通过 ConfigManager 读取黑名单 (解耦 GUI)
        try:
            from api.config_manager import ConfigManager
            cm = ConfigManager()
            return cm.get_blacklist_set()
        except Exception:
            return set()

    def _is_blacklisted(self, param_name):
        return param_name in self._get_blacklist_params()

    def _init_llm(self):
        # 通过 ConfigManager 读取 LLM 配置 (解耦 GUI)
        try:
            from api.config_manager import ConfigManager
            cm = ConfigManager()
            config = cm.get_llm_config()
            if config["enabled"]:
                self.llm_helper = LLMHelper(
                    config["base_url"],
                    config["api_key"],
                    config["model"],
                    verify_ssl=config["verify_ssl"],
                )
            else:
                self.llm_helper = None
        except Exception:
            self.llm_helper = None

    def _set_progress_message(self, message, indeterminate=None):
        try:
            extender = getattr(self.db_manager, "extender", None)
            progress_bar = getattr(extender, "progressBar", None) if extender else None
            if not progress_bar:
                return
            from javax.swing import SwingUtilities

            def update():
                if indeterminate is not None:
                    progress_bar.setIndeterminate(indeterminate)
                progress_bar.setString(message)
                progress_bar.setStringPainted(True)

            SwingUtilities.invokeLater(update)
        except Exception:
            pass

    def _get_parameter_pool_user_count(self):
        try:
            rows = self.db_manager.fetch_all(
                "SELECT COUNT(DISTINCT user_identifier) FROM parameter_pool WHERE user_identifier IS NOT NULL AND user_identifier != ''"
            )
            if rows:
                return int(rows[0][0] or 0)
        except Exception as e:
            print("[Attacker] Error checking parameter pool users: " + str(e))
        return 0

    def generate_attacks(self, hidden_param_config=None):
        self._init_llm()
        """
        Scan for requests from User A (or any user) that haven't been attacked yet,
        find matching parameters from other users (User B), and generate attack payloads.
        """
        print("[Attacker] Starting attack generation scan...")

        parameter_pool_user_count = self._get_parameter_pool_user_count()
        one_user_pool_warning = "参数池只识别到一个用户，请检查是否填错了cookie导致没有识别到用户，或者是没有抓到另一个用户的流量？"

        # 0. Global Analysis: Update risk scores based on parameter exclusivity
        try:
            self._update_risk_scores_based_on_exclusivity()
        except Exception as e:
            print("[Attacker] Error in global analysis: " + str(e))

        # 1. Find potential target requests
        # We look for requests that are analyzed but not yet in attack_queue (as original_request_id)
        # To avoid complex joins, we can select requests and check if they have attacks.
        # Or simpler: add 'attack_generated' flag to raw_requests?
        # Let's use a simple query: select requests where user_identifier is NOT NULL
        # For MVP, let's just pick recent analyzed requests.
        # TODO: Add 'attack_generated' column to raw_requests for state tracking.

        # For now, let's fetch analyzed requests from the last hour?
        # Or just fetch all analyzed requests and check if they are already in attack_queue

        # Better approach:
        # SELECT r.id, r.method, r.host, r.url, r.path, r.headers, r.query_params, r.body, r.user_identifier
        # FROM raw_requests r
        # WHERE r.is_analyzed = 1
        # AND r.id NOT IN (SELECT original_request_id FROM attack_queue)
        # LIMIT 50

        sql = """
        SELECT r.id, r.method, r.host, r.url, r.path, r.headers, r.query_params, r.body, r.user_identifier 
        FROM raw_requests r 
        WHERE r.is_analyzed = 1 
        AND r.id NOT IN (SELECT original_request_id FROM attack_queue)
        LIMIT 200
        """

        requests = self.db_manager.fetch_all(sql)

        if not requests:
            print("[Attacker] No new requests to generate attacks for.")
            if parameter_pool_user_count == 1:
                self._set_progress_message(one_user_pool_warning, False)
            return 0

        print("[Attacker] Processing {} potential requests...".format(len(requests)))

        # Access progress bar if available
        extender = getattr(self.db_manager, "extender", None)
        progressBar = getattr(extender, "progressBar", None)
        from javax.swing import SwingUtilities

        count = 0
        total = len(requests)
        created_count = 0

        for req in requests:
            count += 1
            req_id = req[0]

            # Update progress
            if progressBar:

                def update_progress(c=count, t=total, rid=req_id):
                    progressBar.setString(
                        "Processing {}/{} (Req ID {})...".format(c, t, rid)
                    )

                SwingUtilities.invokeLater(update_progress)

            try:
                created_count += self._process_request(req, hidden_param_config)
            except Exception as e:
                print(
                    "[Attacker] Error processing request {}: {}".format(req_id, str(e))
                )
                import traceback

                traceback.print_exc()

            # print("[Attacker] Finished processing Request ID: " + str(req_id))

        if created_count == 0 and parameter_pool_user_count == 1:
            self._set_progress_message(one_user_pool_warning, False)
        print("[Attacker] Attack generation scan complete. Created {} attack queue records.".format(created_count))
        return created_count

    def _update_risk_scores_based_on_exclusivity(self):
        """
        Identify parameters that are present for some users but missing for others on the same API.
        If a parameter is 'exclusive' (not present for all users), increase its risk score.
        """
        print("[Attacker] Analyzing parameter exclusivity...")

        # 1. Get all API signatures and their total user count
        # We assume if a user has ANY parameter for an API, they accessed it.
        # This is an approximation. Ideally we check raw_requests, but parameter_pool is faster.
        sql_api_users = """
        SELECT api_signature, COUNT(DISTINCT user_identifier) as total_users
        FROM parameter_pool
        GROUP BY api_signature
        HAVING total_users > 1
        """
        api_rows = self.db_manager.fetch_all(sql_api_users)
        if api_rows is None:
            # 查询失败：跳过本次 exclusivity 更新，不影响主流程
            print("[Attacker] fetch api_users failed, skip exclusivity update")
            return

        for api_row in api_rows:
            api_signature, total_users = api_row

            # 2. For this API, check each parameter's user count
            sql_param_users = """
            SELECT param_name, COUNT(DISTINCT user_identifier) as param_users
            FROM parameter_pool
            WHERE api_signature = '{}'
            GROUP BY param_name
            """.format(api_signature.replace("'", "''"))
            param_rows = self.db_manager.fetch_all(sql_param_users)
            if param_rows is None:
                # 该 API 的参数查询失败：跳过这个 API，继续下一个
                print("[Attacker] fetch param_users failed for " + api_signature + ", skip")
                continue

            for param_row in param_rows:
                param_name, param_users = param_row

                # If parameter is NOT present for all users who accessed this API
                if param_users < total_users:
                    # Filter out common optional parameters
                    if param_name.lower() in [
                        "page",
                        "limit",
                        "size",
                        "sort",
                        "order",
                        "lang",
                        "locale",
                        "callback",
                        "_",
                        "t",
                    ]:
                        continue

                    # This is an "Exclusive" parameter. Boost its score.
                    print(
                        "[Attacker] Found exclusive parameter: {} in {} (Users: {}/{})".format(
                            param_name, api_signature, param_users, total_users
                        )
                    )

                    # Update risk score: Add 20 points (cap at 100)
                    # We only update if it hasn't been boosted yet?
                    # Or we just set a flag?
                    # Let's just update risk_score directly, ensuring we don't double count excessively.
                    # Maybe check if it's already high?
                    # Simple heuristic: specific update query
                    # Use execute_query to update
                    update_sql = """
                    UPDATE parameter_pool 
                    SET risk_score = MIN(risk_score + 20, 100)
                    WHERE api_signature = '{}' AND param_name = '{}'
                    """.format(
                        api_signature.replace("'", "''"), param_name.replace("'", "''")
                    )
                    self.db_manager.execute_query(update_sql)

    def _process_request(self, req, hidden_param_config=None):
        (
            req_id,
            method,
            host,
            url,
            path,
            headers_json,
            query_params_json,
            body,
            user_identifier,
        ) = req

        print(
            "[Attacker] Analyzing Request ID: {} ({} {}) User: {}".format(
                req_id, method, path, user_identifier
            )
        )

        # 1. Identify API Signature
        api_signature = self._generate_api_signature(method, host, path)
        try:
            if self.db_manager.extender:
                api_signature = self.db_manager.extender.extractor._get_api_signature(
                    method, path
                )
        except:
            pass

        # Identify API Risk (if enabled)
        try:
            from api.config_manager import ConfigManager
            cm = ConfigManager()
            if (
                self.llm_helper
                and cm.get_bool("llm_identify_risk", True)
            ):
                print("[Attacker] Calling LLM Identify Risk for " + api_signature)
                self._identify_api_risk(api_signature, req)
                print("[Attacker] LLM Identify Risk finished for " + api_signature)
        except Exception as e_llm:
            print("[Attacker] Error in API Risk ID: " + str(e_llm))

        # 2. Extract parameters from current request
        current_params = self._extract_params_from_request(
            path, query_params_json, body, headers_json, user_identifier
        )

        if not current_params:
            return 0

        # Filter parameters based on risk score threshold
        # We need to fetch risk scores for these parameters
        target_params = []  # List of dicts: {name, value, location, risk_score}

        for name, value, location in current_params:
            if self._is_blacklisted(name):
                continue

            # Query risk score from pool (assuming we have it stored)
            # If not found, default to 0.
            sql = "SELECT risk_score FROM parameter_pool WHERE api_signature = '{}' AND param_name = '{}' AND user_identifier = '{}' AND location = '{}'".format(
                api_signature.replace("'", "''"),
                name.replace("'", "''"),
                user_identifier.replace("'", "''"),
                location.replace("'", "''"),
            )
            rows = self.db_manager.fetch_all(sql)
            score = 0
            if rows:
                score = rows[0][0]

            # Threshold Check (Default 0, but user suggested filtering low risk if needed)
            # Let's keep it 0 for now to be inclusive, or maybe 10 to skip complete junk?
            # User said "Threshold (default 0)". So we include everything > 0? Or >= 0?
            # Let's say >= 0.
            if score >= 0:
                target_params.append(
                    {
                        "name": name,
                        "value": value,
                        "location": location,
                        "risk_score": score,
                    }
                )

        if not target_params:
            return 0

        # 3. Find other users who have accessed this API
        # We need to find ONE other user to impersonate (or swap params with).
        # Ideally, we find a user who has values for ALL the target_params.
        # But maybe they only have values for some.

        sql_users = "SELECT DISTINCT user_identifier FROM parameter_pool WHERE api_signature = '{}' AND user_identifier != '{}'".format(
            api_signature.replace("'", "''"), user_identifier.replace("'", "''")
        )
        try:
            other_users = self.db_manager.fetch_all(sql_users)
        except Exception as e_db:
            print("[Attacker] Error fetching other users: " + str(e_db))
            return 0

        if not other_users:
            # Fallback: if user_identifier is "User 1", try finding "User 2" specifically even if API sig doesn't match perfectly?
            # Or maybe api_signature is too strict?
            # Try finding ANY other user in the system to see if we have cross-user data at all.
            # But for now, just log.
            # print("[Attacker] No other users found for API: " + api_signature)
            return 0

        created_count = 0
        for user_row in other_users:
            other_user = user_row[0]
            print(
                "[Attacker] Generating permutations for Target User: " + str(other_user)
            )

            # Fetch all params for this other user on this API
            sql_other_params = "SELECT param_name, param_value, location FROM parameter_pool WHERE api_signature = '{}' AND user_identifier = '{}'".format(
                api_signature.replace("'", "''"), other_user.replace("'", "''")
            )
            other_param_rows = []
            try:
                fetched = self.db_manager.fetch_all(sql_other_params)
                if fetched is not None:
                    other_param_rows = fetched
                else:
                    # 查询失败：当作 0 行处理，跳过这个用户
                    print("[Attacker] fetch other_user params failed for " + str(other_user) + ", skip")
                    continue
            except Exception as e_p:
                print("[Attacker] Error fetching other user params: " + str(e_p))
                continue

            # Convert to dictionary for easy lookup
            other_params_map = {
                self._param_lookup_key(row[0], row[2]): row[1]
                for row in other_param_rows
                if not self._is_blacklisted(row[0])
            }

            # Identify which parameters can be swapped
            swappable_params = []
            for tp in target_params:
                p_name = tp["name"]
                p_val = tp["value"]
                lookup_key = self._param_lookup_key(p_name, tp["location"])
                if lookup_key in other_params_map:
                    other_val = other_params_map[lookup_key]
                    # Log comparison
                    # print("[Attacker] Comparing param {}: My val={}, Other val={}".format(p_name, p_val, other_val))
                    if str(other_val) != str(p_val):
                        # Found a difference!
                        swappable_params.append(
                            {
                                "name": p_name,
                                "current_value": p_val,
                                "new_value": other_val,
                                "location": tp["location"],
                                "risk_score": tp["risk_score"],
                            }
                        )

            if not swappable_params:
                # print("[Attacker] No swappable params found for User: " + str(other_user))
                continue

            print(
                "[Attacker] Found {} swappable params for User {}".format(
                    len(swappable_params), other_user
                )
            )
            # We need to generate combinations:
            # - Single parameter replacement (for each swappable param)
            # - All parameters replacement
            # - (Optional) Subsets? For now, let's do Single + All.
            # User asked for: "Generate 4 packets: Only ID, Only Account, Both ID and Account"
            # This implies All Subsets (Power Set) logic.

            import itertools

            # If we have too many swappable params, power set is 2^N.
            # Limit N? User said "prune reasonable".
            # If N > 5, maybe just do Single + All?
            # Let's try full combinations if N <= 4. If N > 4, do Single + All.

            combinations = []
            n_swappable = len(swappable_params)

            if n_swappable <= 4:
                # Generate all non-empty combinations
                for r in range(1, n_swappable + 1):
                    combinations.extend(itertools.combinations(swappable_params, r))
            else:
                # Generate Single replacements
                for p in swappable_params:
                    combinations.append([p])
                # Generate All replacements
                combinations.append(swappable_params)

            for combo in combinations:
                if self._create_attack_entry_for_combination(req, combo, other_user, hidden_param_config):
                    created_count += 1

        return created_count

    def _create_attack_entry_for_combination(self, req, combination, target_user, hidden_param_config=None):
        (
            req_id,
            method,
            host,
            url,
            path,
            headers_json,
            query_params_json,
            body,
            user_identifier,
        ) = req

        # combination is a tuple/list of param dicts to swap

        # Calculate combined risk score (max? sum? average?)
        # Let's use Max score of involved params.
        risk_score = max([p["risk_score"] for p in combination])

        # Description
        changes = []
        for p in combination:
            changes.append(
                "{}={}->{}".format(p["name"], p["current_value"], p["new_value"])
            )
        description = "Swap params ({}): {}".format(
            len(combination), ", ".join(changes)
        )

        # Perform replacements
        new_path = path

        # Handle Query Params
        new_query_str = query_params_json
        q_dict = {}
        if query_params_json:
            try:
                q_dict = json.loads(query_params_json)
            except:
                pass

        # Handle Body
        new_body_str = body
        b_dict = {}
        if body and body.strip().startswith("{"):
            try:
                b_dict = json.loads(body)
            except:
                pass

        try:
            new_headers = json.loads(headers_json)
        except Exception:
            new_headers = []

        # Apply swaps
        for p in combination:
            name = p["name"]
            val = p["new_value"]
            loc = p["location"]

            if loc == "PATH":
                # Path replacement - support both old (path_seg_N) and new (semantic) naming
                try:
                    # Try old naming format first: path_seg_N
                    if name.startswith("path_seg_"):
                        seg_index = int(name.split("_")[-1])
                        parts = new_path.split("/")
                        if seg_index < len(parts):
                            parts[seg_index] = val
                            new_path = "/".join(parts)
                    else:
                        # New semantic naming: find and replace the current value in path
                        # We need to match the parameter by its current value
                        current_val = p["current_value"]
                        parts = new_path.split("/")
                        for i, part in enumerate(parts):
                            if part == current_val:
                                parts[i] = val
                                break
                        new_path = "/".join(parts)
                except Exception as e:
                    print(
                        "[Attacker] Error replacing PATH param {}: {}".format(
                            name, str(e)
                        )
                    )

            elif loc == "QUERY":
                q_dict[name] = val

            elif loc == "BODY_JSON":
                self._update_json_value(b_dict, name, val)

            elif loc == "HEADER":
                new_headers = self._upsert_header(new_headers, name, val)

        # Serialize back
        if q_dict:
            new_query_str = json.dumps(q_dict)

        if b_dict:
            new_body_str = json.dumps(b_dict)

        hidden_param_applied = False
        hidden_param_entry = self._build_hidden_param_entry(hidden_param_config, target_user)
        if hidden_param_entry:
            request_data_preview = {
                "method": method,
                "host": host,
                "path": new_path,
                "headers": new_headers,
                "query_params": json.loads(new_query_str) if new_query_str else {},
                "body": new_body_str,
            }
            request_data_preview = self._apply_hidden_param_to_request_data(
                request_data_preview, hidden_param_entry
            )
            new_path = request_data_preview["path"]
            new_body_str = request_data_preview["body"]
            hidden_headers = request_data_preview.get("headers", new_headers)
            hidden_query_params = request_data_preview.get("query_params", {})
            hidden_param_applied = True
        else:
            hidden_headers = new_headers
            hidden_query_params = json.loads(new_query_str) if new_query_str else {}

        # Create Request Data
        request_data = {
            "method": method,
            "host": host,
            "path": new_path,
            "headers": hidden_headers,
            "query_params": hidden_query_params,
            "body": new_body_str,
        }

        if hidden_param_entry:
            request_data["hidden_param"] = hidden_param_entry

        if hidden_param_applied:
            description += " | Hidden param: {}={}".format(
                hidden_param_entry["key"], hidden_param_entry["value"]
            )

        request_data_json_str = json.dumps(request_data).replace("'", "''")
        description_str = description.replace("'", "''")

        sql = """
        INSERT INTO attack_queue 
        (original_request_id, target_user, payload_description, request_data, status, vulnerability_score)
        VALUES ({}, '{}', '{}', '{}', 'PENDING', {})
        """.format(
            req_id, target_user, description_str, request_data_json_str, risk_score
        )

        try:
            self.db_manager.execute_query(sql)
            print("[Attacker] Queued attack: " + description)
            return True
        except Exception as e_ins:
            print("[Attacker] Error inserting attack: " + str(e_ins))
            return False

    def _update_json_value(self, json_obj, key_path, new_value):
        # key_path is like "user.profile.id" or "items.0.id"
        keys = key_path.split(".")
        current = json_obj
        for i, key in enumerate(keys[:-1]):
            if isinstance(current, list):
                try:
                    idx = int(key)
                    current = current[idx]
                except:
                    return
            else:
                current = current.get(key, {})

        last_key = keys[-1]
        if isinstance(current, list):
            try:
                idx = int(last_key)
                current[idx] = new_value
            except:
                pass
        elif isinstance(current, dict):
            current[last_key] = new_value

    def _get_user_rule_context(self, target_user):
        extender = getattr(self.db_manager, "extender", None)
        if not extender or not hasattr(extender, "userTab") or not extender.userTab:
            return None, ""

        for user_id, user_data in extender.userTab.user_tabs.items():
            user_name = user_data.get("user_name")
            if str(user_name).strip().lower() == str(target_user).strip().lower():
                mr_instance = user_data.get("mr_instance")
                headers_instance = user_data.get("headers_instance")
                user_headers_text = ""
                try:
                    if headers_instance and hasattr(headers_instance, "replaceString"):
                        user_headers_text = headers_instance.replaceString.getText()
                except Exception:
                    user_headers_text = ""
                return mr_instance, user_headers_text

        return None, ""

    def _apply_user_context_rules_to_request_data(self, request_data, target_user, helpers):
        if not request_data:
            return request_data

        mr_instance, user_headers_text = self._get_user_rule_context(target_user)
        if mr_instance is None and not user_headers_text:
            return request_data

        headers = list(request_data.get("headers") or [])
        if not headers:
            return request_data

        body = request_data.get("body")
        if body is None:
            body_text = ""
        elif isinstance(body, unicode):
            body_text = body
        else:
            try:
                body_text = helpers.bytesToString(body)
            except Exception:
                body_text = str(body)

        request_line, header_lines, body_text = apply_user_rules_to_request_components(
            self.db_manager.extender,
            headers[0],
            headers[1:],
            body_text,
            mr_instance,
            user_headers_text,
            True,
        )

        request_data["headers"] = [request_line] + header_lines
        request_data["body"] = body_text

        uri = request_line.split(" ")[1] if " " in request_line else request_data.get("path", "")
        if "?" in uri:
            path_part, query_string = uri.split("?", 1)
        else:
            path_part, query_string = uri, ""

        request_data["path"] = path_part
        query_params = {}
        if query_string:
            for pair in query_string.split("&"):
                if pair == "":
                    continue
                if "=" in pair:
                    key, value = pair.split("=", 1)
                else:
                    key, value = pair, ""
                query_params[key] = value
        request_data["query_params"] = query_params
        return request_data

    def _parse_hidden_header_entries(self, header_key_text, header_value_text):
        entries = []
        key_lines = [line.strip() for line in str(header_key_text or "").splitlines()]
        value_lines = [line.strip() for line in str(header_value_text or "").splitlines()]

        normalized_keys = [line for line in key_lines if line]
        normalized_values = [line for line in value_lines if line != ""]

        if len(normalized_keys) > 1:
            for idx, key in enumerate(normalized_keys):
                value = normalized_values[idx] if idx < len(normalized_values) else ""
                if key:
                    entries.append((key, value))
            return entries

        single_key = normalized_keys[0] if normalized_keys else str(header_key_text or "").strip()
        if not single_key:
            return entries

        raw_values = str(header_value_text or "")
        value_candidates = [line.strip() for line in raw_values.splitlines() if line.strip()]
        if not value_candidates:
            entries.append((single_key, ""))
            return entries

        for line in value_candidates:
            if ":" in line:
                name, value = line.split(":", 1)
                name = name.strip()
                if name:
                    entries.append((name, value.strip()))
            else:
                entries.append((single_key, line))

        return entries

    def _upsert_header(self, headers, header_name, header_value):
        if not headers:
            headers = []
        if not header_name:
            return headers

        updated = []
        replaced = False
        target_name = header_name.strip().lower()

        for i, line in enumerate(headers):
            if i == 0:
                updated.append(line)
                continue
            if ":" in line:
                current_name = line.split(":", 1)[0].strip().lower()
                if current_name == target_name:
                    if not replaced:
                        updated.append("{}: {}".format(header_name, header_value))
                        replaced = True
                    continue
            updated.append(line)

        if not replaced:
            if updated:
                updated.append("{}: {}".format(header_name, header_value))
            else:
                updated = ["{}: {}".format(header_name, header_value)]

        return updated

    def _build_hidden_param_entry(self, hidden_param_config, target_user=None):
        if not hidden_param_config:
            return None

        try:
            enabled = hidden_param_config.get("enabled", True)
            key = hidden_param_config.get("key", "").strip()
            if not enabled or not key:
                return None

            value = hidden_param_config.get("value")
            if target_user is not None:
                target_user_l = str(target_user).strip().lower()
                a_user = hidden_param_config.get("a_user", "")
                b_user = hidden_param_config.get("b_user", "")
                if b_user and target_user_l == str(b_user).strip().lower():
                    value = hidden_param_config.get("b_value")
                elif a_user and target_user_l == str(a_user).strip().lower():
                    value = hidden_param_config.get("a_value")
                elif hidden_param_config.get("b_value") and not hidden_param_config.get("a_value"):
                    value = hidden_param_config.get("b_value")
                elif hidden_param_config.get("a_value") is not None:
                    value = hidden_param_config.get("a_value")

            if value is None:
                value = ""

            location = hidden_param_config.get("location", "QUERY")
            header_entries = []
            if location == "HEADER":
                header_entries = self._parse_hidden_header_entries(key, value)
                if not header_entries:
                    return None

            return {
                "enabled": True,
                "key": key,
                "value": value,
                "location": location,
                "header_entries": header_entries,
                "a_value": hidden_param_config.get("a_value", ""),
                "b_value": hidden_param_config.get("b_value", ""),
            }
        except Exception:
            return None

    def _apply_hidden_param_to_request_data(self, request_data, hidden_param_entry):
        if not request_data or not hidden_param_entry:
            return request_data

        location = hidden_param_entry.get("location")

        if location == "QUERY":
            query_params = request_data.get("query_params") or {}
            if not isinstance(query_params, dict):
                query_params = {}

            query_params[hidden_param_entry["key"]] = hidden_param_entry.get("value", "")
            request_data["query_params"] = query_params
        elif location == "HEADER":
            headers = request_data.get("headers") or []
            header_entries = hidden_param_entry.get("header_entries") or [
                (hidden_param_entry["key"], hidden_param_entry.get("value", ""))
            ]
            for header_name, header_value in header_entries:
                headers = self._upsert_header(headers, header_name, header_value)
            request_data["headers"] = headers

        request_data["hidden_param"] = hidden_param_entry
        return request_data

    def _describe_hidden_param(self, hidden_param_entry):
        if not hidden_param_entry:
            return ""
        if hidden_param_entry.get("location") == "HEADER":
            entries = hidden_param_entry.get("header_entries") or []
            if entries:
                return ", ".join(
                    ["{}={}".format(name, value) for name, value in entries]
                )
        return "{}={}".format(
            hidden_param_entry.get("key", ""), hidden_param_entry.get("value", "")
        )

    def _param_lookup_key(self, name, location):
        # parameter_pool 的 location 字段可能被 LLM 提取覆盖为 "LLM_llm" 等，
        # 与 _extract_params_from_request 返回的 "QUERY"/"BODY_JSON"/"PATH" 不一致。
        # 由于 parameter_pool UNIQUE 键为 (api_signature, param_name, user_identifier)，
        # 每个参数名每用户只有一条记录，故仅用参数名做 key 即可正确匹配。
        return str(name).strip().lower()

    def _get_header_fuzz_key_map(self, user_identifier):
        key_map = {}
        extender = getattr(self.db_manager, "extender", None)
        user_tab = getattr(extender, "userTab", None) if extender else None
        if not user_tab:
            return key_map

        try:
            for key in user_tab.get_global_header_fuzz_keys():
                key = key.strip()
                if key:
                    key_map[key.lower()] = key
        except Exception:
            pass

        try:
            for user_id, user_data in user_tab.user_tabs.items():
                if str(user_data.get("user_name", "")).strip().lower() != str(user_identifier).strip().lower():
                    continue
                mr_instance = user_data.get("mr_instance")
                if not mr_instance:
                    break
                for i in range(mr_instance.MRModel.getSize()):
                    rule_key = mr_instance.MRModel.getElementAt(i)
                    rule_data = mr_instance.badProgrammerMRModel.get(rule_key)
                    if not rule_data:
                        rule_data = mr_instance.badProgrammerMRModel.get(str(rule_key))
                    if rule_data and rule_data.get("type") == "Header Add/Set:":
                        key = (rule_data.get("match") or "").strip()
                        if key:
                            key_map[key.lower()] = key
                break
        except Exception as e:
            print("[Attacker] Error reading header fuzz keys: " + str(e))

        return key_map

    def _extract_header_params_from_request(self, headers_json, user_identifier, params):
        key_map = self._get_header_fuzz_key_map(user_identifier)
        if not key_map or not headers_json:
            return

        try:
            headers = json.loads(headers_json)
        except Exception:
            return

        for line in headers:
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            header_name = name.strip()
            if not header_name:
                continue
            if header_name.lower() in key_map:
                params.append((header_name, value.strip(), "HEADER"))

    def _extract_params_from_request(self, path, query_params_json, body, headers_json=None, user_identifier=None):
        params = []  # (name, value, location)

        # Path - use the same semantic naming strategy as extractor
        parts = path.split("/")
        for i, part in enumerate(parts):
            param_type = None
            if self._is_numeric(part):
                param_type = "id"
            elif self._is_uuid(part):
                param_type = "uuid"
            else:
                hash_type = self._is_hash(part)
                if hash_type:
                    param_type = hash_type

            if param_type:
                param_name = self._generate_path_param_name(parts, i, param_type)
                params.append((param_name, part, "PATH"))

        # Query
        if query_params_json:
            try:
                q = json.loads(query_params_json)
                for k, v in q.items():
                    params.append((k, v, "QUERY"))
            except:
                pass

        # Body
        if body and body.strip().startswith("{"):
            try:
                b = json.loads(body)
                self._flatten_json(b, params)
            except:
                pass

        self._extract_header_params_from_request(headers_json, user_identifier, params)

        return params

    def _flatten_json(self, json_obj, params, prefix=""):
        if isinstance(json_obj, dict):
            for k, v in json_obj.items():
                self._flatten_json(v, params, prefix + k + ".")
        elif isinstance(json_obj, list):
            for i, item in enumerate(json_obj):
                self._flatten_json(item, params, prefix + str(i) + ".")
        else:
            params.append((prefix.rstrip("."), str(json_obj), "BODY_JSON"))

    def _identify_api_risk(self, api_signature, req_data):
        # req_data is tuple: (id, method, host, url, path, headers, query, body, user)
        # Check if already analyzed
        rows = self.db_manager.fetch_all(
            "SELECT 1 FROM api_metadata WHERE api_signature = '{}'".format(
                api_signature.replace("'", "''")
            )
        )
        if rows:
            return

        print("[Attacker] Analyzing API Risk for: " + api_signature)
        req_obj = {
            "method": req_data[1],
            "path": req_data[4],
            "query": req_data[6],
            "body": req_data[7],
        }

        try:
            result = self.llm_helper.identify_sensitive_api(req_obj)
            is_sensitive = 1 if result["is_sensitive"] else 0
            reason = result["reason"]

            self.db_manager.execute_query(
                "INSERT OR REPLACE INTO api_metadata (api_signature, is_sensitive, risk_reason) VALUES (?, ?, ?)",
                (api_signature, is_sensitive, reason),
            )
            print(
                "[Attacker] API Risk Analyzed: Sensitive={}, Reason={}".format(
                    is_sensitive, reason
                )
            )
        except Exception as e:
            print("[Attacker] Error identifying API risk: " + str(e))

    def _generate_path_param_name(self, parts, index, param_type):
        """
        Keep PATH parameter naming consistent with extractor._generate_param_name
        so parameter_pool lookup and cross-user matching work correctly.
        """
        prefix = "unknown"
        for j in range(index - 1, -1, -1):
            if parts[j] and not self._is_param_like(parts[j]):
                prefix = parts[j]
                break

        import re

        prefix = re.sub(r"[^a-zA-Z0-9_]", "_", prefix)
        prefix = prefix.strip("_").lower()
        if not prefix:
            prefix = "unknown"

        return "{}_id".format(prefix)

    def _is_param_like(self, s):
        if not s:
            return False
        return self._is_numeric(s) or self._is_uuid(s) or bool(self._is_hash(s))

    def _generate_api_signature(self, method, host, path):
        # Same heuristic as extractor
        parts = path.split("/")
        normalized_parts = []
        for part in parts:
            if self._is_numeric(part):
                normalized_parts.append("{id}")
            elif self._is_uuid(part):
                normalized_parts.append("{uuid}")
            else:
                hash_type = self._is_hash(part)
                if hash_type:
                    normalized_parts.append("{" + hash_type + "}")
                else:
                    normalized_parts.append(part)
        return method + " " + host + "/".join(normalized_parts)

    def _is_numeric(self, s):
        return s.isdigit()

    def _is_uuid(self, s):
        import re

        uuid_regex = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        return bool(uuid_regex.match(s))

    def _is_hash(self, s):
        """
        Identify common hash formats (MD5, SHA1, SHA256, Base64).
        Returns the hash type string if matched, False otherwise.
        """
        import re

        if not s:
            return False

        # Convert to string if needed
        s = str(s)

        # MD5: 32-character hexadecimal
        if re.match(r"^[0-9a-f]{32}$", s, re.IGNORECASE):
            return "md5"

        # SHA1: 40-character hexadecimal
        if re.match(r"^[0-9a-f]{40}$", s, re.IGNORECASE):
            return "sha1"

        # SHA256: 64-character hexadecimal
        if re.match(r"^[0-9a-f]{64}$", s, re.IGNORECASE):
            return "sha256"

        # Base64-like string (length > 20, alphanumeric with +/=)
        if len(s) > 20 and re.match(r"^[A-Za-z0-9+/]+=*$", s):
            if len(s) % 4 == 0:
                return "base64"

        return False

    def reconstruct_request(self, request_data, helpers):
        from java.util import ArrayList

        # 1. Get Headers
        headers_list = ArrayList()
        for h in request_data["headers"]:
            headers_list.add(h)

        # 2. Reconstruct Request Line (Method + Path + Query)
        method = request_data["method"]
        path = request_data["path"]
        query_params = request_data.get("query_params", {})

        # Build Query String
        query_string = ""
        if query_params:
            import urllib

            # Note: urllib.urlencode might reorder params, but standard servers shouldn't care.
            # However, to be cleaner, we might want to iterate if we knew the order.
            # Here we just use what we have.
            # Also need to handle list values if any.
            # JSON from DB might have values as strings or lists.
            # Check if query_params is dict
            if isinstance(query_params, dict):
                # We need to encode values.
                # Assuming simple key-value for now as per extraction logic.
                q_pairs = []
                for k, v in query_params.items():
                    if isinstance(v, list):
                        for sub_v in v:
                            q_pairs.append("{}={}".format(k, sub_v))
                    else:
                        q_pairs.append("{}={}".format(k, v))
                query_string = "&".join(q_pairs)

        full_path = path
        if query_string:
            full_path += "?" + query_string

        # Get HTTP Version from original headers[0]
        original_req_line = headers_list.get(0)
        http_version = "HTTP/1.1"  # Default
        if "HTTP/" in original_req_line:
            parts = original_req_line.split(" ")
            if len(parts) >= 3:
                http_version = parts[-1]

        new_req_line = "{} {} {}".format(method, full_path, http_version)
        headers_list.set(0, new_req_line)

        # 3. Body
        body = request_data["body"]
        if body is None:
            body = ""
        if isinstance(body, unicode):
            body = body.encode("utf-8")

        return helpers.buildHttpMessage(headers_list, body)

    def execute_pending_get_attacks(self, callbacks, helpers, llm_config=None, limit=50, hidden_param_config=None, apply_hidden_param_on_execute=False):
        """
        Execute pending GET attacks only. Used by both manual batch execution
        and scheduled automation to avoid mutating APIs.
        """
        sql = """
        SELECT a.id, r.method
        FROM attack_queue a
        JOIN raw_requests r ON a.original_request_id = r.id
        WHERE a.status = 'PENDING' AND r.method = 'GET'
        ORDER BY a.vulnerability_score DESC
        LIMIT {}
        """.format(int(limit))
        attacks = self.db_manager.fetch_all(sql)

        summary = {
            "total": len(attacks) if attacks else 0,
            "success": 0,
            "failed": 0,
            "vulnerable": 0,
            "results": [],
        }

        if not attacks:
            print("[Batch Attack] No PENDING GET attacks found.")
            return summary

        print(
            "[Batch Attack] Found {} PENDING GET attacks to execute (limit {}).".format(
                len(attacks), limit
            )
        )

        for attack_row in attacks:
            attack_id = attack_row[0]
            try:
                result = self.execute_attack(
                    attack_id,
                    callbacks,
                    helpers,
                    llm_config,
                    hidden_param_config,
                    apply_hidden_param_on_execute,
                )
                if result:
                    summary["success"] += 1
                    if result.get("status") == "VULNERABLE":
                        summary["vulnerable"] += 1
                    summary["results"].append(result)
                    print(
                        "[Batch Attack] Executed attack ID: {} - Status: {}".format(
                            attack_id, result.get("status", "UNKNOWN")
                        )
                    )
                else:
                    summary["failed"] += 1
                    print(
                        "[Batch Attack] Failed to execute attack ID: {}".format(
                            attack_id
                        )
                    )
            except Exception as e:
                summary["failed"] += 1
                print(
                    "[Batch Attack] Error executing attack {}: {}".format(
                        attack_id, str(e)
                    )
                )

        return summary

    def execute_attack(self, attack_id, callbacks, helpers, llm_config=None, hidden_param_config=None, apply_hidden_param_on_execute=False):
        from java.util import ArrayList
        from helpers.llm_helper import LLMHelper
        from java.net import URL
        import traceback as _tb

        # 1. Fetch attack data
        try:
            sql = (
                "SELECT request_data, original_request_id, target_user FROM attack_queue WHERE id = "
                + str(attack_id)
            )
            rows = self.db_manager.fetch_all(sql)
            if not rows:
                print("[Attacker] Attack ID {} not found.".format(attack_id))
                return None

            request_data_json, original_req_id, target_user = rows[0]
            # Handle Java byte arrays from zxJDBC BLOB columns
            if not isinstance(request_data_json, (str, unicode)):
                try:
                    request_data_json = helpers.bytesToString(request_data_json)
                except Exception:
                    request_data_json = str(request_data_json)
            request_data = json.loads(request_data_json)
        except Exception as e:
            print("[Attacker] Step 1 (fetch attack data) failed: " + str(e))
            _tb.print_exc()
            raise

        if apply_hidden_param_on_execute:
            hidden_param_entry = self._build_hidden_param_entry(hidden_param_config, target_user)
            if hidden_param_entry:
                request_data = self._apply_hidden_param_to_request_data(request_data, hidden_param_entry)
                print(
                    "[Attacker] Applying hidden param on execute for attack {}: {}".format(
                        attack_id, self._describe_hidden_param(hidden_param_entry)
                    )
                )

        # Verify Attack ID in request_data if possible, or just trust the DB row
        print(
            "[Attacker] Executing Attack ID: {} (Original Request ID: {})".format(
                attack_id, original_req_id
            )
        )

        # 2. Reconstruct Request (Correctly updating Request Line)
        request_data = self._apply_user_context_rules_to_request_data(
            request_data, target_user, helpers
        )
        new_request_bytes = self.reconstruct_request(request_data, helpers)

        # 3. Determine Service Details (Host, Port, Protocol)
        # We fetch original URL to determine port/protocol
        sql_url = "SELECT url FROM raw_requests WHERE id = " + str(original_req_id)
        url_rows = self.db_manager.fetch_all(sql_url)

        host = request_data["host"]  # Default host from saved data
        port = 80
        useHttps = False

        if url_rows:
            original_url_str = url_rows[0][0]
            try:
                u = URL(original_url_str)
                host = u.getHost()  # Use host from URL to be safe
                port = u.getPort()
                protocol = u.getProtocol()
                useHttps = protocol.lower() == "https"

                if port == -1:
                    port = 443 if useHttps else 80
            except:
                pass

        # 4. Send Request
        # Jython Burp API: byte[] makeHttpRequest(java.lang.String host, int port, boolean useHttps, byte[] request)
        response_bytes = callbacks.makeHttpRequest(
            host, port, useHttps, new_request_bytes
        )

        # 5. Process Response
        response_code = 0
        response_data = None

        if response_bytes:
            response_info = helpers.analyzeResponse(response_bytes)
            headers = response_info.getHeaders()
            if headers:
                # First line is status line (e.g., "HTTP/1.1 200 OK")
                status_line = headers[0]
                try:
                    response_code = int(status_line.split(" ")[1])
                except:
                    pass

            response_data = response_bytes

        # 6. LLM Verification
        llm_result_str = "PENDING"
        status = "SENT"
        attack_request_text = helpers.bytesToString(new_request_bytes)
        attack_response_text = (
            helpers.bytesToString(response_bytes) if response_bytes else ""
        )

        if 200 <= response_code < 300:
            # Only check if successful
            if llm_config and llm_config.get("enabled", False):
                try:
                    llm = LLMHelper(
                        llm_config["base_url"],
                        llm_config["api_key"],
                        llm_config["model"],
                        verify_ssl=llm_config.get("verify_ssl", True),
                    )

                    # Fetch original request string
                    orig_req_sql = (
                        "SELECT method, url, headers, body, response_headers, response_body FROM raw_requests WHERE id = "
                        + str(original_req_id)
                    )
                    orig_rows = self.db_manager.fetch_all(orig_req_sql)
                    orig_req_str = ""
                    orig_res_str = "Not Available"
                    if orig_rows:
                        m, u, h_json, b, res_h_json, res_b = orig_rows[0]
                        # Safely handle headers JSON (may be Java String/byte[])
                        try:
                            if not isinstance(h_json, (str, unicode)):
                                h_json = helpers.bytesToString(h_json) if h_json else "[]"
                            h_list = json.loads(h_json) if h_json else []
                            if not isinstance(h_list, list):
                                h_list = [str(h_list)]
                            h_str = "\n".join(h_list)
                        except Exception as e_h:
                            print("[Attacker] Error parsing original headers: " + str(e_h))
                            h_str = str(h_json) if h_json else ""
                        # Safely handle body (may be Java byte[])
                        try:
                            if b is not None and not isinstance(b, (str, unicode)):
                                b_str = helpers.bytesToString(b) if b else ""
                            else:
                                b_str = b if b else ""
                        except Exception:
                            b_str = ""
                        orig_req_str = "{} {}\n{}\n\n{}".format(
                            m, u, h_str, b_str
                        )
                        if res_h_json:
                            try:
                                if not isinstance(res_h_json, (str, unicode)):
                                    res_h_json = helpers.bytesToString(res_h_json) if res_h_json else "[]"
                                rh_list = json.loads(res_h_json) if res_h_json else []
                                if not isinstance(rh_list, list):
                                    rh_list = [str(rh_list)]
                                response_headers = "\n".join(rh_list)
                                response_body = (
                                    helpers.bytesToString(res_b) if res_b else ""
                                )
                                orig_res_str = "{}\n\n{}".format(
                                    response_headers, response_body
                                )
                            except Exception as e_rh:
                                print("[Attacker] Error parsing orig response headers: " + str(e_rh))
                                orig_res_str = helpers.bytesToString(res_b) if res_b else ""

                    print("[Attacker] Calling LLM for verification...")
                    llm_res = llm.analyze_idor_vulnerability(
                        orig_req_str,
                        orig_res_str,
                        attack_request_text,
                        attack_response_text,
                    )
                    print("[Attacker] LLM returned type: {}, value: {}".format(type(llm_res), str(llm_res)[:200]))
                    llm_result_str = json.dumps(llm_res)

                    # Update status based on LLM
                    if isinstance(llm_res, dict) and "result" in llm_res:
                        if llm_res["result"] == "VULNERABLE":
                            status = "VULNERABLE"
                        elif llm_res["result"] == "SAFE":
                            status = "SAFE"
                        else:
                            status = "UNCERTAIN"
                    else:
                        print("[Attacker] WARNING: llm_res is not a dict or missing 'result' key: " + str(llm_res)[:200])
                        status = "UNCERTAIN"
                        llm_result_str = json.dumps({"result": "UNCERTAIN", "reason": "LLM returned unexpected type", "confidence": 0.3})
                except Exception as e_llm:
                    print("[Attacker] LLM verification failed: " + str(e_llm))
                    _tb.print_exc()
                    status = "UNCERTAIN"
                    llm_result_str = json.dumps({"result": "UNCERTAIN", "reason": "LLM verification error: " + str(e_llm), "confidence": 0.3})
            else:
                status = "CHECKING_SKIPPED"  # No LLM
        else:
            status = "FAILED"  # Non-2xx

        # 7. Update DB
        response_data_sql = ""
        if response_data:
            if isinstance(response_data, unicode):
                response_data_sql = response_data.encode("utf-8")
            else:
                response_data_sql = response_data

        update_sql = """
        UPDATE attack_queue 
        SET status = ?, response_data = ?, response_code = ?, llm_verification_result = ?, executed_request_data = ?
        WHERE id = ?
        """
        self.db_manager.execute_query(
            update_sql,
            (status, response_data_sql, response_code, llm_result_str, new_request_bytes, attack_id),
        )

        return {"id": attack_id, "status": status, "code": response_code}

    # ------------------------------------------------------------------
    # Feature 1: AI 剪枝 - 批量评估并删除低价值 POC
    # ------------------------------------------------------------------
    def prune_attacks(self, llm_config=None, limit=50, score_threshold=30):
        """
        对 PENDING 状态的攻击进行 LLM 评分, 删除低于阈值的.
        使用参数化 DELETE, 不影响自增序列和索引.
        """
        from helpers.llm_helper import LLMHelper

        # 获取 PENDING 攻击列表
        sql = (
            "SELECT a.id, a.payload_description, a.request_data, a.target_user "
            "FROM attack_queue a "
            "WHERE a.status = 'PENDING' "
            "ORDER BY a.vulnerability_score DESC LIMIT ?"
        )
        rows = self.db_manager.fetch_all(sql, [int(limit)])
        if not rows:
            return {"total": 0, "pruned": 0, "remaining": 0, "details": []}

        details = []
        pruned_ids = []

        for row in rows:
            attack_id, payload_desc, req_data, target_user = row
            # 处理 byte[]
            if req_data and not isinstance(req_data, (str, unicode)):
                try:
                    req_data_str = str(req_data)
                except Exception:
                    req_data_str = ""
            else:
                req_data_str = req_data or ""

            score = 50
            reason = ""
            should_prune = False

            if llm_config and llm_config.get("enabled", False):
                llm = LLMHelper(
                    llm_config["base_url"],
                    llm_config["api_key"],
                    llm_config["model"],
                    verify_ssl=llm_config.get("verify_ssl", True),
                )
                result = llm.score_attack_potential(payload_desc, req_data_str, target_user)
                score = result.get("score", 50)
                reason = result.get("reason", "")
                should_prune = result.get("should_prune", score < score_threshold)
            else:
                # 无 LLM 时用简单启发式: 检查 payload_description 中是否包含 "->99999" 等无意义值
                if payload_desc and "99999" in str(payload_desc):
                    should_prune = True
                    reason = "Contains non-existent test value"
                    score = 20

            details.append({
                "attack_id": attack_id,
                "score": score,
                "reason": reason,
                "pruned": should_prune,
                "payload": payload_desc,
            })

            if should_prune:
                pruned_ids.append(attack_id)

        # 批量删除低分 POC (使用参数化查询)
        for aid in pruned_ids:
            self.db_manager.execute_query(
                "DELETE FROM attack_queue WHERE id = ?",
                [aid],
                commit=True,
            )

        remaining = len(rows) - len(pruned_ids)
        print("[Attacker] Pruned {} of {} PENDING attacks (remaining: {})".format(
            len(pruned_ids), len(rows), remaining))

        return {
            "total": len(rows),
            "pruned": len(pruned_ids),
            "remaining": remaining,
            "pruned_ids": pruned_ids,
            "details": details,
        }

    # ------------------------------------------------------------------
    # Feature 2: AI 越权验证 - 带完整上下文的深度验证
    # ------------------------------------------------------------------
    def ai_verify_attack(self, attack_id, llm_config=None, callbacks=None, helpers=None, extra_context=None):
        """
        AI 验证单个攻击结果, 带完整上下文.
        结果写入 ai_verification_result 和 ai_verified 字段, 优先级高于 LLM 自动验证.
        """
        from helpers.llm_helper import LLMHelper
        import json as _json

        # 1. 获取攻击数据和原始请求数据
        sql = (
            "SELECT a.id, a.executed_request_data, a.response_data, a.response_code, a.status, "
            "a.llm_verification_result, a.payload_description, "
            "r.method, r.url, r.headers, r.body, r.response_headers, r.response_body "
            "FROM attack_queue a "
            "JOIN raw_requests r ON a.original_request_id = r.id "
            "WHERE a.id = ?"
        )
        rows = self.db_manager.fetch_all(sql, [attack_id])
        if not rows:
            return {"error": "Attack not found"}

        row = rows[0]
        (_, exec_req_data, resp_data, resp_code, status, llm_result, payload_desc,
         method, url, orig_headers, orig_body, orig_resp_headers, orig_resp_body) = row

        # 2. 构建请求/响应文本
        def to_str(val):
            if val is None:
                return ""
            if isinstance(val, (str, unicode)):
                return val
            if helpers:
                try:
                    return helpers.bytesToString(val)
                except Exception:
                    pass
            try:
                return str(val)
            except Exception:
                return ""

        attack_req_text = to_str(exec_req_data) or ""
        attack_res_text = to_str(resp_data) or ""

        # 原始请求
        orig_req_str = ""
        try:
            h_list = _json.loads(orig_headers) if orig_headers else []
            if not isinstance(h_list, list):
                h_list = [str(h_list)]
            h_str = "\n".join(h_list)
        except Exception:
            h_str = str(orig_headers or "")
        orig_req_str = "{} {}\n{}\n\n{}".format(
            method or "GET", url or "", h_str, to_str(orig_body))

        # 原始响应
        orig_res_str = "Not Available"
        try:
            rh_list = _json.loads(orig_resp_headers) if orig_resp_headers else []
            if not isinstance(rh_list, list):
                rh_list = [str(rh_list)]
            rh_str = "\n".join(rh_list)
            orig_res_str = "{}\n\n{}".format(rh_str, to_str(orig_resp_body))
        except Exception:
            orig_res_str = to_str(orig_resp_body) or "Not Available"

        # 3. 调用 LLM 验证
        if llm_config and llm_config.get("enabled", False):
            llm = LLMHelper(
                llm_config["base_url"],
                llm_config["api_key"],
                llm_config["model"],
                verify_ssl=llm_config.get("verify_ssl", True),
            )
            result = llm.verify_with_full_context(
                orig_req_str, orig_res_str,
                attack_req_text, attack_res_text,
                extra_context or {},
            )
        else:
            return {"error": "LLM not enabled"}

        # 4. 回写数据库
        ai_result_str = _json.dumps(result)
        # AI 验证结果优先: 如果 AI 判定为 VULNERABLE, 更新 status
        new_status = status
        if result.get("result") == "VULNERABLE":
            new_status = "VULNERABLE"
        elif result.get("result") == "SAFE" and status == "PENDING":
            new_status = "SAFE"

        self.db_manager.execute_query(
            "UPDATE attack_queue SET ai_verification_result = ?, ai_verified = 1, status = ? WHERE id = ?",
            [ai_result_str, new_status, attack_id],
            commit=True,
        )

        print("[Attacker] AI verified attack {}: {} (confidence: {})".format(
            attack_id, result.get("result"), result.get("confidence")))

        return {
            "attack_id": attack_id,
            "ai_result": result,
            "new_status": new_status,
            "payload": payload_desc,
        }

    # ------------------------------------------------------------------
    # Feature 3: AI POC 生成 - 基于 LLM 建议创建攻击条目
    # ------------------------------------------------------------------
    def ai_create_poc(self, request_id, modifications=None, llm_config=None, target_user=None):
        """
        基于 AI 建议的参数修改, 创建新的攻击条目.
        modifications: list of {"param", "new_value", "location", "reason"}
        如果 modifications 为空, 则调用 LLM 自动生成.
        """
        from helpers.llm_helper import LLMHelper
        import json as _json

        # 1. 获取原始请求数据
        sql = (
            "SELECT id, method, host, url, path, headers, query_params, body, user_identifier "
            "FROM raw_requests WHERE id = ?"
        )
        rows = self.db_manager.fetch_all(sql, [request_id])
        if not rows:
            return {"error": "Request not found"}

        req = rows[0]
        (req_id, method, host, url, path, headers_json,
         query_params_json, body, user_identifier) = req

        # 构建 request_data (与 _create_attack_entry_for_combination 格式一致)
        try:
            headers_list = _json.loads(headers_json) if headers_json else []
        except Exception:
            headers_list = [str(headers_json)] if headers_json else []
        try:
            query_params = _json.loads(query_params_json) if query_params_json else {}
        except Exception:
            query_params = {}

        request_data = {
            "headers": list(headers_list),
            "method": method or "GET",
            "body": body if body else "",
            "path": path or "",
            "query_params": query_params,
            "host": host or "",
        }

        # 2. 如果没有提供 modifications, 调用 LLM 生成
        if not modifications and llm_config and llm_config.get("enabled", False):
            llm = LLMHelper(
                llm_config["base_url"],
                llm_config["api_key"],
                llm_config["model"],
                verify_ssl=llm_config.get("verify_ssl", True),
            )
            # 获取已知的参数池数据
            existing_params = []
            try:
                pool_rows = self.db_manager.fetch_all(
                    "SELECT param_name, param_value, location, user_identifier "
                    "FROM parameter_pool WHERE api_signature = "
                    "(SELECT api_signature FROM raw_requests WHERE id = ?) LIMIT 20",
                    [request_id],
                )
                if pool_rows:
                    existing_params = [
                        {"name": r[0], "value": r[1], "location": r[2], "user": r[3]}
                        for r in pool_rows
                    ]
            except Exception:
                pass

            # 获取所有用户标识
            target_users = []
            try:
                user_rows = self.db_manager.fetch_all(
                    "SELECT DISTINCT user_identifier FROM parameter_pool "
                    "WHERE user_identifier IS NOT NULL LIMIT 10"
                )
                if user_rows:
                    target_users = [r[0] for r in user_rows]
            except Exception:
                pass

            modifications = llm.generate_poc_modifications(
                _json.dumps(request_data), existing_params, target_users
            )

        if not modifications:
            return {"error": "No modifications provided or generated", "generated": 0}

        # 3. 为每个 modification 创建攻击条目
        created_ids = []
        for mod in modifications:
            param_name = mod.get("param", "")
            new_value = mod.get("new_value", "")
            location = mod.get("location", "QUERY").upper()
            reason = mod.get("reason", "")

            if not param_name or not new_value:
                continue

            # 克隆并修改 request_data
            mod_data = _json.loads(_json.dumps(request_data))  # deep copy

            if location == "QUERY":
                old_val = mod_data.get("query_params", {}).get(param_name, "")
                mod_data["query_params"][param_name] = new_value
                # 更新请求行中的查询参数
                if mod_data.get("headers"):
                    req_line = mod_data["headers"][0]
                    if "?" in req_line:
                        base, qs = req_line.split("?", 1)
                        pairs = qs.split("&")
                        new_pairs = []
                        for pair in pairs:
                            if "=" in pair:
                                k, v = pair.split("=", 1)
                                if k == param_name:
                                    new_pairs.append("{}={}".format(k, new_value))
                                else:
                                    new_pairs.append(pair)
                            else:
                                if pair == param_name:
                                    new_pairs.append("{}={}".format(param_name, new_value))
                                else:
                                    new_pairs.append(pair)
                        mod_data["headers"][0] = "{}?{}".format(base, "&".join(new_pairs))
                    else:
                        mod_data["headers"][0] = "{}?{}={}".format(
                            mod_data["headers"][0].split(" ")[0] if " " in mod_data["headers"][0] else mod_data["headers"][0],
                            param_name, new_value)

            elif location == "PATH":
                # 替换 path 中的参数值
                old_val = mod_data.get("path", "")
                # 简单的值替换: 在 path 中找到旧值并替换
                # 这里需要原始参数值来定位
                old_val = mod.get("original_value", "")
                if old_val and old_val in mod_data["path"]:
                    mod_data["path"] = mod_data["path"].replace(old_val, new_value)
                    # 更新请求行
                    if mod_data.get("headers"):
                        parts = mod_data["headers"][0].split(" ")
                        if len(parts) >= 2:
                            parts[1] = mod_data["path"]
                            mod_data["headers"][0] = " ".join(parts)

            elif location == "BODY":
                old_val = ""
                body_str = mod_data.get("body", "")
                if isinstance(body_str, (str, unicode)):
                    try:
                        body_obj = _json.loads(body_str)
                        if isinstance(body_obj, dict) and param_name in body_obj:
                            old_val = body_obj[param_name]
                            body_obj[param_name] = new_value
                            mod_data["body"] = _json.dumps(body_obj)
                    except Exception:
                        # 非 JSON body, 尝试 key=value 替换
                        if param_name + "=" in body_str:
                            import re as _re
                            old_val = ""
                            mod_data["body"] = _re.sub(
                                r"{}=[^&]*".format(_re.escape(param_name)),
                                "{}={}".format(param_name, new_value),
                                body_str,
                            )

            elif location == "HEADER":
                old_val = ""
                if mod_data.get("headers"):
                    for i, h in enumerate(mod_data["headers"]):
                        if h.startswith(param_name + ":"):
                            old_val = h.split(":", 1)[1].strip()
                            mod_data["headers"][i] = "{}: {}".format(param_name, new_value)
                            break

            # 构造描述
            desc = "[AI] Swap {} ({}): {}->{}".format(
                location, param_name,
                old_val if old_val else "?", new_value)
            if reason:
                desc += " | {}".format(reason[:100])

            # 入队
            request_data_json_str = _json.dumps(mod_data).replace("'", "''")
            desc_str = desc.replace("'", "''")
            # 获取 risk_score
            risk_score = 40  # 默认
            try:
                score_rows = self.db_manager.fetch_all(
                    "SELECT risk_score FROM parameter_pool "
                    "WHERE param_name = ? AND location = ? LIMIT 1",
                    [param_name, location],
                )
                if score_rows and score_rows[0][0] is not None:
                    risk_score = score_rows[0][0]
            except Exception:
                pass

            insert_sql = (
                "INSERT INTO attack_queue "
                "(original_request_id, target_user, payload_description, request_data, status, vulnerability_score) "
                "VALUES ({}, '{}', '{}', '{}', 'PENDING', {})"
            ).format(
                request_id,
                (target_user or user_identifier or "AI-Generated").replace("'", "''"),
                desc_str,
                request_data_json_str,
                risk_score,
            )

            try:
                self.db_manager.execute_query(insert_sql)
                # 获取插入的 ID (不能用 last_insert_rowid(), 因为是不同连接)
                id_rows = self.db_manager.fetch_all(
                    "SELECT max(id) as id FROM attack_queue WHERE original_request_id = ?",
                    [request_id],
                )
                if id_rows and id_rows[0][0]:
                    created_ids.append(id_rows[0][0])
                print("[Attacker] AI POC created: " + desc)
            except Exception as e:
                print("[Attacker] Error creating AI POC: " + str(e))

        return {
            "generated": len(created_ids),
            "attack_ids": created_ids,
            "modifications": modifications,
        }
