#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import re
import traceback

from javax.swing import (
    JPanel,
    JLabel,
    JButton,
    JTextField,
    JComboBox,
    JCheckBox,
    JScrollPane,
    JSplitPane,
    JTable,
    ListSelectionModel,
    GroupLayout,
)
from javax.swing.table import AbstractTableModel, TableRowSorter
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout
from java.lang import Runnable
from javax.swing import SwingUtilities
from burp import IMessageEditorController

from helpers.llm_helper import LLMHelper


class RecommendationTableModel(AbstractTableModel):
    columns = [
        "Rank",
        "Target Key",
        "Pool Key",
        "Suggested Value",
        "Source User",
        "Location",
        "Endpoint",
        "Score",
        "Reason",
    ]

    def __init__(self):
        self.rows = []

    def set_rows(self, rows):
        self.rows = rows or []
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self.rows)

    def getColumnCount(self):
        return len(self.columns)

    def getColumnName(self, column):
        return self.columns[column]

    def getValueAt(self, rowIndex, columnIndex):
        row = self.rows[rowIndex]
        mapping = [
            row.get("rank", ""),
            row.get("key", ""),
            row.get("param_name", ""),
            row.get("value", ""),
            row.get("source_user", ""),
            row.get("location", ""),
            row.get("endpoint", ""),
            row.get("score", ""),
            row.get("reason", ""),
        ]
        return mapping[columnIndex]

    def get_row(self, idx):
        if idx < 0 or idx >= len(self.rows):
            return None
        return self.rows[idx]


class RecommenderViewerController(IMessageEditorController):
    def __init__(self, panel, kind):
        self.panel = panel
        self.kind = kind

    def getHttpService(self):
        return None

    def getRequest(self):
        row = self.panel.selected_row
        if not row:
            return None
        return row.get("request_bytes") if self.kind == "request" else None

    def getResponse(self):
        row = self.panel.selected_row
        if not row:
            return None
        return row.get("response_bytes") if self.kind == "response" else None


class RecommendationSelectionListener(ListSelectionListener):
    def __init__(self, panel):
        self.panel = panel

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        self.panel.on_selection_change()


class ParamRecommendRunnable(Runnable):
    def __init__(self, panel, key, location):
        self.panel = panel
        self.key = key
        self.location = location

    def run(self):
        self.panel._run_recommendation(self.key, self.location)


class UserParamRecommenderPanel(JPanel):
    def __init__(self, extender, user_tab, user_id):
        JPanel.__init__(self, BorderLayout())
        self.extender = extender
        self.user_tab = user_tab
        self.user_id = user_id
        self.selected_row = None

        self.top_panel = JPanel()
        top_layout = GroupLayout(self.top_panel)
        self.top_panel.setLayout(top_layout)
        top_layout.setAutoCreateGaps(True)
        top_layout.setAutoCreateContainerGaps(True)

        self.keyLabel = JLabel("Key to test:")
        self.keyField = JTextField(24)
        self.locationLabel = JLabel("Location:")
        self.locationCombo = JComboBox(["Auto", "Query", "Header", "Body", "Path"])
        self.useLlmCheck = JCheckBox("Use LLM reranking")
        self.useLlmCheck.setSelected(True)
        self.recommendButton = JButton("Recommend Top 3", actionPerformed=self.recommend)
        self.useButton = JButton("Use selected", actionPerformed=self.use_selected)
        self.statusLabel = JLabel("Enter a key and click Recommend Top 3.")
        self.sourceUserLabel = JLabel("Source User: -")

        top_layout.setHorizontalGroup(
            top_layout.createParallelGroup()
                .addGroup(top_layout.createSequentialGroup()
                    .addComponent(self.keyLabel)
                    .addComponent(self.keyField)
                    .addComponent(self.locationLabel)
                    .addComponent(self.locationCombo)
                    .addComponent(self.useLlmCheck)
                    .addComponent(self.recommendButton)
                    .addComponent(self.useButton)
                )
                .addComponent(self.statusLabel)
                .addComponent(self.sourceUserLabel)
        )
        top_layout.setVerticalGroup(
            top_layout.createSequentialGroup()
                .addGroup(top_layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.keyLabel)
                    .addComponent(self.keyField)
                    .addComponent(self.locationLabel)
                    .addComponent(self.locationCombo)
                    .addComponent(self.useLlmCheck)
                    .addComponent(self.recommendButton)
                    .addComponent(self.useButton)
                )
                .addComponent(self.statusLabel)
                .addComponent(self.sourceUserLabel)
        )

        self.add(self.top_panel, BorderLayout.NORTH)

        self.table_model = RecommendationTableModel()
        self.table = JTable(self.table_model)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.setRowSorter(TableRowSorter(self.table_model))
        self.table.getSelectionModel().addListSelectionListener(
            RecommendationSelectionListener(self)
        )
        table_scroll = JScrollPane(self.table)

        self.request_viewer = self.extender._callbacks.createMessageEditor(
            RecommenderViewerController(self, "request"), False
        )
        self.response_viewer = self.extender._callbacks.createMessageEditor(
            RecommenderViewerController(self, "response"), False
        )

        viewers_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        viewers_split.setLeftComponent(self.request_viewer.getComponent())
        viewers_split.setRightComponent(self.response_viewer.getComponent())
        viewers_split.setDividerLocation(500)

        self.main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.main_split.setTopComponent(table_scroll)
        self.main_split.setBottomComponent(viewers_split)
        self.main_split.setDividerLocation(180)
        self.add(self.main_split, BorderLayout.CENTER)

    def _log(self, message):
        try:
            print("[Param Recommender] " + str(message))
        except Exception:
            pass

    def _set_status(self, message):
        def update():
            self.statusLabel.setText(message)

        if SwingUtilities.isEventDispatchThread():
            update()
        else:
            SwingUtilities.invokeLater(update)

    def _set_recommend_enabled(self, enabled):
        def update():
            self.recommendButton.setEnabled(enabled)

        if SwingUtilities.isEventDispatchThread():
            update()
        else:
            SwingUtilities.invokeLater(update)

    def _clear_results(self):
        def update():
            self.table_model.set_rows([])
            self.selected_row = None
            self.sourceUserLabel.setText("Source User: -")
            self.request_viewer.setMessage(None, True)
            self.response_viewer.setMessage(None, False)

        if SwingUtilities.isEventDispatchThread():
            update()
        else:
            SwingUtilities.invokeLater(update)

    def _display_results(self, rows):
        def update():
            self.table_model.set_rows(rows)
            if len(rows) > 0:
                self.table.setRowSelectionInterval(0, 0)
                self.on_selection_change()

        if SwingUtilities.isEventDispatchThread():
            update()
        else:
            SwingUtilities.invokeLater(update)

    def _get_current_user_data(self):
        return self.user_tab.user_tabs.get(self.user_id)

    def _get_current_user_name(self):
        user_data = self._get_current_user_data()
        return user_data.get("user_name") if user_data else None

    def _normalize_key(self, key):
        if not key:
            return ""
        return re.sub(r"[^a-z0-9]", "", key.lower())

    def _split_key_tokens(self, key, strip_generic=True):
        if not key:
            return []

        key_text = str(key)
        key_text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key_text)
        key_text = re.sub(r"[^A-Za-z0-9]+", " ", key_text)

        raw_tokens = []
        for token in key_text.lower().split():
            token = self._normalize_token(token)
            if not token:
                continue
            raw_tokens.extend(self._expand_compound_token(token))

        tokens = []
        for token in raw_tokens:
            token = self._normalize_token(token)
            if token:
                tokens.append(token)

        if strip_generic and len(tokens) > 1:
            generic = set([
                "x",
                "http",
                "https",
                "header",
                "hdr",
                "param",
                "parameter",
                "request",
                "req",
                "value",
                "val",
            ])
            tokens = [t for t in tokens if t not in generic]

        return tokens

    def _expand_compound_token(self, token):
        if not token:
            return []
        if token.endswith("uuid") and len(token) > 4:
            return [token[:-4], "uuid"]
        if token.endswith("guid") and len(token) > 4:
            return [token[:-4], "guid"]
        if token.endswith("id") and len(token) > 2:
            return [token[:-2], "id"]
        return [token]

    def _normalize_token(self, token):
        if not token:
            return ""

        token = token.lower().strip()
        synonyms = {
            "identifier": "id",
            "ident": "id",
            "uid": "id",
            "uuid": "id",
            "guid": "id",
            "acct": "account",
            "accounts": "account",
            "usr": "user",
            "users": "user",
            "domains": "domain",
            "org": "organization",
            "organisation": "organization",
        }
        if token in synonyms:
            return synonyms[token]

        if token.endswith("ies") and len(token) > 4:
            return token[:-3] + "y"
        if token.endswith("s") and len(token) > 3 and not token.endswith("ss"):
            return token[:-1]
        return token

    def _semantic_key_score(self, target_key, pool_key):
        target_norm = self._normalize_key(target_key)
        pool_norm = self._normalize_key(pool_key)

        if not target_norm or not pool_norm:
            return 0, "empty key"

        if str(target_key).strip().lower() == str(pool_key).strip().lower():
            return 100, "exact key match"
        if target_norm == pool_norm:
            return 96, "normalized key match"

        target_tokens = self._split_key_tokens(target_key, True)
        pool_tokens = self._split_key_tokens(pool_key, True)
        target_core = "".join(target_tokens)
        pool_core = "".join(pool_tokens)

        if target_core and target_core == pool_core:
            return 92, "same key tokens after removing generic prefixes"
        if target_core and pool_core and (target_core.endswith(pool_core) or pool_core.endswith(target_core)):
            return 86, "one key is a suffix of the other after token normalization"
        if target_norm.endswith(pool_norm) or pool_norm.endswith(target_norm):
            return 82, "one normalized key is a suffix of the other"

        target_set = set(target_tokens)
        pool_set = set(pool_tokens)
        if not target_set or not pool_set:
            return 0, "no comparable key tokens"

        shared = target_set.intersection(pool_set)
        if not shared:
            return 0, "no shared key tokens"

        union = target_set.union(pool_set)
        jaccard = float(len(shared)) / float(len(union))
        score = int(35 + (jaccard * 50))

        if target_set.issubset(pool_set) or pool_set.issubset(target_set):
            score = max(score, 78)

        important_shared = [t for t in shared if t not in set(["id", "key", "code", "token"])]
        if important_shared and "id" in shared:
            score = max(score, 84)
        elif important_shared:
            score = max(score, 70)

        return min(score, 90), "shared semantic tokens: " + ", ".join(sorted(shared))

    def _looks_like_location(self, row_location, requested_location):
        if not requested_location or requested_location == "Auto":
            return True
        row_location = (row_location or "").upper()
        requested_location = requested_location.upper()
        if row_location == requested_location:
            return True
        if requested_location == "BODY":
            return "BODY" in row_location
        if requested_location == "QUERY":
            return "QUERY" in row_location or row_location == "PARAM_URL"
        if requested_location == "HEADER":
            return "HEADER" in row_location
        if requested_location == "PATH":
            return "PATH" in row_location
        return False

    def _to_text(self, value):
        if value is None:
            return ""
        try:
            if isinstance(value, basestring):
                return value
        except Exception:
            pass
        try:
            return self.extender._helpers.bytesToString(value)
        except Exception:
            try:
                return str(value)
            except Exception:
                return ""

    def _fetch_candidates(self, key, requested_location):
        if not hasattr(self.extender, "db_manager") or not self.extender.db_manager:
            self._log("Database manager is not initialized; cannot search parameter_pool.")
            return []

        normalized = self._normalize_key(key)
        sql = "SELECT api_signature, param_name, param_value, location, user_identifier, risk_score, llm_analysis_result FROM parameter_pool"
        self._log("Searching parameter_pool for key='{}', normalized='{}', location='{}', current_user='{}'".format(
            key, normalized, requested_location, self._get_current_user_name()
        ))
        rows = self.extender.db_manager.fetch_all(sql)
        self._log("parameter_pool returned {} total rows before filtering.".format(len(rows or [])))
        candidates = []
        current_user_name = self._get_current_user_name()
        skipped_same_user = 0
        location_mismatch = 0
        skipped_key = 0

        for row in rows or []:
            api_signature, param_name, param_value, location, source_user, risk_score, llm_analysis_result = row
            if not param_name or not param_value or not source_user:
                continue
            if current_user_name and str(source_user).strip().lower() == str(current_user_name).strip().lower():
                skipped_same_user += 1
                continue

            location_match = self._looks_like_location(location, requested_location)
            if not location_match:
                location_mismatch += 1

            exact = str(param_name).strip().lower() == str(key).strip().lower()
            normalized_match = self._normalize_key(param_name) == normalized
            key_similarity, key_match_reason = self._semantic_key_score(key, param_name)
            if key_similarity < 30:
                skipped_key += 1
                continue

            method = ""
            endpoint = api_signature or ""
            if api_signature and " " in api_signature:
                try:
                    method, endpoint = api_signature.split(" ", 1)
                except Exception:
                    pass

            score = int(risk_score or 0)
            score = key_similarity + min(score / 5, 20)
            if exact:
                score = max(score, 100)
            elif normalized_match:
                score = max(score, 96)
            if location_match and requested_location != "Auto":
                score += 10
            elif not location_match and requested_location != "Auto":
                score -= 10
            score = max(0, min(int(score), 100))

            candidates.append({
                "key": key,
                "param_name": param_name,
                "value": param_value,
                "source_user": source_user,
                "location": location,
                "api_signature": api_signature,
                "method": method,
                "endpoint": endpoint,
                "score": score,
                "key_similarity": key_similarity,
                "key_match_reason": key_match_reason,
                "llm_analysis_result": llm_analysis_result,
            })

        candidates.sort(key=lambda x: x.get("score", 0), reverse=True)
        self._log(
            "Candidate filter complete: matched={}, skipped_same_user={}, location_mismatch={}, skipped_key={}.".format(
                len(candidates), skipped_same_user, location_mismatch, skipped_key
            )
        )
        return candidates[:30]

    def _find_evidence_for_candidate(self, candidate):
        source_user = candidate.get("source_user")
        param_name = candidate.get("param_name")
        param_value = candidate.get("value")
        requested_location = (candidate.get("location") or "").upper()
        endpoint_fragment = ""
        if candidate.get("api_signature") and " " in candidate.get("api_signature"):
            try:
                endpoint_fragment = candidate.get("api_signature").split(" ", 1)[1]
            except Exception:
                endpoint_fragment = ""

        sql = "SELECT method, url, headers, query_params, body, response_headers, response_body, user_identifier, path FROM raw_requests WHERE user_identifier = ? ORDER BY id DESC"
        rows = self.extender.db_manager.fetch_all(sql, (source_user,))
        self._log("Searching evidence for {}={} from user '{}': {} raw rows.".format(
            param_name, param_value, source_user, len(rows or [])
        ))

        best = None
        best_score = -1
        for row in rows or []:
            method, url, headers_json, query_json, body, response_headers_json, response_body, user_identifier, path = row
            score = 0
            if endpoint_fragment and path and str(endpoint_fragment).endswith(str(path)):
                score += 30
            request_headers = []
            try:
                request_headers = json.loads(headers_json) if headers_json else []
            except Exception:
                request_headers = []
            query_params = {}
            try:
                query_params = json.loads(query_json) if query_json else {}
            except Exception:
                query_params = {}
            body_text = self._to_text(body)

            matched = False
            if requested_location == "HEADER":
                for header in request_headers:
                    if ":" in header:
                        h_name, h_val = header.split(":", 1)
                        if h_name.strip().lower() == str(param_name).strip().lower() and param_value in h_val:
                            matched = True
                            score += 50
                            break
            elif requested_location == "QUERY":
                if isinstance(query_params, dict) and str(query_params.get(param_name, "")) == str(param_value):
                    matched = True
                    score += 50
            elif requested_location == "PATH":
                if path and str(param_value) in str(path):
                    matched = True
                    score += 50
            else:
                if body_text and str(param_value) in body_text:
                    matched = True
                    score += 40
                if not matched and isinstance(query_params, dict) and str(query_params.get(param_name, "")) == str(param_value):
                    matched = True
                    score += 30
                if not matched:
                    for header in request_headers:
                        if ":" in header:
                            h_name, h_val = header.split(":", 1)
                            if h_name.strip().lower() == str(param_name).strip().lower() and param_value in h_val:
                                matched = True
                                score += 30
                                break

            if not matched:
                continue

            request_text = "{} {}\n{}\n\n{}".format(
                method,
                url,
                "\n".join(request_headers),
                body_text,
            )
            response_text = ""
            try:
                response_headers = json.loads(response_headers_json) if response_headers_json else []
            except Exception:
                response_headers = []
            response_body_text = self._to_text(response_body)
            response_text = "{}\n\n{}".format("\n".join(response_headers), response_body_text)

            if response_body_text and str(param_value) in response_body_text:
                score += 10

            if score > best_score:
                best_score = score
                best = {
                    "request_bytes": self.extender._helpers.stringToBytes(request_text),
                    "response_bytes": self.extender._helpers.stringToBytes(response_text),
                    "endpoint": path or url,
                    "method": method,
                }

        if best:
            self._log("Evidence matched for {}={} with score {}.".format(param_name, param_value, best_score))
        else:
            self._log("No evidence matched for {}={} from user '{}'.".format(param_name, param_value, source_user))
        return best

    def _build_reason(self, candidate):
        location = candidate.get("location") or "UNKNOWN"
        endpoint = candidate.get("endpoint") or candidate.get("api_signature") or ""
        return "Target key '{}' matched pool key '{}' ({}). {} candidate from {} traffic on {}".format(
            candidate.get("key", ""),
            candidate.get("param_name", ""),
            candidate.get("key_match_reason", "semantic match"),
            location,
            candidate.get("source_user", "unknown"),
            endpoint
        )

    def _rerank_with_llm(self, key, location, candidates):
        if not candidates:
            return candidates
        if not hasattr(self.extender, 'enableLlm') or not self.extender.enableLlm.isSelected():
            self._log("LLM reranking skipped: global LLM analysis is disabled.")
            return candidates
        if not self.useLlmCheck.isSelected():
            self._log("LLM reranking skipped: panel checkbox is disabled.")
            return candidates

        try:
            self._set_status("Reranking recommendations with LLM...")
            self._log("LLM reranking started for {} enriched candidates.".format(len(candidates)))
            llm = LLMHelper(
                self.extender.llmBaseUrl.getText(),
                self.extender.llmApiKey.getText(),
                self.extender.llmModel.getText(),
            )
            prompt_candidates = []
            for idx, candidate in enumerate(candidates):
                prompt_candidates.append({
                    "index": idx,
                    "target_key": key,
                    "pool_key": candidate.get("param_name"),
                    "value": candidate.get("value"),
                    "source_user": candidate.get("source_user"),
                    "location": candidate.get("location"),
                    "endpoint": candidate.get("endpoint"),
                    "score": candidate.get("score"),
                    "local_key_similarity": candidate.get("key_similarity"),
                    "local_reason": candidate.get("key_match_reason"),
                })

            prompt = """You are helping rank candidate parameter keys for authorization/IDOR testing.
Given a target key and candidate keys from a parameter pool, choose the top 3 candidates whose pool_key is semantically closest to the target key and useful for IDOR testing.
Treat common HTTP/header prefixes as weak signals only. For example, X-Domain-id and domain_id are highly similar because both mean domain id.
Return ONLY a JSON list of up to 3 objects.
Each object must contain:
- index: the candidate index from input
- score: integer 0-100
- reason: concise reason explaining the semantic key match and mentioning source user when helpful

Target key: {key}
Target location: {location}
Candidates:
{candidates}
""".format(
                key=key,
                location=location,
                candidates=json.dumps(prompt_candidates),
            )
            response = llm._call_llm(prompt)
            content = llm._extract_content(response)
            ranked = json.loads(content)
            results = []
            for item in ranked:
                idx = item.get("index")
                if idx is None or idx < 0 or idx >= len(candidates):
                    continue
                candidate = dict(candidates[idx])
                candidate["score"] = item.get("score", candidate.get("score", 0))
                candidate["reason"] = item.get("reason", candidate.get("reason", ""))
                results.append(candidate)
            if results:
                self._log("LLM reranking returned {} usable results.".format(len(results)))
                return results[:3]
        except Exception as e:
            print("[Param Recommender] LLM rerank failed: " + str(e))
            traceback.print_exc()

        self._log("Falling back to local ranking.")
        return candidates[:3]

    def recommend(self, event):
        key = self.keyField.getText().strip()
        if not key:
            self.statusLabel.setText("Please enter a key to test.")
            return

        location = str(self.locationCombo.getSelectedItem())
        self._log("Recommend Top 3 clicked: user_id={}, user_name='{}', key='{}', location='{}'.".format(
            self.user_id, self._get_current_user_name(), key, location
        ))
        self._set_status("Searching parameter pool...")
        self._set_recommend_enabled(False)
        if hasattr(self.extender, "executor") and self.extender.executor:
            self.extender.executor.submit(ParamRecommendRunnable(self, key, location))
        else:
            self._log("Executor is not available; running recommendation on current thread.")
            self._run_recommendation(key, location)

    def _run_recommendation(self, key, location):
        try:
            if not hasattr(self.extender, "db_manager") or not self.extender.db_manager:
                self._clear_results()
                self._set_status("Database manager is not initialized yet. Try again after initialization completes.")
                self._log("Recommendation aborted because DatabaseManager is not initialized.")
                return

            candidates = self._fetch_candidates(key, location)
            if not candidates:
                self._clear_results()
                self._set_status("No candidate values found in parameter_pool. Run Extract Params first if the pool is empty.")
                return

            enriched = []
            for candidate in candidates:
                evidence = self._find_evidence_for_candidate(candidate)
                if not evidence:
                    continue
                candidate = dict(candidate)
                candidate.update(evidence)
                candidate["reason"] = self._build_reason(candidate)
                enriched.append(candidate)
            self._log("Evidence enrichment complete: {}/{} candidates matched.".format(
                len(enriched), len(candidates)
            ))

            if not enriched:
                self._clear_results()
                self._set_status("Candidates found, but no source request/response evidence was matched.")
                return

            ranked = self._rerank_with_llm(key, location, enriched)
            if not ranked:
                ranked = enriched[:3]
            ranked = ranked[:3]
            for idx, row in enumerate(ranked):
                row["rank"] = idx + 1
            self._display_results(ranked)
            self._set_status("Found {} recommendations.".format(len(ranked)))
            self._log("Recommendation complete: {} rows displayed.".format(len(ranked)))
        except Exception as e:
            self._clear_results()
            self._set_status("Recommendation failed: " + str(e))
            self._log("Recommendation failed: " + str(e))
            traceback.print_exc()
        finally:
            self._set_recommend_enabled(True)

    def on_selection_change(self):
        view_row = self.table.getSelectedRow()
        if view_row < 0:
            self.selected_row = None
            self.sourceUserLabel.setText("Source User: -")
            self.request_viewer.setMessage(None, True)
            self.response_viewer.setMessage(None, False)
            return
        model_row = self.table.convertRowIndexToModel(view_row)
        row = self.table_model.get_row(model_row)
        self.selected_row = row
        self.sourceUserLabel.setText("Source User: {}".format(row.get("source_user", "-")))
        self.request_viewer.setMessage(row.get("request_bytes"), True)
        self.response_viewer.setMessage(row.get("response_bytes"), False)

    def use_selected(self, event):
        row = self.selected_row
        if not row:
            self.statusLabel.setText("Please select a recommendation first.")
            return

        user_data = self._get_current_user_data()
        if not user_data:
            self.statusLabel.setText("Current user context not found.")
            return

        mr_instance = user_data.get("mr_instance")
        if not mr_instance:
            self.statusLabel.setText("Match/Replace model not found for current user.")
            return

        location = (row.get("location") or str(self.locationCombo.getSelectedItem()) or "").upper()
        selected_location = str(self.locationCombo.getSelectedItem()).upper()
        if selected_location and selected_location != "AUTO":
            location = selected_location
        if location == "HEADER":
            rule_type = "Header Add/Set:"
        else:
            rule_type = "Query Add/Set:"

        mr_instance.MRType.setSelectedItem(rule_type)
        mr_instance.MText.setText(row.get("key", ""))
        mr_instance.RText.setText(str(row.get("value", "")))
        mr_instance.addMRFilter(None)
        self.statusLabel.setText(
            "Applied {}={} from source user {} to current user Match/Replace.".format(
                row.get("key", ""), row.get("value", ""), row.get("source_user", "-"),
            )
        )
