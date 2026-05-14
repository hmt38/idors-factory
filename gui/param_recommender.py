#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import re

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
from burp import IMessageEditorController

from helpers.llm_helper import LLMHelper


class RecommendationTableModel(AbstractTableModel):
    columns = [
        "Rank",
        "Key",
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

    def _get_current_user_data(self):
        return self.user_tab.user_tabs.get(self.user_id)

    def _get_current_user_name(self):
        user_data = self._get_current_user_data()
        return user_data.get("user_name") if user_data else None

    def _normalize_key(self, key):
        if not key:
            return ""
        return re.sub(r"[^a-z0-9]", "", key.lower())

    def _looks_like_location(self, row_location, requested_location):
        if not requested_location or requested_location == "Auto":
            return True
        return (row_location or "").upper() == requested_location.upper()

    def _fetch_candidates(self, key, requested_location):
        normalized = self._normalize_key(key)
        sql = "SELECT api_signature, param_name, param_value, location, user_identifier, risk_score, llm_analysis_result FROM parameter_pool"
        rows = self.extender.db_manager.fetch_all(sql)
        candidates = []
        current_user_name = self._get_current_user_name()

        for row in rows or []:
            api_signature, param_name, param_value, location, source_user, risk_score, llm_analysis_result = row
            if not param_name or not param_value or not source_user:
                continue
            if current_user_name and str(source_user).strip().lower() == str(current_user_name).strip().lower():
                continue
            if not self._looks_like_location(location, requested_location):
                continue

            exact = str(param_name).strip().lower() == str(key).strip().lower()
            normalized_match = self._normalize_key(param_name) == normalized
            if not exact and not normalized_match:
                continue

            method = ""
            endpoint = api_signature or ""
            if api_signature and " " in api_signature:
                try:
                    method, endpoint = api_signature.split(" ", 1)
                except Exception:
                    pass

            score = int(risk_score or 0)
            if exact:
                score += 50
            elif normalized_match:
                score += 30
            if location and requested_location != "Auto" and location.upper() == requested_location.upper():
                score += 10

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
                "llm_analysis_result": llm_analysis_result,
            })

        candidates.sort(key=lambda x: x.get("score", 0), reverse=True)
        return candidates[:10]

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
            body_text = self.extender._helpers.bytesToString(body) if body else ""

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
            response_body_text = self.extender._helpers.bytesToString(response_body) if response_body else ""
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

        return best

    def _build_reason(self, candidate):
        location = candidate.get("location") or "UNKNOWN"
        endpoint = candidate.get("endpoint") or candidate.get("api_signature") or ""
        return "Matched {} candidate from {} traffic on {}".format(
            location, candidate.get("source_user", "unknown"), endpoint
        )

    def _rerank_with_llm(self, key, location, candidates):
        if not candidates:
            return candidates
        if not hasattr(self.extender, 'enableLlm') or not self.extender.enableLlm.isSelected():
            return candidates
        if not self.useLlmCheck.isSelected():
            return candidates

        try:
            llm = LLMHelper(
                self.extender.llmBaseUrl.getText(),
                self.extender.llmApiKey.getText(),
                self.extender.llmModel.getText(),
            )
            prompt_candidates = []
            for idx, candidate in enumerate(candidates):
                prompt_candidates.append({
                    "index": idx,
                    "key": key,
                    "value": candidate.get("value"),
                    "source_user": candidate.get("source_user"),
                    "location": candidate.get("location"),
                    "endpoint": candidate.get("endpoint"),
                    "score": candidate.get("score"),
                })

            prompt = """You are helping rank candidate parameter values for authorization/IDOR testing.
Given a target key and up to 10 candidates, return ONLY a JSON list of up to 3 objects.
Each object must contain:
- index: the candidate index from input
- score: integer 0-100
- reason: concise reason mentioning source user when helpful

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
                return results[:3]
        except Exception as e:
            print("[Param Recommender] LLM rerank failed: " + str(e))

        return candidates[:3]

    def recommend(self, event):
        key = self.keyField.getText().strip()
        if not key:
            self.statusLabel.setText("Please enter a key to test.")
            return

        location = str(self.locationCombo.getSelectedItem())
        self.statusLabel.setText("Searching parameter pool...")
        candidates = self._fetch_candidates(key, location)
        if not candidates:
            self.table_model.set_rows([])
            self.selected_row = None
            self.sourceUserLabel.setText("Source User: -")
            self.request_viewer.setMessage(None, True)
            self.response_viewer.setMessage(None, False)
            self.statusLabel.setText("No candidate values found in parameter_pool.")
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

        if not enriched:
            self.table_model.set_rows([])
            self.statusLabel.setText("Candidates found, but no source request/response evidence was matched.")
            return

        ranked = self._rerank_with_llm(key, location, enriched)
        if not ranked:
            ranked = enriched[:3]
        ranked = ranked[:3]
        for idx, row in enumerate(ranked):
            row["rank"] = idx + 1
        self.table_model.set_rows(ranked)
        self.statusLabel.setText("Found {} recommendations.".format(len(ranked)))
        if len(ranked) > 0:
            self.table.setRowSelectionInterval(0, 0)
            self.on_selection_change()

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
