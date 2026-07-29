#!/usr/bin/env python
# -*- coding: utf-8 -*-

from java.lang import Throwable
from javax.swing import (
    JPanel,
    JSplitPane,
    JTabbedPane,
    JScrollPane,
    JTable,
    JButton,
    JLabel,
    ListSelectionModel,
    SwingUtilities,
    JTextArea,
    JTextField,
    JCheckBox,
    JPopupMenu,

    JMenuItem,
)
from javax.swing.table import (
    AbstractTableModel,
    DefaultTableCellRenderer,
    TableRowSorter,
)
from java.awt import BorderLayout, FlowLayout, Color, Dimension, Font
from java.awt.event import ActionListener, MouseAdapter, MouseMotionAdapter
from burp import IMessageEditorController
import json
from java.util import ArrayList
from threading import Thread


class IDORAttackTableModel(AbstractTableModel):
    def __init__(self):
        self.column_names = [
            "ID",
            "Method",
            "Path",
            "Status",
            "Code",
            "Risk",
            "LLM Result",
            "Description",
        ]
        self.attacks = []

    def getColumnCount(self):
        return len(self.column_names)

    def getRowCount(self):
        return len(self.attacks)

    def getColumnName(self, col):
        return self.column_names[col]

    def getValueAt(self, row, col):
        if row >= len(self.attacks):
            return ""
        attack = self.attacks[row]
        # attack tuple: (id, method, path, status, response_code, vulnerability_score, llm_result, description)
        if col == 0:
            return attack[0]
        if col == 1:
            return attack[1]
        if col == 2:
            return attack[2]
        if col == 3:
            return attack[3]
        if col == 4:
            return str(attack[4]) if attack[4] else ""
        if col == 5:
            return str(attack[5])
        if col == 6:
            try:
                if attack[6]:
                    res = json.loads(attack[6])
                    result = res.get("result", "")
                    confidence = res.get("confidence", None)
                    if confidence is not None:
                        try:
                            return "{} ({:.0f}%)".format(result, float(confidence) * 100)
                        except Exception:
                            return str(result)
                    return result
            except:
                pass
            return ""
        if col == 7:
            return attack[7]
        return ""

    def set_attacks(self, attacks):
        self.attacks = attacks
        self.fireTableDataChanged()


class RiskRenderer(DefaultTableCellRenderer):
    def __init__(self, panel):
        self.panel = panel

    def getTableCellRendererComponent(
        self, table, value, isSelected, hasFocus, row, column
    ):
        c = super(RiskRenderer, self).getTableCellRendererComponent(
            table, value, isSelected, hasFocus, row, column
        )

        model = table.getModel()
        try:
            model_row = table.convertRowIndexToModel(row)

            # Default colors
            fg_color = Color.BLACK
            bg_color = table.getBackground()

            # Check if verified (deep green background)
            attack_id = model.getValueAt(model_row, 0)
            is_verified = self.panel.is_attack_verified(attack_id)
            if is_verified:
                bg_color = Color(0, 150, 0)  # Deep Green for verified
                fg_color = Color.WHITE

            # 1. Check for Status (Column 3) specific coloring (only if not verified)
            if not is_verified:
                status = model.getValueAt(model_row, 3)
                if status == "VULNERABLE":
                    bg_color = Color(255, 200, 200)  # Light Red
                elif status == "SAFE":
                    bg_color = Color(200, 255, 200)  # Light Green
                elif status == "SENT":
                    bg_color = Color(255, 255, 200)  # Light Yellow

            # 2. Check for Sensitive API (Risk)
            method = model.getValueAt(model_row, 1)
            path = model.getValueAt(model_row, 2)
            is_sensitive = self.panel.is_sensitive_api(method, path)

            if is_sensitive:
                fg_color = Color(184, 134, 11)
                if not isSelected:
                    # Make font bold for sensitive? Font handling is tricky in renderer reusing component.
                    # Just stick to dark yellow text.
                    pass

            # Set Tooltip for Description (Column 7)
            if column == 7:
                description = model.getValueAt(model_row, 7)
                if description:
                    description = str(description)
                    lower_description = description.lower()
                    marker = "swap params"
                    marker_pos = lower_description.find(marker)
                    if marker_pos != -1:
                        description = description[marker_pos:]
                    if len(description) > 400:
                        description = description[:400] + "..."
                    c.setToolTipText(description)
                else:
                    c.setToolTipText(None)
            else:
                c.setToolTipText(None)

            if isSelected:
                c.setBackground(table.getSelectionBackground())
                c.setForeground(table.getSelectionForeground())
                if is_sensitive:
                    c.setForeground(Color(218, 165, 32))
            else:
                c.setBackground(bg_color)
                c.setForeground(fg_color)

        except:
            # Fallback for unexpected errors
            c.setBackground(table.getBackground())
            c.setForeground(Color.BLACK)

        return c


class IDORAttackPanel(JPanel, IMessageEditorController):
    class TableTooltipMouseListener(MouseMotionAdapter):
        def __init__(self, panel):
            self.panel = panel

        def _escape_html(self, text):
            return (
                text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
            )

        def mouseMoved(self, event):
            table = self.panel.table
            point = event.getPoint()
            row = table.rowAtPoint(point)
            col = table.columnAtPoint(point)

            if row < 0 or col < 0:
                table.setToolTipText(None)
                return

            model_row = table.convertRowIndexToModel(row)
            model_col = table.convertColumnIndexToModel(col)
            value = self.panel.table_model.getValueAt(model_row, model_col)

            if model_col == 2 and value:
                path_text = str(value)
                if len(path_text) > 300:
                    path_text = path_text[:300] + "..."
                table.setToolTipText(self._escape_html(path_text))
            elif model_col == 7 and value:
                description = str(value)
                lower_description = description.lower()
                marker = "swap params"
                marker_pos = lower_description.find(marker)
                if marker_pos != -1:
                    description = description[marker_pos:]
                if len(description) > 400:
                    description = description[:400] + "..."
                table.setToolTipText(
                    self._escape_html(description).replace("\n", " &#10; ")
                )
            else:
                table.setToolTipText(None)

    def __init__(self, extender):
        print("[IDOR] ========== IDORAttackPanel.__init__ CALLED ==========")
        print("[IDOR] Extender object: " + str(extender))
        self.extender = extender
        self.layout = BorderLayout()
        print("[IDOR] Layout created")

        # Top Bar (Controls)
        self.top_panel = JPanel(FlowLayout(FlowLayout.LEFT))

        self.hidden_param_enabled = JCheckBox("Hidden Query Param")
        self.hidden_param_key = JTextField(16)
        self.hidden_param_a_value = JTextArea(2, 14)
        self.hidden_param_a_value.setLineWrap(True)
        self.hidden_param_a_value.setWrapStyleWord(True)
        self.hidden_param_b_value = JTextArea(2, 14)
        self.hidden_param_b_value.setLineWrap(True)
        self.hidden_param_b_value.setWrapStyleWord(True)
        self.hidden_param_a_scroll = JScrollPane(self.hidden_param_a_value)
        self.hidden_param_a_scroll.setPreferredSize(Dimension(150, 42))
        self.hidden_param_b_scroll = JScrollPane(self.hidden_param_b_value)
        self.hidden_param_b_scroll.setPreferredSize(Dimension(150, 42))
        self.hidden_param_apply_existing = JCheckBox("Apply on execute")
        self.hidden_param_apply_existing.setSelected(True)

        self.btn_refresh = JButton("Refresh", actionPerformed=self.refresh_table)
        self.btn_generate = JButton(
            "Generate Attacks", actionPerformed=self.generate_attacks
        )
        self.btn_execute = JButton(
            "Execute Selected", actionPerformed=self.execute_selected
        )
        self.btn_batch_get = JButton(
            "Batch Attack GET", actionPerformed=self.batch_attack_get
        )
        self.btn_clear = JButton("Clear", actionPerformed=self.clear_attacks)

        self.top_panel.add(self.btn_refresh)
        self.top_panel.add(self.btn_generate)
        self.top_panel.add(self.btn_execute)
        self.top_panel.add(self.btn_batch_get)
        self.top_panel.add(self.btn_clear)
        self.top_panel.add(JLabel(" | Hidden Query Param only (headers/body/path/query user rules are managed in Users):"))
        self.top_panel.add(self.hidden_param_enabled)
        self.top_panel.add(JLabel("Key"))
        self.top_panel.add(self.hidden_param_key)
        self.top_panel.add(JLabel("A"))
        self.top_panel.add(self.hidden_param_a_scroll)
        self.top_panel.add(JLabel("B"))
        self.top_panel.add(self.hidden_param_b_scroll)
        self.top_panel.add(self.hidden_param_apply_existing)
        self.top_panel.add(
            JLabel(
                " | Sensitive APIs (POST/PUT/DELETE) are highlighted in dark yellow and require manual execution."
            )
        )

        self.add(self.top_panel, BorderLayout.NORTH)
        print("[IDOR] Top panel created and added")

        # Main Split Pane
        self.split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self.add(self.split_pane, BorderLayout.CENTER)
        print("[IDOR] Split pane created")

        # Left: Table
        print("[IDOR] Creating table model...")
        self.table_model = IDORAttackTableModel()
        print("[IDOR] Creating JTable...")
        self.table = JTable(self.table_model)
        print("[IDOR] JTable created")
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        # Add selection listener with explicit logging
        print("[IDOR] Registering selection listener for table...")
        selection_model = self.table.getSelectionModel()
        print("[IDOR] Selection model: " + str(selection_model))
        selection_model.addListSelectionListener(lambda e: self.on_selection_change(e))
        print("[IDOR] Selection listener registered successfully")

        # Sorting
        self.sorter = TableRowSorter(self.table_model)
        self.table.setRowSorter(self.sorter)

        # Renderer
        for i in range(self.table.getColumnCount()):
            renderer = RiskRenderer(self)
            self.table.getColumnModel().getColumn(i).setCellRenderer(renderer)

        # Tooltip preview for Path and Description columns
        self.table.addMouseMotionListener(self.TableTooltipMouseListener(self))

        # Set Tooltip for Description Column (Index 7)
        # Note: RiskRenderer needs to handle tooltip.

        # Add right-click menu
        self.setup_context_menu()

        self.scroll_pane = JScrollPane(self.table)
        self.split_pane.setLeftComponent(self.scroll_pane)

        # Right: Details Area (Vertical Split)
        self.details_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.split_pane.setRightComponent(self.details_split_pane)

        # Top Panel: Attack Request, Attack Response, Diff
        print("[IDOR] Creating top tabs...")
        self.top_tabs = JTabbedPane()

        print("[IDOR] Creating message editors...")
        self.request_editor = self.extender._callbacks.createMessageEditor(self, False)
        print("[IDOR] Request editor created")
        self.response_editor = self.extender._callbacks.createMessageEditor(self, False)
        print("[IDOR] Response editor created")

        self.diff_text = JTextArea()
        self.diff_text.setEditable(False)
        self.diff_text.setFont(Font("Monospaced", Font.PLAIN, 12))

        self.top_tabs.addTab("Attack Request", self.request_editor.getComponent())
        self.top_tabs.addTab("Attack Response", self.response_editor.getComponent())
        self.top_tabs.addTab("Diff", JScrollPane(self.diff_text))

        self.details_split_pane.setTopComponent(self.top_tabs)

        # Bottom Panel: Original Request, Original Response
        self.bottom_tabs = JTabbedPane()

        self.original_request_editor = self.extender._callbacks.createMessageEditor(
            self, False
        )
        self.original_response_editor = self.extender._callbacks.createMessageEditor(
            self, False
        )

        self.bottom_tabs.addTab(
            "Original Request", self.original_request_editor.getComponent()
        )
        self.bottom_tabs.addTab(
            "Original Response", self.original_response_editor.getComponent()
        )

        self.details_split_pane.setBottomComponent(self.bottom_tabs)

        # Current selection data
        self.current_request = None
        self.current_response = None
        self.current_original_request = None
        self.current_original_response = None
        self.current_http_service = None
        self.verified_cache = {}
        self.api_risk_cache = {}

        self.split_pane.setDividerLocation(600)
        self.details_split_pane.setDividerLocation(300)

        print("[IDOR] ========== IDORAttackPanel.__init__ COMPLETED ==========")
        print("[IDOR] Panel fully initialized and ready")

    def _build_hidden_param_config(self, target_user=None):
        try:
            if not hasattr(self, "hidden_param_enabled") or not self.hidden_param_enabled.isSelected():
                return None

            key = self.hidden_param_key.getText().strip() if hasattr(self, "hidden_param_key") else ""
            if not key:
                return None

            a_value = self.hidden_param_a_value.getText() if hasattr(self, "hidden_param_a_value") else ""
            b_value = self.hidden_param_b_value.getText() if hasattr(self, "hidden_param_b_value") else ""

            selected_value = a_value
            a_user = self._get_primary_user_name()
            b_user = self._get_secondary_user_name()
            if target_user:
                target_user_l = str(target_user).strip().lower()
                if b_user and target_user_l == b_user.lower():
                    selected_value = b_value
                elif a_user and target_user_l == a_user.lower():
                    selected_value = a_value
                elif b_value and not a_value:
                    selected_value = b_value

            return {
                "enabled": True,
                "key": key,
                "a_user": a_user,
                "b_user": b_user,
                "a_value": a_value,
                "b_value": b_value,
                "value": selected_value,
                "location": "QUERY",
            }
        except Exception:
            return None

    def _get_primary_user_name(self):
        try:
            if hasattr(self.extender, "userTab") and self.extender.userTab:
                user_ids = sorted(self.extender.userTab.user_tabs.keys())
                if user_ids:
                    return self.extender.userTab.user_tabs[user_ids[0]]["user_name"]
        except Exception:
            pass
        return None

    def _get_secondary_user_name(self):
        try:
            if hasattr(self.extender, "userTab") and self.extender.userTab:
                user_ids = sorted(self.extender.userTab.user_tabs.keys())
                if len(user_ids) > 1:
                    return self.extender.userTab.user_tabs[user_ids[1]]["user_name"]
        except Exception:
            pass
        return None

    def _collect_hidden_param_state(self):
        return {
            "enabled": bool(
                hasattr(self, "hidden_param_enabled") and self.hidden_param_enabled.isSelected()
            ),
            "key": self.hidden_param_key.getText() if hasattr(self, "hidden_param_key") else "",
            "a_value": self.hidden_param_a_value.getText() if hasattr(self, "hidden_param_a_value") else "",
            "b_value": self.hidden_param_b_value.getText() if hasattr(self, "hidden_param_b_value") else "",
            "apply_on_execute": bool(
                hasattr(self, "hidden_param_apply_existing")
                and self.hidden_param_apply_existing.isSelected()
            ),
        }

    def _restore_hidden_param_state(self, state):
        if not state:
            return
        try:
            if hasattr(self, "hidden_param_enabled"):
                self.hidden_param_enabled.setSelected(bool(state.get("enabled", False)))
            if hasattr(self, "hidden_param_key"):
                self.hidden_param_key.setText(state.get("key", ""))
            if hasattr(self, "hidden_param_a_value"):
                self.hidden_param_a_value.setText(state.get("a_value", ""))
            if hasattr(self, "hidden_param_b_value"):
                self.hidden_param_b_value.setText(state.get("b_value", ""))
            if hasattr(self, "hidden_param_apply_existing"):
                self.hidden_param_apply_existing.setSelected(bool(state.get("apply_on_execute", True)))
        except Exception:
            pass

    def _is_apply_hidden_param_on_execute(self):
        return bool(
            hasattr(self, "hidden_param_apply_existing")
            and self.hidden_param_apply_existing.isSelected()
        )

    def _get_api_signature(self, method, path):
        try:
            if hasattr(self.extender, "extractor"):
                return self.extender.extractor._get_api_signature(method, path)
        except Exception:
            pass
        return None

    def _preload_attack_metadata(self, rows):
        self.verified_cache = {}
        self.api_risk_cache = {}

        if not rows:
            return

        api_signatures = set()
        for row in rows:
            attack_id = row[0]
            method = row[1]
            path = row[2]
            verified = bool(row[8]) if len(row) > 8 else False
            self.verified_cache[attack_id] = verified

            api_sig = self._get_api_signature(method, path)
            if api_sig:
                api_signatures.add(api_sig)

        if not api_signatures or not hasattr(self.extender, "db_manager"):
            return

        signatures_sql = ", ".join(
            ["'{}'".format(sig.replace("'", "''")) for sig in api_signatures]
        )
        sql = (
            "SELECT api_signature, is_sensitive FROM api_metadata WHERE api_signature IN ({})".format(
                signatures_sql
            )
        )

        try:
            metadata_rows = self.extender.db_manager.fetch_all(sql)
            if metadata_rows is None:
                # 查询失败：不更新 cache，保留默认值（False）
                pass
            else:
                for api_signature, is_sensitive in metadata_rows:
                    self.api_risk_cache[api_signature] = bool(is_sensitive)
        except Exception:
            pass

        for api_signature in api_signatures:
            if api_signature not in self.api_risk_cache:
                self.api_risk_cache[api_signature] = False

    def is_attack_verified(self, attack_id):
        return self.verified_cache.get(attack_id, False)

    def is_sensitive_api(self, method, path):
        is_sensitive = False

        if method in ["POST", "PUT", "DELETE", "PATCH"]:
            is_sensitive = True

        if path and any(
            x in path.lower()
            for x in [
                "delete",
                "remove",
                "update",
                "modify",
                "add",
                "create",
                "change",
            ]
        ):
            is_sensitive = True

        api_sig = self._get_api_signature(method, path)
        if api_sig and self.api_risk_cache.get(api_sig, False):
            is_sensitive = True

        return is_sensitive

    def setup_context_menu(self):
        """Setup right-click context menu for the table"""
        popup_menu = JPopupMenu()

        mark_verified_item = JMenuItem("Mark as Verified")
        mark_verified_item.addActionListener(lambda e: self.mark_as_verified())
        popup_menu.add(mark_verified_item)

        unmark_verified_item = JMenuItem("Unmark Verified")
        unmark_verified_item.addActionListener(lambda e: self.unmark_verified())
        popup_menu.add(unmark_verified_item)

        delete_item = JMenuItem("Delete")
        delete_item.addActionListener(lambda e: self.delete_selected_attack())
        popup_menu.add(delete_item)

        # Add mouse listener to show popup
        class PopupListener(MouseAdapter):
            def __init__(self, panel, popup):
                self.panel = panel
                self.popup = popup

            def mousePressed(self, event):
                self.showPopup(event)

            def mouseReleased(self, event):
                self.showPopup(event)

            def showPopup(self, event):
                if event.isPopupTrigger():
                    row = self.panel.table.rowAtPoint(event.getPoint())
                    if row >= 0:
                        self.panel.table.setRowSelectionInterval(row, row)
                        self.popup.show(
                            event.getComponent(), event.getX(), event.getY()
                        )

        self.table.addMouseListener(PopupListener(self, popup_menu))

    def mark_as_verified(self):
        """Mark selected attack as verified"""
        selected_row = self.table.getSelectedRow()
        if selected_row == -1:
            return

        model_row = self.table.convertRowIndexToModel(selected_row)
        attack_id = self.table_model.getValueAt(model_row, 0)

        if hasattr(self.extender, "db_manager"):
            self.extender.db_manager.execute_query(
                "UPDATE attack_queue SET verified = 1 WHERE id = " + str(attack_id)
            )
            self.refresh_table()

    def unmark_verified(self):
        """Unmark selected attack as verified"""
        selected_row = self.table.getSelectedRow()
        if selected_row == -1:
            return

        model_row = self.table.convertRowIndexToModel(selected_row)
        attack_id = self.table_model.getValueAt(model_row, 0)

        if hasattr(self.extender, "db_manager"):
            self.extender.db_manager.execute_query(
                "UPDATE attack_queue SET verified = 0 WHERE id = " + str(attack_id)
            )
            self.refresh_table()

    def delete_selected_attack(self):
        """Delete selected attack from attack queue"""
        selected_row = self.table.getSelectedRow()
        if selected_row == -1:
            return

        model_row = self.table.convertRowIndexToModel(selected_row)
        attack_id = self.table_model.getValueAt(model_row, 0)

        if hasattr(self.extender, "db_manager"):
            self.extender.db_manager.execute_query(
                "DELETE FROM attack_queue WHERE id = " + str(attack_id)
            )
            self.refresh_table()

            if self.table_model.getRowCount() == 0:
                self.table.clearSelection()
                self.diff_text.setText("")
                self.request_editor.setMessage(None, True)
                self.response_editor.setMessage(None, False)
                self.original_request_editor.setMessage(None, True)
                self.original_response_editor.setMessage(None, False)
            else:
                new_row = min(model_row, self.table_model.getRowCount() - 1)
                view_row = self.table.convertRowIndexToView(new_row)
                if view_row != -1:
                    self.table.setRowSelectionInterval(view_row, view_row)

    def refresh_table(self, event=None):
        # Fetch attacks from DB including verified status
        sql = """
        SELECT a.id, r.method, r.path, a.status, a.response_code, a.vulnerability_score, a.llm_verification_result, a.payload_description, a.verified
        FROM attack_queue a 
        JOIN raw_requests r ON a.original_request_id = r.id
        ORDER BY a.verified DESC, a.id DESC
        """

        # DB 读移到后台线程，避免阻塞 EDT
        def fetch_and_update():
            rows = None
            if hasattr(self.extender, "db_manager"):
                rows = self.extender.db_manager.fetch_all(sql)
                # rows is None 表示查询失败：不要清空表格，保留上次数据
                if rows is None:
                    print("[GUI] refresh_table: fetch failed, keep existing data")
                    return
                self._preload_attack_metadata(rows)
            else:
                rows = []
            # 更新表格必须回到 EDT（set_attacks -> fireTableDataChanged 必须在 EDT 上）
            SwingUtilities.invokeLater(lambda r=rows: self.table_model.set_attacks(r))

        if hasattr(self.extender, "executor"):
            self.extender.executor.submit(fetch_and_update)
        else:
            # 兜底：没有线程池时退回直接执行
            fetch_and_update()

    def generate_attacks(self, event):
        # Trigger generation in background
        def run():
            if hasattr(self.extender, "attack_engine"):
                hidden_param_config = self._build_hidden_param_config()
                created_count = self.extender.attack_engine.generate_attacks(hidden_param_config)
                if created_count == 0:
                    try:
                        rows = self.extender.db_manager.fetch_all(
                            "SELECT COUNT(DISTINCT user_identifier) FROM parameter_pool WHERE user_identifier IS NOT NULL AND user_identifier != ''"
                        )
                        if rows and int(rows[0][0] or 0) == 1:
                            message = "参数池只识别到一个用户，请检查是否填错了cookie导致没有识别到用户，或者是没有抓到另一个用户的流量？"
                            print(message)
                            if hasattr(self.extender, "progressBar"):
                                SwingUtilities.invokeLater(
                                    lambda: self.extender.progressBar.setString(message)
                                )
                                SwingUtilities.invokeLater(
                                    lambda: self.extender.progressBar.setStringPainted(True)
                                )
                    except Exception:
                        pass
                SwingUtilities.invokeLater(lambda: self.refresh_table())

        t = Thread(target=run)
        t.start()

    def execute_selected(self, event):
        selected_row = self.table.getSelectedRow()
        if selected_row == -1:
            return

        model_row = self.table.convertRowIndexToModel(selected_row)
        attack_id = self.table_model.getValueAt(model_row, 0)

        # Log selection
        print(
            "[IDOR] Execute Selected clicked. Row: {}, Model Row: {}, Attack ID: {}".format(
                selected_row, model_row, attack_id
            )
        )

        def run():
            if hasattr(self.extender, "attack_engine"):
                # Prepare LLM config
                llm_config = {
                    "enabled": self.extender.enableLlm.isSelected(),
                    "base_url": self.extender.llmBaseUrl.getText(),
                    "api_key": self.extender.llmApiKey.getText(),
                    "model": self.extender.llmModel.getText(),
                    "analyze_result": self.extender.llmAnalyzeResult.isSelected(),
                    "verify_ssl": not self.extender.llmDisableSslVerification.isSelected()
                    if hasattr(self.extender, "llmDisableSslVerification")
                    else True,
                }

                # Show progress
                if hasattr(self.extender, "progressBar"):
                    SwingUtilities.invokeLater(
                        lambda: self.extender.progressBar.setIndeterminate(True)
                    )
                    SwingUtilities.invokeLater(
                        lambda: self.extender.progressBar.setString(
                            "Executing Attack ID {}...".format(attack_id)
                        )
                    )
                    SwingUtilities.invokeLater(
                        lambda: self.extender.progressBar.setStringPainted(True)
                    )

                print("[IDOR] Launching execution for Attack ID: {}".format(attack_id))
                result = self.extender.attack_engine.execute_attack(
                    attack_id,
                    self.extender._callbacks,
                    self.extender._helpers,
                    llm_config,
                    self._build_hidden_param_config(),
                    self._is_apply_hidden_param_on_execute(),
                )

                # Clear progress
                if hasattr(self.extender, "progressBar"):
                    SwingUtilities.invokeLater(
                        lambda: self.extender.progressBar.setIndeterminate(False)
                    )
                    SwingUtilities.invokeLater(
                        lambda: self.extender.progressBar.setString(
                            "Execution Complete"
                        )
                    )

                    def reset():
                        import time

                        time.sleep(2)
                        if hasattr(self.extender, "progressBar"):
                            SwingUtilities.invokeLater(
                                lambda: self.extender.progressBar.setString("")
                            )
                            SwingUtilities.invokeLater(
                                lambda: self.extender.progressBar.setStringPainted(
                                    False
                                )
                            )

                    # Simple async reset if possible, or just leave it
                    t_reset = Thread(target=reset)
                    t_reset.start()

                def update_ui():
                    # 1. Refresh table data
                    self.refresh_table()

                    # 2. Restore selection (Find row with attack_id)
                    try:
                        found = False
                        for model_idx in range(self.table_model.getRowCount()):
                            current_id = self.table_model.getValueAt(model_idx, 0)
                            if current_id == attack_id:
                                # Found the row in model, convert to view
                                view_idx = self.table.convertRowIndexToView(model_idx)
                                if view_idx != -1:
                                    self.table.setRowSelectionInterval(
                                        view_idx, view_idx
                                    )
                                    # Scroll to visible
                                    self.table.scrollRectToVisible(
                                        self.table.getCellRect(view_idx, 0, True)
                                    )
                                    found = True
                                break

                        if not found:
                            print(
                                "[IDOR] Could not restore selection for Attack ID: "
                                + str(attack_id)
                            )
                    except Exception as e:
                        print("[IDOR] Error restoring selection: " + str(e))

                SwingUtilities.invokeLater(update_ui)

        t = Thread(target=run)
        t.start()

    def clear_attacks(self, event):
        if hasattr(self.extender, "db_manager"):
            self.extender.db_manager.execute_query("DELETE FROM attack_queue")
            self.refresh_table()

    def batch_attack_get(self, event):
        """
        Batch execute all GET method attacks that are in PENDING status.
        """

        def run():
            if not hasattr(self.extender, "attack_engine") or not hasattr(
                self.extender, "db_manager"
            ):
                print("[Batch Attack] Attack engine or DB manager not initialized.")
                return

            # Prepare LLM config
            llm_config = {
                "enabled": self.extender.enableLlm.isSelected()
                if hasattr(self.extender, "enableLlm")
                else False,
                "base_url": self.extender.llmBaseUrl.getText()
                if hasattr(self.extender, "llmBaseUrl")
                else "",
                "api_key": self.extender.llmApiKey.getText()
                if hasattr(self.extender, "llmApiKey")
                else "",
                "model": self.extender.llmModel.getText()
                if hasattr(self.extender, "llmModel")
                else "",
                "analyze_result": self.extender.llmAnalyzeResult.isSelected()
                if hasattr(self.extender, "llmAnalyzeResult")
                else False,
                "verify_ssl": not self.extender.llmDisableSslVerification.isSelected()
                if hasattr(self.extender, "llmDisableSslVerification")
                else True,
            }


            if hasattr(self.extender, "progressBar"):
                SwingUtilities.invokeLater(
                    lambda: self.extender.progressBar.setIndeterminate(True)
                )
                SwingUtilities.invokeLater(
                    lambda: self.extender.progressBar.setString(
                        "Executing up to 50 GET attacks..."
                    )
                )
                SwingUtilities.invokeLater(
                    lambda: self.extender.progressBar.setStringPainted(True)
                )

            try:
                summary_data = self.extender.attack_engine.execute_pending_get_attacks(
                    self.extender._callbacks,
                    self.extender._helpers,
                    llm_config,
                    50,
                    self._build_hidden_param_config(),
                    self._is_apply_hidden_param_on_execute(),
                )

                total = summary_data.get("total", 0)
                success_count = summary_data.get("success", 0)
                vulnerable_count = summary_data.get("vulnerable", 0)
                failed_count = summary_data.get("failed", 0)

                if total == 0:
                    summary = "No GET attacks to execute"
                else:
                    summary = "Batch Attack Complete: {}/{} executed, {} vulnerable, {} failed".format(
                        success_count, total, vulnerable_count, failed_count
                    )

                print("[Batch Attack] " + summary)

                if hasattr(self.extender, "progressBar"):
                    SwingUtilities.invokeLater(
                        lambda s=summary: self.extender.progressBar.setIndeterminate(False)
                    )
                    SwingUtilities.invokeLater(
                        lambda s=summary: self.extender.progressBar.setString(s)
                    )
            finally:
                # Refresh table
                SwingUtilities.invokeLater(lambda: self.refresh_table())

        # Run in background thread
        t = Thread(target=run)
        t.start()

    def on_selection_change(self, event):
        try:
            # Log event entry
            print("[IDOR] ========== on_selection_change TRIGGERED ==========")
            print("[IDOR] Event object: " + str(event))
            print("[IDOR] Event type: " + str(type(event)))

            # Ignore valueIsAdjusting events to avoid double updates?
            # Let's log if we skip
            if event and event.getValueIsAdjusting():
                print("[IDOR] Skipping on_selection_change (adjusting)")
                return  # Actually skip to avoid double processing

            selected_row = self.table.getSelectedRow()
            print("[IDOR] on_selection_change. Selected row: " + str(selected_row))
            print(
                "[IDOR] Table model row count: " + str(self.table_model.getRowCount())
            )

            # Reset state immediately
            self.current_request = None
            self.current_response = None
            self.current_original_request = None
            self.current_original_response = None
            self.diff_text.setText("")

            # Clear editors first
            try:
                empty_msg = self.extender._helpers.stringToBytes("")
                if self.request_editor:
                    self.request_editor.setMessage(empty_msg, False)
                if self.response_editor:
                    self.response_editor.setMessage(empty_msg, False)
                if self.original_request_editor:
                    self.original_request_editor.setMessage(empty_msg, False)
                if self.original_response_editor:
                    self.original_response_editor.setMessage(empty_msg, False)
            except Exception as e_clear:
                print("[IDOR] Error clearing editors: " + str(e_clear))

            if selected_row == -1:
                return

            model_row = self.table.convertRowIndexToModel(selected_row)
            print("[IDOR] Converted to model row: " + str(model_row))

            attack_id = self.table_model.getValueAt(model_row, 0)
            print("[IDOR] Fetching details for Attack ID: " + str(attack_id))

            # Fetch details
            sql = (
                "SELECT request_data, executed_request_data, response_data, original_request_id, payload_description, llm_verification_result FROM attack_queue WHERE id = "
                + str(attack_id)
            )
            print("[IDOR] Executing SQL: " + sql)
            rows = self.extender.db_manager.fetch_all(sql)
            print("[IDOR] Query returned {} rows".format(len(rows) if rows else 0))

            if rows and len(rows) > 0:
                req_data_json, executed_req_data, res_data, orig_req_id, description, llm_result_json = (
                    rows[0]
                )
                print("[IDOR] Data fetched. Orig Req ID: " + str(orig_req_id))

                # Reconstruct request for display with parameter change annotations
                try:
                    if executed_req_data:
                        if isinstance(executed_req_data, unicode):
                            executed_req_data = executed_req_data.encode("utf-8")
                        self.current_request = executed_req_data
                        print("[IDOR] Using executed_request_data for Attack Request viewer")
                    else:
                        rd = json.loads(req_data_json)
                        print("[IDOR] Parsed request_data JSON successfully")

                        # Get original request data for comparison
                        sql_orig_data = (
                            "SELECT path, query_params, body FROM raw_requests WHERE id = "
                            + str(orig_req_id)
                        )
                        print(
                            "[IDOR] Fetching original request data for comparison, orig_req_id: "
                            + str(orig_req_id)
                        )
                        orig_data_rows = self.extender.db_manager.fetch_all(sql_orig_data)
                        print(
                            "[IDOR] Original data query returned {} rows".format(
                                len(orig_data_rows) if orig_data_rows else 0
                            )
                        )

                        if orig_data_rows and len(orig_data_rows) > 0:
                            orig_path, orig_query_json, orig_body = orig_data_rows[0]
                            print(
                                "[IDOR] Got original data: path={}, query={}, body={}".format(
                                    orig_path[:50] if orig_path else "None",
                                    orig_query_json[:50] if orig_query_json else "None",
                                    orig_body[:50] if orig_body else "None",
                                )
                            )
                            # Reconstruct with annotations (fallback to normal if method doesn't exist)
                            try:
                                if hasattr(self, "_reconstruct_request_with_annotations"):
                                    self.current_request = (
                                        self._reconstruct_request_with_annotations(
                                            rd,
                                            orig_path,
                                            orig_query_json,
                                            orig_body,
                                            description,
                                        )
                                    )
                                    print(
                                        "[IDOR] Used _reconstruct_request_with_annotations"
                                    )
                                else:
                                    print(
                                        "[IDOR] _reconstruct_request_with_annotations not found, using normal reconstruction"
                                    )
                                    self.current_request = (
                                        self.extender.attack_engine.reconstruct_request(
                                            rd, self.extender._helpers
                                        )
                                    )
                            except Exception as e_annot:
                                print(
                                    "[IDOR] Error in _reconstruct_request_with_annotations: "
                                    + str(e_annot)
                                )
                                # Fallback to normal reconstruction
                                self.current_request = (
                                    self.extender.attack_engine.reconstruct_request(
                                        rd, self.extender._helpers
                                    )
                                )
                                print("[IDOR] Used fallback normal reconstruction")
                        else:
                            print(
                                "[IDOR] No original data found, using normal reconstruction"
                            )
                            # Fallback to normal reconstruction
                            self.current_request = (
                                self.extender.attack_engine.reconstruct_request(
                                    rd, self.extender._helpers
                                )
                            )
                except Exception as e:
                    print("[IDOR] Error reconstructing request: " + str(e))
                    import traceback

                    traceback.print_exc()
                    self.current_request = None

                # Attack Response
                if res_data:
                    # print("[IDOR] Response data found (" + str(len(res_data)) + " bytes)")
                    if isinstance(res_data, unicode):
                        res_data = res_data.encode("utf-8")
                    self.current_response = res_data
                else:
                    self.current_response = None

                # Original Request & Response
                print("[IDOR] Fetching original req ID: " + str(orig_req_id))
                sql_orig = (
                    "SELECT headers, body, method, url, response_headers, response_body FROM raw_requests WHERE id = "
                    + str(orig_req_id)
                )
                print("[IDOR] Executing SQL: " + sql_orig)
                orig_rows = self.extender.db_manager.fetch_all(sql_orig)
                print(
                    "[IDOR] Original request query returned {} rows".format(
                        len(orig_rows) if orig_rows else 0
                    )
                )

                if orig_rows and len(orig_rows) > 0:
                    h_json, b, orig_method, orig_url, res_h_json, res_b = orig_rows[0]
                    print(
                        "[IDOR] Original row data: headers={}, body={}, method={}, url={}, res_headers={}, res_body={}".format(
                            "present" if h_json else "None",
                            "present" if b else "None",
                            orig_method,
                            orig_url[:50] if orig_url else "None",
                            "present" if res_h_json else "None",
                            "present" if res_b else "None",
                        )
                    )
                    try:
                        # Request
                        if h_json:
                            print("[IDOR] Parsing original request headers JSON...")
                            h_list = json.loads(h_json)
                            print(
                                "[IDOR] Headers list has {} items".format(len(h_list))
                            )
                            headers = ArrayList()
                            for h in h_list:
                                headers.add(h)
                            if isinstance(b, unicode):
                                b = b.encode("utf-8")
                            elif b is None:
                                b = ""
                            print("[IDOR] Building original HTTP request message...")
                            self.current_original_request = (
                                self.extender._helpers.buildHttpMessage(headers, b)
                            )
                            print(
                                "[IDOR] Original request built successfully, size: {} bytes".format(
                                    len(self.current_original_request)
                                    if self.current_original_request
                                    else 0
                                )
                            )
                        else:
                            print(
                                "[IDOR] Error: Original headers missing for req ID "
                                + str(orig_req_id)
                            )
                            self.current_original_request = None

                        # Response
                        if res_h_json and res_b:
                            print("[IDOR] Parsing original response headers JSON...")
                            res_h_list = json.loads(res_h_json)
                            print(
                                "[IDOR] Response headers list has {} items".format(
                                    len(res_h_list)
                                )
                            )
                            res_headers = ArrayList()
                            for h in res_h_list:
                                res_headers.add(h)
                            if isinstance(res_b, unicode):
                                res_b = res_b.encode("utf-8")
                            elif res_b is None:
                                res_b = ""
                            print("[IDOR] Building original HTTP response message...")
                            self.current_original_response = (
                                self.extender._helpers.buildHttpMessage(
                                    res_headers, res_b
                                )
                            )
                            print(
                                "[IDOR] Original response built successfully, size: {} bytes".format(
                                    len(self.current_original_response)
                                    if self.current_original_response
                                    else 0
                                )
                            )
                        else:
                            print(
                                "[IDOR] Original Response missing for req ID "
                                + str(orig_req_id)
                                + " (res_h_json={}, res_b={})".format(
                                    "present" if res_h_json else "None",
                                    "present" if res_b else "None",
                                )
                            )
                            self.current_original_response = None

                        # Update Diff Tab with detailed parameter changes
                        diff_sb = []
                        diff_sb.append("=== Attack Description ===")
                        diff_sb.append(description)

                        # Parse and display parameter changes in detail
                        diff_sb.append("\n=== Parameter Changes ===")
                        try:
                            # Parse description to extract parameter changes
                            # Format: "Swap params (N): param1=val1->val2, param2=val3->val4"
                            if "Swap params" in description and ":" in description:
                                changes_part = description.split(":", 1)[1].strip()
                                changes = changes_part.split(", ")
                                for change in changes:
                                    if "->" in change:
                                        param_info = change.strip()
                                        diff_sb.append("  " + param_info)
                            else:
                                diff_sb.append("  " + description)
                        except:
                            diff_sb.append("  " + description)

                        # Compare original and attack request data
                        diff_sb.append("\n=== Request Comparison ===")
                        try:
                            rd = json.loads(req_data_json)

                            # Fetch original request data
                            sql_orig_data = (
                                "SELECT path, query_params, body FROM raw_requests WHERE id = "
                                + str(orig_req_id)
                            )
                            orig_data_rows = self.extender.db_manager.fetch_all(
                                sql_orig_data
                            )
                            if orig_data_rows:
                                orig_path, orig_query_json, orig_body = orig_data_rows[
                                    0
                                ]

                                # Compare Path
                                if rd.get("path") != orig_path:
                                    diff_sb.append("Path:")
                                    diff_sb.append("  Original: " + str(orig_path))
                                    diff_sb.append("  Attack:   " + str(rd.get("path")))

                                # Compare Query Parameters
                                try:
                                    orig_query = (
                                        json.loads(orig_query_json)
                                        if orig_query_json
                                        else {}
                                    )
                                    attack_query = rd.get("query_params", {})

                                    changed_params = []
                                    for key in set(
                                        list(orig_query.keys())
                                        + list(attack_query.keys())
                                    ):
                                        orig_val = orig_query.get(key, "")
                                        attack_val = attack_query.get(key, "")
                                        if str(orig_val) != str(attack_val):
                                            changed_params.append(
                                                "  {}:  {} -> {}".format(
                                                    key, orig_val, attack_val
                                                )
                                            )

                                    if changed_params:
                                        diff_sb.append("\nQuery Parameters:")
                                        diff_sb.extend(changed_params)
                                except:
                                    pass

                                # Compare Body
                                try:
                                    if orig_body and orig_body.strip().startswith("{"):
                                        orig_body_json = json.loads(orig_body)
                                        attack_body = rd.get("body", "")
                                        if (
                                            attack_body
                                            and attack_body.strip().startswith("{")
                                        ):
                                            attack_body_json = json.loads(attack_body)

                                            # Flatten and compare
                                            orig_flat = self._flatten_dict(
                                                orig_body_json
                                            )
                                            attack_flat = self._flatten_dict(
                                                attack_body_json
                                            )

                                            changed_body_params = []
                                            for key in set(
                                                list(orig_flat.keys())
                                                + list(attack_flat.keys())
                                            ):
                                                orig_val = orig_flat.get(key, "")
                                                attack_val = attack_flat.get(key, "")
                                                if str(orig_val) != str(attack_val):
                                                    changed_body_params.append(
                                                        "  {}:  {} -> {}".format(
                                                            key, orig_val, attack_val
                                                        )
                                                    )

                                            if changed_body_params:
                                                diff_sb.append("\nBody Parameters:")
                                                diff_sb.extend(changed_body_params)
                                except:
                                    pass
                        except Exception as e_compare:
                            print("[IDOR] Error comparing requests: " + str(e_compare))

                        # Add LLM Result if available
                        if llm_result_json and llm_result_json != "PENDING":
                            try:
                                res = json.loads(llm_result_json)
                                diff_sb.append("\n=== LLM Analysis Result ===")
                                diff_sb.append(
                                    "Result: " + res.get("result", "UNKNOWN")
                                )
                                if res.get("confidence", None) is not None:
                                    try:
                                        diff_sb.append(
                                            "Confidence: {:.0f}%".format(
                                                float(res.get("confidence")) * 100
                                            )
                                        )
                                    except:
                                        diff_sb.append(
                                            "Confidence: " + str(res.get("confidence"))
                                        )
                                diff_sb.append(
                                    "Reason: " + res.get("reason", "No reason provided")
                                )
                            except:
                                diff_sb.append("\n=== LLM Analysis Result (Raw) ===")
                                diff_sb.append(str(llm_result_json))

                        diff_sb.append("\n=== Original Request Line ===")
                        diff_sb.append("{} {}".format(orig_method, orig_url))
                        diff_sb.append("\n=== Attack Request Line ===")
                        # Extract from current_request
                        if self.current_request:
                            req_info = self.extender._helpers.analyzeRequest(
                                self.current_request
                            )
                            # getUrl() fails if service not provided during analysis context sometimes
                            # Safely get path
                            try:
                                diff_sb.append(
                                    "{} {}".format(
                                        req_info.getMethod(),
                                        req_info.getUrl().getFile(),
                                    )
                                )
                            except:
                                # Fallback: parse from bytes
                                try:
                                    first_line = self.extender._helpers.bytesToString(
                                        self.current_request
                                    ).split("\n")[0]
                                    diff_sb.append(first_line)
                                except:
                                    diff_sb.append("Error parsing request line")

                        self.diff_text.setText("\n".join(diff_sb))
                        self.diff_text.setCaretPosition(0)

                    except Exception as e:
                        print("[IDOR] Error building original messages: " + str(e))
                        print("[IDOR] Exception type: " + str(type(e)))
                        import traceback

                        traceback.print_exc()
                        self.current_original_request = None
                        self.current_original_response = None
                else:
                    print(
                        "[IDOR] Original request not found in DB for ID "
                        + str(orig_req_id)
                    )
                    print(
                        "[IDOR] This might indicate a database integrity issue - attack references non-existent original request"
                    )
            else:
                print("[IDOR] Attack details not found in DB for ID " + str(attack_id))
                print("[IDOR] This might indicate:")
                print("[IDOR]   1. Attack was deleted from database")
                print("[IDOR]   2. Database query failed (check logs above)")
                print("[IDOR]   3. Attack ID mismatch in table model")

            # Update editors
            print("[IDOR] Updating editors with data...")

            def update_editors():
                try:
                    empty_msg = self.extender._helpers.stringToBytes("")

                    self.request_editor.setMessage(
                        self.current_request if self.current_request else empty_msg,
                        True,
                    )
                    self.response_editor.setMessage(
                        self.current_response if self.current_response else empty_msg,
                        False,
                    )
                    self.original_request_editor.setMessage(
                        self.current_original_request
                        if self.current_original_request
                        else empty_msg,
                        True,
                    )
                    self.original_response_editor.setMessage(
                        self.current_original_response
                        if self.current_original_response
                        else empty_msg,
                        False,
                    )

                    # Ensure divider location is sane (sometimes it collapses)
                    if self.details_split_pane.getDividerLocation() < 50:
                        self.details_split_pane.setDividerLocation(300)
                except Exception as e_upd:
                    print("[IDOR] Error inside update_editors: " + str(e_upd))

            if SwingUtilities.isEventDispatchThread():
                update_editors()
            else:
                SwingUtilities.invokeLater(update_editors)

            # Update HTTP Service (Host/Port)
            try:
                sql_service = (
                    "SELECT url FROM raw_requests WHERE id = " + str(orig_req_id)
                )
                service_rows = self.extender.db_manager.fetch_all(sql_service)
                if service_rows and service_rows[0][0]:
                    from java.net import URL

                    parsed_url = URL(service_rows[0][0])
                    host = parsed_url.getHost()
                    protocol = parsed_url.getProtocol()
                    port = parsed_url.getPort()
                    if port == -1:
                        port = 443 if protocol.lower() == "https" else 80
                    self.current_http_service = self.extender._helpers.buildHttpService(
                        host, port, protocol
                    )
                else:
                    rd = json.loads(req_data_json)
                    host = rd["host"]
                    self.current_http_service = self.extender._helpers.buildHttpService(
                        host, 80, "http"
                    )
            except:
                pass

        except Exception as e_main:
            print("[IDOR] Critical Exception in on_selection_change: " + str(e_main))
            import traceback

            traceback.print_exc()
        except Throwable as t:
            print("[IDOR] Critical Java Error in on_selection_change: " + str(t))
            t.printStackTrace()

    # IMessageEditorController implementation
    def getHttpService(self):
        return self.current_http_service

    def getRequest(self):
        return self.current_request

    def getResponse(self):
        return self.current_response

    def _flatten_dict(self, d, parent_key="", sep="."):
        """Flatten nested dictionary for comparison"""
        items = []
        if isinstance(d, dict):
            for k, v in d.items():
                new_key = parent_key + sep + k if parent_key else k
                if isinstance(v, dict):
                    items.extend(self._flatten_dict(v, new_key, sep=sep).items())
                elif isinstance(v, list):
                    for i, item in enumerate(v):
                        items.extend(
                            self._flatten_dict(
                                item, new_key + sep + str(i), sep=sep
                            ).items()
                        )
                else:
                    items.append((new_key, v))
        elif isinstance(d, list):
            for i, item in enumerate(d):
                items.extend(
                    self._flatten_dict(item, parent_key + sep + str(i), sep=sep).items()
                )
        else:
            items.append((parent_key, d))
        return dict(items)

    def _reconstruct_request_with_annotations(
        self, request_data, orig_path, orig_query_json, orig_body, description
    ):
        """Reconstruct request - simplified version, just use normal reconstruction"""
        # For now, just use the normal reconstruction method
        # The detailed parameter changes are shown in the Diff panel
        return self.extender.attack_engine.reconstruct_request(
            request_data, self.extender._helpers
        )
