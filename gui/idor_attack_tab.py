#!/usr/bin/env python
# -*- coding: utf-8 -*-

from javax.swing import JPanel, JSplitPane, JTabbedPane, JScrollPane, JTable, JButton, JLabel, ListSelectionModel, SwingUtilities, JTextArea
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer, TableRowSorter
from java.awt import BorderLayout, FlowLayout, Color, Dimension, Font
from java.awt.event import ActionListener
from burp import IMessageEditorController
import json
from java.util import ArrayList
from threading import Thread

class IDORAttackTableModel(AbstractTableModel):
    def __init__(self):
        self.column_names = ["ID", "Method", "Path", "Status", "Code", "Risk", "LLM Result", "Description"]
        self.attacks = []

    def getColumnCount(self):
        return len(self.column_names)

    def getRowCount(self):
        return len(self.attacks)

    def getColumnName(self, col):
        return self.column_names[col]

    def getValueAt(self, row, col):
        if row >= len(self.attacks): return ""
        attack = self.attacks[row]
        # attack tuple: (id, method, path, status, response_code, vulnerability_score, llm_result, description)
        if col == 0: return attack[0]
        if col == 1: return attack[1]
        if col == 2: return attack[2]
        if col == 3: return attack[3]
        if col == 4: return str(attack[4]) if attack[4] else ""
        if col == 5: return str(attack[5])
        if col == 6: 
            try:
                if attack[6]:
                    res = json.loads(attack[6])
                    return res.get("result", "")
            except: pass
            return ""
        if col == 7: return attack[7]
        return ""
    
    def set_attacks(self, attacks):
        self.attacks = attacks
        self.fireTableDataChanged()

class RiskRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = super(RiskRenderer, self).getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        
        model = table.getModel()
        try:
            model_row = table.convertRowIndexToModel(row)
            
            # Default colors
            fg_color = Color.BLACK
            bg_color = table.getBackground()
            
            # 1. Check for Status (Column 3) specific coloring
            status = model.getValueAt(model_row, 3)
            if status == "VULNERABLE":
                bg_color = Color(255, 200, 200) # Light Red
            elif status == "SAFE":
                bg_color = Color(200, 255, 200) # Light Green
            elif status == "SENT":
                bg_color = Color(255, 255, 200) # Light Yellow

            # 2. Check for Sensitive API (Risk)
            method = model.getValueAt(model_row, 1)
            path = model.getValueAt(model_row, 2)
            
            is_sensitive = False
            if method in ["POST", "PUT", "DELETE", "PATCH"]:
                is_sensitive = True
            if path and any(x in path.lower() for x in ["delete", "remove", "update", "modify", "add", "create", "change"]):
                is_sensitive = True
                
            if is_sensitive:
                fg_color = Color.RED
                if not isSelected:
                    # Make font bold for sensitive? Font handling is tricky in renderer reusing component.
                    # Just stick to RED text.
                    pass

            if isSelected:
                c.setBackground(table.getSelectionBackground())
                c.setForeground(table.getSelectionForeground())
                if is_sensitive:
                     c.setForeground(Color(255, 100, 100))
            else:
                c.setBackground(bg_color)
                c.setForeground(fg_color)
                
        except:
            pass
            
        return c

class IDORAttackPanel(JPanel, IMessageEditorController):
    def __init__(self, extender):
        self.extender = extender
        self.layout = BorderLayout()
        
        # Top Bar (Controls)
        self.top_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        self.btn_refresh = JButton("Refresh", actionPerformed=self.refresh_table)
        self.btn_generate = JButton("Generate Attacks", actionPerformed=self.generate_attacks)
        self.btn_execute = JButton("Execute Selected", actionPerformed=self.execute_selected)
        self.btn_clear = JButton("Clear", actionPerformed=self.clear_attacks)
        
        self.top_panel.add(self.btn_refresh)
        self.top_panel.add(self.btn_generate)
        self.top_panel.add(self.btn_execute)
        self.top_panel.add(self.btn_clear)
        self.top_panel.add(JLabel(" | Sensitive APIs (POST/PUT/DELETE) are highlighted in RED and require manual execution."))
        
        self.add(self.top_panel, BorderLayout.NORTH)
        
        # Main Split Pane
        self.split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self.add(self.split_pane, BorderLayout.CENTER)
        
        # Left: Table
        self.table_model = IDORAttackTableModel()
        self.table = JTable(self.table_model)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(lambda e: self.on_selection_change(e))
        
        # Sorting
        self.sorter = TableRowSorter(self.table_model)
        self.table.setRowSorter(self.sorter)
        
        # Renderer
        for i in range(self.table.getColumnCount()):
            renderer = RiskRenderer()
            self.table.getColumnModel().getColumn(i).setCellRenderer(renderer)
            
        # Status Column (Index 3) - Custom renderer if needed, but RiskRenderer handles it generically?
        # RiskRenderer currently highlights based on row data (Method/Path).
        # We might want status specific colors.
        
        self.scroll_pane = JScrollPane(self.table)
        self.split_pane.setLeftComponent(self.scroll_pane)
        
        # Right: Details Tabs
        self.details_tabs = JTabbedPane()
        self.split_pane.setRightComponent(self.details_tabs)
        
        # Editors
        self.request_editor = self.extender._callbacks.createMessageEditor(self, False)
        self.response_editor = self.extender._callbacks.createMessageEditor(self, False)
        self.original_request_editor = self.extender._callbacks.createMessageEditor(self, False)
        
        self.details_tabs.addTab("Attack Request", self.request_editor.getComponent())
        self.details_tabs.addTab("Attack Response", self.response_editor.getComponent())
        self.details_tabs.addTab("Original Request", self.original_request_editor.getComponent())
        
        self.diff_text = JTextArea()
        self.diff_text.setEditable(False)
        self.diff_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.details_tabs.addTab("Diff", JScrollPane(self.diff_text))
        
        # Current selection data
        self.current_request = None
        self.current_response = None
        self.current_original_request = None
        self.current_http_service = None
        
        self.split_pane.setDividerLocation(600)

    def refresh_table(self, event=None):
        # Fetch attacks from DB
        # We need to join with raw_requests to get method/path if not stored in attack_queue (wait, attack_queue has request_data json)
        # But for the table, we want to display Method/Path.
        # attack_queue: request_data BLOB. We can parse it, but it's slow for list.
        # Actually raw_requests has method/path.
        # query: SELECT a.id, r.method, r.path, a.status, a.response_code, a.vulnerability_score, a.llm_verification_result, a.payload_description 
        # FROM attack_queue a JOIN raw_requests r ON a.original_request_id = r.id
        
        sql = '''
        SELECT a.id, r.method, r.path, a.status, a.response_code, a.vulnerability_score, a.llm_verification_result, a.payload_description 
        FROM attack_queue a 
        JOIN raw_requests r ON a.original_request_id = r.id
        ORDER BY a.id DESC
        '''
        if hasattr(self.extender, 'db_manager'):
            rows = self.extender.db_manager.fetch_all(sql)
            self.table_model.set_attacks(rows)

    def generate_attacks(self, event):
        # Trigger generation in background
        def run():
            if hasattr(self.extender, 'attack_engine'):
                self.extender.attack_engine.generate_attacks()
                SwingUtilities.invokeLater(lambda: self.refresh_table())
        
        t = Thread(target=run)
        t.start()

    def execute_selected(self, event):
        selected_row = self.table.getSelectedRow()
        if selected_row == -1: return
        
        model_row = self.table.convertRowIndexToModel(selected_row)
        attack_id = self.table_model.getValueAt(model_row, 0)
        
        def run():
            if hasattr(self.extender, 'attack_engine'):
                # Prepare LLM config
                llm_config = {
                    'enabled': self.extender.enableLlm.isSelected(),
                    'base_url': self.extender.llmBaseUrl.getText(),
                    'api_key': self.extender.llmApiKey.getText(),
                    'model': self.extender.llmModel.getText()
                }
                
                result = self.extender.attack_engine.execute_attack(
                    attack_id, 
                    self.extender._callbacks, 
                    self.extender._helpers,
                    llm_config
                )
                
                SwingUtilities.invokeLater(lambda: self.refresh_table())
                # Also refresh details if still selected
                SwingUtilities.invokeLater(lambda: self.on_selection_change(None))
        
        t = Thread(target=run)
        t.start()

    def clear_attacks(self, event):
        if hasattr(self.extender, 'db_manager'):
            self.extender.db_manager.execute_query("DELETE FROM attack_queue")
            self.refresh_table()

    def on_selection_change(self, event):
        selected_row = self.table.getSelectedRow()
        if selected_row == -1:
            self.current_request = None
            self.current_response = None
            self.current_original_request = None
            self.request_editor.setMessage(None, False)
            self.response_editor.setMessage(None, False)
            self.original_request_editor.setMessage(None, False)
            return

        model_row = self.table.convertRowIndexToModel(selected_row)
        attack_id = self.table_model.getValueAt(model_row, 0)
        
        # Fetch details
        sql = "SELECT request_data, response_data, original_request_id, payload_description FROM attack_queue WHERE id = ?"
        rows = self.extender.db_manager.fetch_all(sql, (attack_id,))
        if rows:
            req_data_json, res_data, orig_req_id, description = rows[0]
            
            # Reconstruct request for display
            try:
                rd = json.loads(req_data_json)
                self.current_request = self.extender.attack_engine.reconstruct_request(rd, self.extender._helpers)
            except:
                self.current_request = None
                
            # Response
            if res_data:
                if isinstance(res_data, unicode): res_data = res_data.encode('utf-8')
                self.current_response = res_data
            else:
                self.current_response = None
                
            # Original Request
            sql_orig = "SELECT headers, body, method, url FROM raw_requests WHERE id = ?"
            orig_rows = self.extender.db_manager.fetch_all(sql_orig, (orig_req_id,))
            if orig_rows:
                h_json, b, orig_method, orig_url = orig_rows[0]
                try:
                    h_list = json.loads(h_json)
                    headers = ArrayList()
                    for h in h_list: headers.add(h)
                    if isinstance(b, unicode): b = b.encode('utf-8')
                    self.current_original_request = self.extender._helpers.buildHttpMessage(headers, b)
                    
                    # Update Diff Tab
                    diff_sb = []
                    diff_sb.append("=== Attack Description ===")
                    diff_sb.append(description)
                    diff_sb.append("\n=== Original Request Line ===")
                    diff_sb.append("{} {}".format(orig_method, orig_url))
                    diff_sb.append("\n=== Attack Request Line ===")
                    # Extract from current_request
                    if self.current_request:
                        req_info = self.extender._helpers.analyzeRequest(self.current_request)
                        diff_sb.append("{} {}".format(req_info.getMethod(), req_info.getUrl().getFile())) # getFile returns path+query
                    
                    self.diff_text.setText("\n".join(diff_sb))
                    self.diff_text.setCaretPosition(0)
                    
                except:
                    self.current_original_request = None
            
            # Update editors
            self.request_editor.setMessage(self.current_request, True)
            self.response_editor.setMessage(self.current_response, False)
            self.original_request_editor.setMessage(self.current_original_request, True)
            
            # Update HTTP Service (Host/Port)
            # We can get it from request_data
            try:
                rd = json.loads(req_data_json)
                host = rd['host']
                # port/protocol not saved in json explicitly (my bad in attacker.py _create_attack_entry... wait, I added it in execute_attack but not in saved json)
                # But execute_attack reads raw_requests to get URL.
                # Here we can do the same or just default.
                self.current_http_service = self.extender._helpers.buildHttpService(host, 80, "http") # Placeholder
            except: pass

    # IMessageEditorController implementation
    def getHttpService(self):
        return self.current_http_service

    def getRequest(self):
        return self.current_request

    def getResponse(self):
        return self.current_response
