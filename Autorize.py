#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from burp import IBurpExtender, IHttpListener, IProxyListener, IExtensionStateListener
from authorization.authorization import handle_message
from helpers.initiator import Initiator
from helpers.filters import handle_proxy_message
from java.util.concurrent import Executors, ScheduledThreadPoolExecutor, TimeUnit
from javax.swing import SwingUtilities

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("IDORs Factory")
        
        self.executor = Executors.newFixedThreadPool(10)
        # Separate scheduler for background tasks like extraction
        self.scheduler = ScheduledThreadPoolExecutor(1)
        self.auto_idor_running = False
        
        callbacks.registerExtensionStateListener(self)

        initiator = Initiator(self)

        initiator.init_constants()
        
        initiator.draw_all()

        initiator.implement_all()

        initiator.init_ui() 
        
        initiator.print_welcome_message()
        
        # Initialize DatabaseManager in a background thread to prevent UI freezing
        self.executor.submit(self.init_database)
        
        return

    def init_database(self):
        try:
            from db.database import DatabaseManager
            self.db_manager = DatabaseManager()
            self.db_manager.extender = self  # Link extender to db_manager
            print("DatabaseManager initialized successfully.")

            # 初始化 ConfigManager (配置管理单例)
            from api.config_manager import ConfigManager
            self.config_manager = ConfigManager(self.db_manager)
            self.config_manager.set_extender(self)

            # 从 GUI 同步配置到 ConfigManager
            self.config_manager.sync_from_gui(self)

            # Initialize Extractor
            from extractor.extractor import ParameterExtractor
            self.extractor = ParameterExtractor(self.db_manager)
            
            # Initialize Attack Engine
            from attacker.attacker import AttackEngine
            self.attack_engine = AttackEngine(self.db_manager)
            
            # Disable automatic scheduling for debugging purposes (manual trigger only)
            # self.scheduler.scheduleWithFixedDelay(self.run_extraction_task, 10, 10, TimeUnit.SECONDS)
            print("Parameter Extractor and Attack Engine initialized (Manual Mode).")
            self.scheduler.scheduleWithFixedDelay(
                self.run_auto_idor_cycle, 5, 5, TimeUnit.MINUTES
            )
            print("Auto IDOR scheduler initialized (disabled by default).")

            # 启动 HTTP API Server (后台线程)
            try:
                from api.http_server import ApiService
                self.api_service = ApiService(self)
                self.api_service.start()
                print("[Autorize] HTTP API server started on 127.0.0.1:8899")
            except Exception as e:
                print("[Autorize] Failed to start HTTP API server: " + str(e))
                self.api_service = None

        except Exception as e:
            print("Failed to initialize DatabaseManager or Extractor: " + str(e))
            import traceback
            traceback.print_exc()

    def run_extraction_task(self):
        try:
            if hasattr(self, 'extractor'):
                self.extractor.process_unanalyzed_requests()
        except Exception as e:
            print("Error in extraction task: " + str(e))

    def _get_llm_config(self):
        enable_llm = (
            self.enableLlm.isSelected() if hasattr(self, "enableLlm") else False
        )
        analyze_result = (
            self.llmAnalyzeResult.isSelected()
            if hasattr(self, "llmAnalyzeResult")
            else False
        )
        return {
            "enabled": enable_llm and analyze_result,
            "base_url": self.llmBaseUrl.getText() if hasattr(self, "llmBaseUrl") else "",
            "api_key": self.llmApiKey.getText() if hasattr(self, "llmApiKey") else "",
            "model": self.llmModel.getText() if hasattr(self, "llmModel") else "",
            "analyze_result": analyze_result,
            "verify_ssl": not self.llmDisableSslVerification.isSelected()
            if hasattr(self, "llmDisableSslVerification")
            else True,
        }

    def _update_auto_status(self, message):
        try:
            def update():
                if hasattr(self, "autoIdorStatus"):
                    self.autoIdorStatus.setText(message)
                if hasattr(self, "progressBar"):
                    self.progressBar.setString(message)
                    self.progressBar.setStringPainted(True)

            if SwingUtilities.isEventDispatchThread():
                update()
            else:
                SwingUtilities.invokeLater(update)
        except Exception:
            pass

    def run_auto_idor_cycle(self):
        if self.auto_idor_running:
            print("[Auto IDOR] Previous cycle still running. Skipping this round.")
            return

        if not hasattr(self, "autoIdorEnabled") or not self.autoIdorEnabled.isSelected():
            return

        self.auto_idor_running = True
        try:
            print("[Auto IDOR] Starting scheduled cycle...")
            self._update_auto_status("Auto IDOR: extracting parameters...")

            if hasattr(self, "extractor"):
                self.extractor.process_unanalyzed_requests()

            self._update_auto_status("Auto IDOR: generating attacks...")
            if hasattr(self, "attack_engine"):
                hidden_param_config = None
                try:
                    if hasattr(self, "idorAttackPanel") and self.idorAttackPanel:
                        hidden_param_config = self.idorAttackPanel._build_hidden_param_config()
                except Exception:
                    hidden_param_config = None
                self.attack_engine.generate_attacks(hidden_param_config)

            self._update_auto_status("Auto IDOR: executing pending GET attacks...")
            summary = {"total": 0, "success": 0, "failed": 0, "vulnerable": 0}
            if hasattr(self, "attack_engine"):
                hidden_param_config = None
                apply_hidden_param_on_execute = False
                try:
                    if hasattr(self, "idorAttackPanel") and self.idorAttackPanel:
                        hidden_param_config = self.idorAttackPanel._build_hidden_param_config()
                        apply_hidden_param_on_execute = self.idorAttackPanel._is_apply_hidden_param_on_execute()
                except Exception:
                    hidden_param_config = None
                    apply_hidden_param_on_execute = False
                summary = self.attack_engine.execute_pending_get_attacks(
                    self._callbacks,
                    self._helpers,
                    self._get_llm_config(),
                    50,
                    hidden_param_config,
                    apply_hidden_param_on_execute,
                )

            summary_text = "Auto IDOR: cycle complete - {}/{} executed, {} vulnerable, {} failed".format(
                summary.get("success", 0),
                summary.get("total", 0),
                summary.get("vulnerable", 0),
                summary.get("failed", 0),
            )
            print("[Auto IDOR] " + summary_text)
            self._update_auto_status(summary_text)

            try:
                if hasattr(self, "idorAttackPanel") and self.idorAttackPanel:
                    SwingUtilities.invokeLater(lambda: self.idorAttackPanel.refresh_table())
            except Exception:
                pass

        except Exception as e:
            print("[Auto IDOR] Error in scheduled cycle: " + str(e))
            self._update_auto_status("Auto IDOR: cycle failed - " + str(e))
        finally:
            self.auto_idor_running = False

    def toggle_auto_idor(self, enabled):
        if enabled:
            self._update_auto_status("Auto IDOR: enabled (every 5 minutes)")
        else:
            self._update_auto_status("Auto IDOR: disabled")

    #
    # implement IHttpListener
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):      
        handle_message(self, toolFlag, messageIsRequest, messageInfo)

    #
    # implement IProxyListener
    #
    def processProxyMessage(self, messageIsRequest, message):
        handle_proxy_message(self, message)

    #
    # implement IExtensionStateListener
    #
    def extensionUnloaded(self):
        if hasattr(self, "api_service") and self.api_service:
            self.api_service.stop()
        self.executor.shutdown()
        self.scheduler.shutdown()
        print "Autorize extension unloaded."
