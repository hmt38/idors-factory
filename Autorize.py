#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from burp import IBurpExtender, IHttpListener, IProxyListener, IExtensionStateListener
from authorization.authorization import handle_message
from helpers.initiator import Initiator
from helpers.filters import handle_proxy_message
from java.util.concurrent import Executors, ScheduledThreadPoolExecutor, TimeUnit

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Autorize")
        
        self.executor = Executors.newFixedThreadPool(10)
        # Separate scheduler for background tasks like extraction
        self.scheduler = ScheduledThreadPoolExecutor(1)
        
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
            print("DatabaseManager initialized successfully.")
            
            # Initialize Extractor
            from extractor.extractor import ParameterExtractor
            self.extractor = ParameterExtractor(self.db_manager)
            
            # Initialize Attack Engine
            from attacker.attacker import AttackEngine
            self.attack_engine = AttackEngine(self.db_manager)
            
            # Disable automatic scheduling for debugging purposes (manual trigger only)
            # self.scheduler.scheduleWithFixedDelay(self.run_extraction_task, 10, 10, TimeUnit.SECONDS)
            print("Parameter Extractor and Attack Engine initialized (Manual Mode).")
            
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
        self.executor.shutdown()
        print "Autorize extension unloaded."
