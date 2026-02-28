#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from java.awt.event import ActionListener
from java.lang import Runnable
from javax.swing import SwingUtilities
from javax.swing import JToggleButton
from javax.swing import JTabbedPane
from javax.swing import GroupLayout
from javax.swing import JSplitPane
from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import JPanel
from java.awt import Dimension

from table import UpdateTableEDT


from javax.swing import JTextField
from javax.swing import JLabel

class ClearTableRunnable(Runnable):
    """Runs on executor so EDT never blocks on _lock."""
    def __init__(self, extender):
        self._extender = extender

    def run(self):
        self._extender._lock.acquire()
        try:
            oldSize = self._extender._log.size()
            self._extender._log.clear()
            if oldSize > 0:
                SwingUtilities.invokeLater(UpdateTableEDT(self._extender, "delete", 0, oldSize - 1))
        finally:
            self._extender._lock.release()

class RunExtractorRunnable(Runnable):
    def __init__(self, extender):
        self._extender = extender

    def run(self):
        if hasattr(self._extender, 'extractor') and self._extender.extractor:
            print("Manually running Parameter Extractor...")
            self._extender.extractor.process_unanalyzed_requests()
            print("Parameter extraction complete.")
        else:
            print("Extractor not initialized.")

class RunAttackerRunnable(Runnable):
    def __init__(self, extender):
        self._extender = extender

    def run(self):
        if hasattr(self._extender, 'attack_engine') and self._extender.attack_engine:
            print("Manually running Attack Engine...")
            self._extender.attack_engine.generate_attacks()
            print("Attack generation complete.")
        else:
            print("Attack Engine not initialized.")

class ClearDatabaseRunnable(Runnable):
    def __init__(self, extender):
        self._extender = extender

    def run(self):
        if hasattr(self._extender, 'db_manager') and self._extender.db_manager:
            success = self._extender.db_manager.clear_all_data()
            if success:
                print("Database cleared successfully.")
            else:
                print("Failed to clear database.")
        else:
            print("Database manager not initialized.")

class ConfigurationTab():
    def __init__(self, extender):
        self._extender = extender

    def draw(self):
        """  init configuration tab
        """
        self._extender.startButton = JToggleButton("Autorize is off",
                                    actionPerformed=self.startOrStop)
        self._extender.startButton.setBounds(10, 20, 230, 30)

        self._extender.clearButton = JButton("Clear table", actionPerformed=self.clearTable)
        self._extender.clearButton.setBounds(10, 80, 100, 30)
        
        self._extender.clearDbButton = JButton("Clear DB", actionPerformed=self.clearDatabase)
        self._extender.clearDbButton.setBounds(10, 120, 100, 30)
        self._extender.clearDbButton.setToolTipText("Clear all data from the local database (requests, parameters, attacks)")
        
        self._extender.runExtractorButton = JButton("Extract Params", actionPerformed=self.runExtractor)
        self._extender.runExtractorButton.setBounds(10, 160, 120, 30)
        self._extender.runExtractorButton.setToolTipText("Manually extract parameters from captured requests")

        self._extender.generateAttacksButton = JButton("Generate Attacks", actionPerformed=self.generateAttacks)
        self._extender.generateAttacksButton.setBounds(10, 200, 140, 30)
        self._extender.generateAttacksButton.setToolTipText("Generate attack payloads based on parameter differences")

        # LLM Configuration UI
        self._extender.llmBaseUrlLabel = JLabel("LLM Base URL:")
        self._extender.llmBaseUrl = JTextField("https://api.openai.com/v1", 20)
        
        self._extender.llmApiKeyLabel = JLabel("LLM API Key:")
        self._extender.llmApiKey = JTextField("", 20)
        
        self._extender.llmModelLabel = JLabel("Model:")
        self._extender.llmModel = JTextField("gpt-3.5-turbo", 10)
        
        self._extender.enableLlm = JCheckBox("Enable LLM Analysis")
        self._extender.enableLlm.setSelected(False)

        self._extender.autoScroll = JCheckBox("Auto scroll")
        self._extender.autoScroll.setBounds(145, 80, 130, 30)


        self._extender.ignore304 = JCheckBox("Ignore 304/204 status code responses")
        self._extender.ignore304.setBounds(280, 5, 300, 30)
        self._extender.ignore304.setSelected(True)

        self._extender.prevent304 = JCheckBox("Prevent 304 Not Modified status code")
        self._extender.prevent304.setBounds(280, 25, 300, 30)
        self._extender.interceptRequestsfromRepeater = JCheckBox("Intercept requests from Repeater")
        self._extender.interceptRequestsfromRepeater.setBounds(280, 45, 300, 30)

        self._extender.doUnauthorizedRequest = JCheckBox("Check unauthenticated")
        self._extender.doUnauthorizedRequest.setBounds(280, 65, 300, 30)
        self._extender.doUnauthorizedRequest.setSelected(True)

        self._extender.replaceQueryParam = JCheckBox("Replace query params", actionPerformed=self.replaceQueryHanlder)
        self._extender.replaceQueryParam.setBounds(280, 85, 300, 30)
        self._extender.replaceQueryParam.setSelected(False)

        self._extender.filtersTabs = JTabbedPane()
        self._extender.filtersTabs = self._extender.filtersTabs
        self._extender.filtersTabs.addTab("Unauthentication Detector ", self._extender.EDPnlUnauth)
        self._extender.filtersTabs.addTab("Interception Filters", self._extender.filtersPnl)
        self._extender.filtersTabs.addTab("Table Filter", self._extender.filterPnl)
        self._extender.filtersTabs.addTab("Save/Restore", self._extender.exportPnl)

        self._extender.filtersTabs.setSelectedIndex(1)
        self._extender.filtersTabs.setBounds(0, 350, 2000, 700)

        self.config_pnl = JPanel()
        layout = GroupLayout(self.config_pnl)
        self.config_pnl.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)

        minsize = Dimension(0, 0)
        self._extender.filtersTabs.setMinimumSize(minsize)
        self.config_pnl.setMinimumSize(minsize)

        layout.setHorizontalGroup(
            layout.createSequentialGroup()
                .addGroup(
                    layout.createParallelGroup()
                    .addComponent(
                            self._extender.startButton,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            )
                    .addComponent(
                        self._extender.clearButton,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        )
                    .addComponent(
                        self._extender.clearDbButton,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        )
                    .addComponent(
                        self._extender.runExtractorButton,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        )
                    .addComponent(
                        self._extender.generateAttacksButton,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        )
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(self._extender.llmBaseUrlLabel)
                        .addComponent(self._extender.llmBaseUrl, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addComponent(self._extender.llmApiKeyLabel)
                        .addComponent(self._extender.llmApiKey, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                    )
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(self._extender.llmModelLabel)
                        .addComponent(self._extender.llmModel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addComponent(self._extender.enableLlm, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                    )
                    )
                .addGroup(
                    layout.createParallelGroup()
                        .addComponent(
                            self._extender.ignore304,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                        )
                        .addComponent(
                            self._extender.prevent304,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                        )
                        .addComponent(
                            self._extender.interceptRequestsfromRepeater,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                        )
                        .addComponent(
                            self._extender.doUnauthorizedRequest,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                        )
                        .addComponent(
                            self._extender.autoScroll,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                        )
                        .addComponent(
                            self._extender.replaceQueryParam,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                        )
                    )
            )
        
        layout.setVerticalGroup(
                layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)

                    .addComponent(
                            self._extender.startButton,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            )
                    .addComponent(
                        self._extender.ignore304,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                )
                    .addComponent(
                        self._extender.prevent304,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(
                        self._extender.clearButton,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        )
                    .addComponent(
                            self._extender.interceptRequestsfromRepeater,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                        )
                )
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(
                        self._extender.clearDbButton,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        )
                    .addComponent(
                        self._extender.doUnauthorizedRequest,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                )
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(
                        self._extender.runExtractorButton,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        )
                    .addComponent(
                        self._extender.replaceQueryParam,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                )
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(
                        self._extender.generateAttacksButton,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        )
                )
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(self._extender.llmBaseUrlLabel)
                        .addComponent(self._extender.llmBaseUrl, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addComponent(self._extender.llmApiKeyLabel)
                        .addComponent(self._extender.llmApiKey, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                    )
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(self._extender.llmModelLabel)
                        .addComponent(self._extender.llmModel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addComponent(self._extender.enableLlm, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                    )
                    .addComponent(
                            self._extender.autoScroll,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                        )
                )
        
        self._extender._cfg_splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._extender._cfg_splitpane.setResizeWeight(0.5)
        self._extender._cfg_splitpane.setBounds(0, 0, 1000, 1000)
        self._extender._cfg_splitpane.setRightComponent(self._extender.filtersTabs)
        self._extender._cfg_splitpane.setLeftComponent(self.config_pnl)

    def startOrStop(self, event):
        if self._extender.startButton.getText() == "Autorize is off":
            self._extender.startButton.setText("Autorize is on")
            self._extender.startButton.setSelected(True)
            self._extender.intercept = 1
        else:
            self._extender.startButton.setText("Autorize is off")
            self._extender.startButton.setSelected(False)
            self._extender.intercept = 0
    
    def clearTable(self, event):
        # Run on executor so the EDT never blocks on _lock (avoids UI freeze)
        self._extender.executor.submit(ClearTableRunnable(self._extender))

    def clearDatabase(self, event):
        # Run on executor to avoid UI freeze
        self._extender.executor.submit(ClearDatabaseRunnable(self._extender))

    def runExtractor(self, event):
        self._extender.executor.submit(RunExtractorRunnable(self._extender))

    def generateAttacks(self, event):
        self._extender.executor.submit(RunAttackerRunnable(self._extender))
    
    def replaceQueryHanlder(self, event):
        default_text = "Cookie: Insert=injected; cookie=or;\nHeader: here"
        if hasattr(self._extender, 'userTab') and self._extender.userTab:
            for user_id, user_data in self._extender.userTab.user_tabs.items():
                if self._extender.replaceQueryParam.isSelected():
                    user_data['headers_instance'].replaceString.setText("paramName=paramValue")
                else:
                    user_data['headers_instance'].replaceString.setText(default_text)
