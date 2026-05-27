# ==============================================================
#  DeserAuth v1.2 - Deserialization Authorization Analyzer
#  
#  Automated Java Serialization Manipulation & Authorization
#  Testing for Burp Suite
#
#  Author: Yuthan Balaji K
#  GitHub: https://github.com/iamyuthan
#  Repository: https://github.com/iamyuthan/DeserAuth
#  License: MIT
#
#  Description:
#    A Burp Suite extension for testing authorization controls
#    in applications that use Java serialized objects (Spring
#    HTTP Invoker, RMI over HTTP, custom binary protocols).
#    Automatically replays requests with modified serialized
#    identifiers and compares responses to detect privilege
#    escalation, IDOR, and broken access control vulnerabilities.
#
#  Features:
#    - Passive automatic analysis (intercept & compare)
#    - Manual right-click Send-to-Repeater mutations
#    - Same-length and variable-length serialized string swapping
#    - Java char[] buffer patching with null-padding awareness
#    - TC_STRING length prefix auto-patching
#    - Multi-rule support with per-rule enable/disable
#    - Color-coded SAME/SIMILAR/DIFFERENT results
#    - Sortable results table
#    - Export to CSV, HTML, XML, Excel
#    - Full request/response comparison viewers
#    - Works across all Burp tools (Proxy, Repeater, Scanner, etc.)
#
#  Requirements:
#    - Burp Suite Professional or Community
#    - Jython Standalone JAR (2.7.x)
#
#  Usage:
#    1. Set Jython JAR in Extender -> Options -> Python Environment
#    2. Load this file as a Python extension
#    3. Configure swap rules in the DeserAuth tab
#    4. Select scope and click START for passive analysis
#    5. Right-click any request for manual mutations
#
# ==============================================================

from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory
from javax.swing import (JPanel, JButton, JTable, JScrollPane, JLabel,
                         JTextField, JCheckBox, JComboBox, JSplitPane,
                         JTabbedPane, BoxLayout, Box, BorderFactory,
                         SwingConstants, JOptionPane, SwingUtilities,
                         ListSelectionModel, JFileChooser, JMenu, JMenuItem)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, FlowLayout, Color, Dimension, Font
from java.awt.event import ActionListener
from java.lang import Runnable, String, Integer
from java.io import File
from java.util import ArrayList
from threading import Thread, Lock
from java.awt.event import MouseAdapter
from java.awt import Cursor
from burp import IExtensionStateListener
import java.awt.Desktop as Desktop
import java.net.URI as URI
import time

class SwapRule:
    def __init__(self, search="", replace="", mode="any", enabled=True):
        self.search = search
        self.replace = replace
        self.mode = mode
        self.enabled = enabled

class LogEntry:
    def __init__(self, tool, method, host, path, url, orig_status, orig_length,
                 mod_status, mod_length, difference, diff_pct, timestamp,
                 orig_request, orig_response, mod_request, mod_response,
                 http_service, orig_headers, mod_headers):
        self.tool = tool
        self.method = method
        self.host = host
        self.path = path
        self.url = url
        self.orig_status = orig_status
        self.orig_length = orig_length
        self.mod_status = mod_status
        self.mod_length = mod_length
        self.difference = difference
        self.diff_pct = diff_pct
        self.timestamp = timestamp
        self.orig_request = orig_request
        self.orig_response = orig_response
        self.mod_request = mod_request
        self.mod_response = mod_response
        self.http_service = http_service
        self.orig_headers = orig_headers
        self.mod_headers = mod_headers

class LogTableModel(AbstractTableModel):
    COLUMNS = ["#", "Tool", "Method", "Host", "Path",
               "Orig Status", "Orig Length", "Mod Status", "Mod Length",
               "Difference", "Diff %", "Time"]

    def __init__(self):
        self._log = []
        self._lock = Lock()

    def addEntry(self, entry):
        self._lock.acquire()
        try:
            row = len(self._log)
            self._log.append(entry)
            self.fireTableRowsInserted(row, row)
        finally:
            self._lock.release()

    def getEntry(self, row):
        return self._log[row]

    def getLog(self):
        return self._log[:]

    def clearLog(self):
        self._lock.acquire()
        try:
            self._log = []
            self.fireTableDataChanged()
        finally:
            self._lock.release()

    def getRowCount(self):
        return len(self._log)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getColumnClass(self, col):
        if col == 0:
            return Integer
        if col in (5, 6, 7, 8):
            return Integer
        return String

    def getValueAt(self, row, col):
        entry = self._log[row]
        if col == 0:
            return Integer(row + 1)
        elif col == 1:
            return entry.tool
        elif col == 2:
            return entry.method
        elif col == 3:
            return entry.host
        elif col == 4:
            return entry.path
        elif col == 5:
            return Integer(int(entry.orig_status))
        elif col == 6:
            return Integer(int(entry.orig_length))
        elif col == 7:
            return Integer(int(entry.mod_status))
        elif col == 8:
            return Integer(int(entry.mod_length))
        elif col == 9:
            return entry.difference
        elif col == 10:
            return entry.diff_pct
        elif col == 11:
            return entry.timestamp
        return ""

class LinkClickListener(MouseAdapter):
    def __init__(self, url):
        self.url = url

    def mouseClicked(self, event):
        try:
            Desktop.getDesktop().browse(URI(self.url))
        except:
            pass

    def mouseEntered(self, event):
        event.getSource().setCursor(Cursor(Cursor.HAND_CURSOR))

    def mouseExited(self, event):
        event.getSource().setCursor(Cursor(Cursor.DEFAULT_CURSOR))

class DiffCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)

        if not isSelected:
            model_row = table.convertRowIndexToModel(row)
            model = table.getModel()
            diff_val = model.getValueAt(model_row, 9)

            if col == 9 or col == 10:
                if diff_val == "SAME":
                    comp.setBackground(Color(200, 255, 200))
                    comp.setForeground(Color(0, 100, 0))
                elif diff_val == "SIMILAR":
                    comp.setBackground(Color(255, 255, 180))
                    comp.setForeground(Color(130, 100, 0))
                elif diff_val == "DIFFERENT":
                    comp.setBackground(Color(255, 200, 200))
                    comp.setForeground(Color(150, 0, 0))
                else:
                    comp.setBackground(Color.WHITE)
                    comp.setForeground(Color.BLACK)
            else:
                if diff_val == "DIFFERENT":
                    comp.setBackground(Color(255, 240, 240))
                elif diff_val == "SIMILAR":
                    comp.setBackground(Color(255, 255, 240))
                else:
                    comp.setBackground(Color.WHITE)
                comp.setForeground(Color.BLACK)

        comp.setHorizontalAlignment(SwingConstants.CENTER)
        return comp

class RulePanel(JPanel):
    def __init__(self, rule, remove_callback):
        JPanel.__init__(self)
        self.rule = rule
        self.setLayout(FlowLayout(FlowLayout.LEFT, 5, 2))
        self.setMaximumSize(Dimension(9999, 40))

        self.enabled_cb = JCheckBox("", rule.enabled)
        self.add(self.enabled_cb)

        self.add(JLabel("Search:"))
        self.search_field = JTextField(rule.search, 15)
        self.search_field.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.add(self.search_field)

        self.add(JLabel("Replace:"))
        self.replace_field = JTextField(rule.replace, 15)
        self.replace_field.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.add(self.replace_field)

        self.add(JLabel("Mode:"))
        self.mode_combo = JComboBox(["Any Length", "Same Length"])
        if rule.mode == "same":
            self.mode_combo.setSelectedIndex(1)
        self.add(self.mode_combo)

        remove_btn = JButton("X")
        remove_btn.setPreferredSize(Dimension(30, 25))
        remove_btn.setForeground(Color.RED)
        remove_btn.addActionListener(RemoveRuleAction(remove_callback, self))
        self.add(remove_btn)

    def get_rule(self):
        self.rule.search = self.search_field.getText()
        self.rule.replace = self.replace_field.getText()
        self.rule.enabled = self.enabled_cb.isSelected()
        if self.mode_combo.getSelectedIndex() == 0:
            self.rule.mode = "any"
        else:
            self.rule.mode = "same"
        return self.rule

class RemoveRuleAction(ActionListener):
    def __init__(self, callback, panel):
        self.callback = callback
        self.panel = panel

    def actionPerformed(self, event):
        self.callback(self.panel)

class StartStopAction(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender.toggle_running()

class AddRuleAction(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender.add_rule_panel(SwapRule())

class ClearLogAction(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender._table_model.clearLog()
        print("[+] Table cleared")

class SelectAllScopeAction(ActionListener):
    def __init__(self, extender, select):
        self.extender = extender
        self.select = select

    def actionPerformed(self, event):
        self.extender._scope_proxy.setSelected(self.select)
        self.extender._scope_repeater.setSelected(self.select)
        self.extender._scope_intruder.setSelected(self.select)
        self.extender._scope_scanner.setSelected(self.select)
        self.extender._scope_sequencer.setSelected(self.select)
        self.extender._scope_spider.setSelected(self.select)
        self.extender._scope_extender.setSelected(self.select)
        self.extender._scope_target.setSelected(self.select)

class ExportAction(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender.show_export_dialog()

class BuildUIRunnable(Runnable):
    def __init__(self, extender):
        self.extender = extender

    def run(self):
        self.extender.build_ui()

class AddEntryRunnable(Runnable):
    def __init__(self, model, entry):
        self.model = model
        self.entry = entry

    def run(self):
        self.model.addEntry(self.entry)

class TableSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self.extender = extender

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return

        row = self.extender._results_table.getSelectedRow()
        if row < 0:
            return

        model_row = self.extender._results_table.convertRowIndexToModel(row)
        entry = self.extender._table_model.getEntry(model_row)

        if entry.orig_request:
            self.extender._orig_request_viewer.setMessage(entry.orig_request, True)
        if entry.orig_response:
            self.extender._orig_response_viewer.setMessage(entry.orig_response, False)
        if entry.mod_request:
            self.extender._mod_request_viewer.setMessage(entry.mod_request, True)
        if entry.mod_response:
            self.extender._mod_response_viewer.setMessage(entry.mod_response, False)

class SavedRuleMenuAction(ActionListener):
    def __init__(self, extender, invocation, rule_index):
        self.extender = extender
        self.invocation = invocation
        self.rule_index = rule_index

    def actionPerformed(self, event):
        self.extender.context_send_saved_rule(self.invocation, self.rule_index)

class ManualSameAction(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, event):
        self.extender.context_send_to_repeater(self.invocation, "same")

class ManualAnyAction(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, event):
        self.extender.context_send_to_repeater(self.invocation, "any")

class ManualBatchAction(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, event):
        self.extender.context_send_to_repeater_batch(self.invocation)

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("DeserAuth")

        self._running = False
        self._rule_panels = []
        self._lock = Lock()
        self._repeater_counter = 0

        callbacks.registerExtensionStateListener(self)
        
        SwingUtilities.invokeLater(BuildUIRunnable(self))
        
    def extensionUnloaded(self):
        self._running = False
        print("[+] DeserAuth unloaded cleanly")

    def build_ui(self):
        self._main_panel = JPanel(BorderLayout(5, 5))
        self._main_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        config_panel = JPanel(BorderLayout(5, 5))

        title_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        title_label = JLabel("DeserAuth")
        title_label.setFont(Font("Dialog", Font.BOLD, 16))
        title_label.setForeground(Color(60, 60, 60))
        title_panel.add(title_label)
        subtitle = JLabel("  - Deserialization Authorization Analyzer")
        subtitle.setFont(Font("Dialog", Font.ITALIC, 12))
        subtitle.setForeground(Color(100, 100, 100))
        title_panel.add(subtitle)
        
        # Author info
        author_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        author_label = JLabel("  Author: Yuthan Balaji K  |  ")
        author_label.setFont(Font("Dialog", Font.PLAIN, 11))
        author_label.addMouseListener(LinkClickListener("https://github.com/iamyuthan"))
        author_panel.add(author_label)

        repo_link = JLabel("github.com/iamyuthan/DeserAuth")
        repo_link.setFont(Font("Dialog", Font.PLAIN, 11))
        repo_link.addMouseListener(LinkClickListener("https://github.com/iamyuthan/DeserAuth"))
        author_panel.add(repo_link)

        title_panel.add(Box.createHorizontalStrut(20))
        title_panel.add(author_label)
        title_panel.add(repo_link)
        config_panel.add(title_panel, BorderLayout.NORTH)

        rules_outer = JPanel(BorderLayout())
        rules_outer.setBorder(BorderFactory.createTitledBorder("Swap Rules"))

        self._rules_container = JPanel()
        self._rules_container.setLayout(BoxLayout(self._rules_container, BoxLayout.Y_AXIS))

        rules_scroll = JScrollPane(self._rules_container)
        rules_scroll.setPreferredSize(Dimension(800, 100))
        rules_outer.add(rules_scroll, BorderLayout.CENTER)

        rules_btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        add_rule_btn = JButton("+ Add Rule")
        add_rule_btn.addActionListener(AddRuleAction(self))
        rules_btn_panel.add(add_rule_btn)
        rules_outer.add(rules_btn_panel, BorderLayout.SOUTH)

        config_panel.add(rules_outer, BorderLayout.CENTER)

        controls_panel = JPanel(BorderLayout(5, 5))

        scope_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 5))
        scope_panel.setBorder(BorderFactory.createTitledBorder("Scope"))

        self._scope_proxy = JCheckBox("Proxy", True)
        self._scope_repeater = JCheckBox("Repeater", True)
        self._scope_intruder = JCheckBox("Intruder", True)
        self._scope_scanner = JCheckBox("Scanner", True)
        self._scope_sequencer = JCheckBox("Sequencer", True)
        self._scope_spider = JCheckBox("Spider", True)
        self._scope_extender = JCheckBox("Extender", True)
        self._scope_target = JCheckBox("Target", True)

        scope_panel.add(self._scope_proxy)
        scope_panel.add(self._scope_repeater)
        scope_panel.add(self._scope_intruder)
        scope_panel.add(self._scope_scanner)
        scope_panel.add(self._scope_sequencer)
        scope_panel.add(self._scope_spider)
        scope_panel.add(self._scope_extender)
        scope_panel.add(self._scope_target)

        scope_panel.add(JLabel("  "))
        select_all_btn = JButton("All")
        select_all_btn.addActionListener(SelectAllScopeAction(self, True))
        scope_panel.add(select_all_btn)
        deselect_all_btn = JButton("None")
        deselect_all_btn.addActionListener(SelectAllScopeAction(self, False))
        scope_panel.add(deselect_all_btn)

        controls_panel.add(scope_panel, BorderLayout.CENTER)

        action_panel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))

        self._start_btn = JButton("   START   ")
        self._start_btn.setFont(Font("Dialog", Font.BOLD, 13))
        self._start_btn.setForeground(Color(0, 130, 0))
        self._start_btn.addActionListener(StartStopAction(self))
        action_panel.add(self._start_btn)

        self._status_label = JLabel("  STOPPED")
        self._status_label.setFont(Font("Dialog", Font.BOLD, 12))
        self._status_label.setForeground(Color(150, 0, 0))
        action_panel.add(self._status_label)

        action_panel.add(Box.createHorizontalStrut(30))

        clear_btn = JButton("Clear Log")
        clear_btn.addActionListener(ClearLogAction(self))
        action_panel.add(clear_btn)

        action_panel.add(Box.createHorizontalStrut(10))

        export_btn = JButton("Export...")
        export_btn.addActionListener(ExportAction(self))
        action_panel.add(export_btn)

        controls_panel.add(action_panel, BorderLayout.SOUTH)
        config_panel.add(controls_panel, BorderLayout.SOUTH)

        self._main_panel.add(config_panel, BorderLayout.NORTH)

        self._table_model = LogTableModel()
        self._results_table = JTable(self._table_model)
        self._results_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._results_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._results_table.setRowHeight(22)

        sorter = TableRowSorter(self._table_model)
        self._results_table.setRowSorter(sorter)

        col_model = self._results_table.getColumnModel()
        col_widths = [40, 65, 50, 150, 200, 70, 80, 70, 80, 85, 55, 60]
        for i in range(len(col_widths)):
            col_model.getColumn(i).setPreferredWidth(col_widths[i])

        renderer = DiffCellRenderer()
        for i in range(self._table_model.getColumnCount()):
            col_model.getColumn(i).setCellRenderer(renderer)

        self._results_table.getSelectionModel().addListSelectionListener(
            TableSelectionListener(self))

        table_scroll = JScrollPane(self._results_table)

        self._orig_request_viewer = self._callbacks.createMessageEditor(self, False)
        self._orig_response_viewer = self._callbacks.createMessageEditor(self, False)
        self._mod_request_viewer = self._callbacks.createMessageEditor(self, False)
        self._mod_response_viewer = self._callbacks.createMessageEditor(self, False)

        orig_tabs = JTabbedPane()
        orig_tabs.addTab("Original Request", self._orig_request_viewer.getComponent())
        orig_tabs.addTab("Original Response", self._orig_response_viewer.getComponent())

        mod_tabs = JTabbedPane()
        mod_tabs.addTab("Modified Request", self._mod_request_viewer.getComponent())
        mod_tabs.addTab("Modified Response", self._mod_response_viewer.getComponent())

        msg_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, orig_tabs, mod_tabs)
        msg_split.setResizeWeight(0.5)

        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, msg_split)
        main_split.setResizeWeight(0.5)

        self._main_panel.add(main_split, BorderLayout.CENTER)

        self.add_rule_panel(SwapRule("User1", "User2", "any", True))

        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerContextMenuFactory(self)

        print("[+] DeserAuth v1.2 loaded")
        print("[+] Passive analyzer + manual context menu + saved-rule context actions")

    def getTabCaption(self):
        return "DeserAuth"

    def getUiComponent(self):
        return self._main_panel

    def getHttpService(self):
        return None

    def getRequest(self):
        return None

    def getResponse(self):
        return None

    def createMenuItems(self, invocation):
        menu = ArrayList()

        msgs = invocation.getSelectedMessages()
        if msgs is None or len(msgs) == 0:
            return menu

        root = JMenu("DeserAuth")

        saved_rules = self.get_active_rules()
        if len(saved_rules) > 0:
            saved_menu = JMenu("Send to Repeater using Saved Rule")
            for i in range(len(saved_rules)):
                rule = saved_rules[i]
                label = "%s] %s -> %s" % (rule.mode.upper(), rule.search, rule.replace)
                item = JMenuItem(label)
                item.addActionListener(SavedRuleMenuAction(self, invocation, i))
                saved_menu.add(item)
            root.add(saved_menu)

        root.addSeparator()

        same_item = JMenuItem("Send to Repeater (Same Length)")
        same_item.addActionListener(ManualSameAction(self, invocation))
        root.add(same_item)

        any_item = JMenuItem("Send to Repeater (Any Length)")
        any_item.addActionListener(ManualAnyAction(self, invocation))
        root.add(any_item)

        batch_item = JMenuItem("Send to Repeater (Batch)")
        batch_item.addActionListener(ManualBatchAction(self, invocation))
        root.add(batch_item)

        menu.add(root)
        return menu

    def _next_repeater_label(self):
        self._repeater_counter += 1
        return "DeserAuth Swap " + str(self._repeater_counter)

    def _send_modified_request_to_repeater(self, http_service, headers, new_body):
        updated_headers = []
        for h in headers:
            if h.lower().startswith("content-length:"):
                updated_headers.append("Content-Length: " + str(len(new_body)))
            else:
                updated_headers.append(h)

        new_request = self._helpers.buildHttpMessage(updated_headers, new_body)

        self._callbacks.sendToRepeater(
            http_service.getHost(),
            http_service.getPort(),
            http_service.getProtocol().lower() == "https",
            new_request,
            self._next_repeater_label()
        )

    def context_send_saved_rule(self, invocation, rule_index):
        rules = self.get_active_rules()
        if rule_index < 0 or rule_index >= len(rules):
            return

        rule = rules[rule_index]
        messages = invocation.getSelectedMessages()
        if messages is None or len(messages) == 0:
            return

        for msg in messages:
            request = msg.getRequest()
            if request is None:
                continue

            http_service = msg.getHttpService()
            req_info = self._helpers.analyzeRequest(http_service, request)
            body_offset = req_info.getBodyOffset()
            headers = list(req_info.getHeaders())
            body = request[body_offset:]
            body_str = self._helpers.bytesToString(body)

            if rule.mode == "same":
                if len(rule.search) != len(rule.replace):
                    continue
                new_body_str = self.apply_swap_same(body_str, rule.search, rule.replace)
            else:
                new_body_str = self.apply_swap_any(body_str, rule.search, rule.replace)

            if new_body_str == body_str:
                continue

            new_body = self._helpers.stringToBytes(new_body_str)
            self._send_modified_request_to_repeater(http_service, headers, new_body)

    def context_send_to_repeater(self, invocation, mode):
        messages = invocation.getSelectedMessages()
        if messages is None or len(messages) == 0:
            return

        search = JOptionPane.showInputDialog(None, "Search string:", "DeserAuth", JOptionPane.PLAIN_MESSAGE)
        if search is None or len(str(search)) == 0:
            return

        replace = JOptionPane.showInputDialog(None, "Replace string:", "DeserAuth", JOptionPane.PLAIN_MESSAGE)
        if replace is None:
            return

        search = str(search)
        replace = str(replace)

        if mode == "same" and len(search) != len(replace):
            JOptionPane.showMessageDialog(None,
                "Same Length mode requires equal lengths.\nSearch=%d, Replace=%d" % (len(search), len(replace)),
                "DeserAuth", JOptionPane.WARNING_MESSAGE)
            return

        for msg in messages:
            request = msg.getRequest()
            if request is None:
                continue

            http_service = msg.getHttpService()
            req_info = self._helpers.analyzeRequest(http_service, request)
            body_offset = req_info.getBodyOffset()
            headers = list(req_info.getHeaders())
            body = request[body_offset:]
            body_str = self._helpers.bytesToString(body)

            if mode == "same":
                new_body_str = self.apply_swap_same(body_str, search, replace)
            else:
                new_body_str = self.apply_swap_any(body_str, search, replace)

            if new_body_str == body_str:
                continue

            new_body = self._helpers.stringToBytes(new_body_str)
            self._send_modified_request_to_repeater(http_service, headers, new_body)

    def context_send_to_repeater_batch(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages is None or len(messages) == 0:
            return

        search = JOptionPane.showInputDialog(None, "Search string:", "DeserAuth Batch", JOptionPane.PLAIN_MESSAGE)
        if search is None or len(str(search)) == 0:
            return
        search = str(search)

        payloads = JOptionPane.showInputDialog(
            None,
            "Replace values (comma-separated):\nExample:\nUser2,ID00001,<script>alert(1)</script>",
            "DeserAuth Batch",
            JOptionPane.PLAIN_MESSAGE
        )
        if payloads is None or len(str(payloads).strip()) == 0:
            return

        words = []
        parts = str(payloads).split(",")
        for p in parts:
            s = p.strip()
            if len(s) > 0:
                words.append(s)

        if len(words) == 0:
            return

        for msg in messages:
            request = msg.getRequest()
            if request is None:
                continue

            http_service = msg.getHttpService()
            req_info = self._helpers.analyzeRequest(http_service, request)
            body_offset = req_info.getBodyOffset()
            headers = list(req_info.getHeaders())
            body = request[body_offset:]
            body_str = self._helpers.bytesToString(body)

            for word in words:
                if len(search) == len(word):
                    new_body_str = self.apply_swap_same(body_str, search, word)
                else:
                    new_body_str = self.apply_swap_any(body_str, search, word)

                if new_body_str == body_str:
                    continue

                new_body = self._helpers.stringToBytes(new_body_str)
                self._send_modified_request_to_repeater(http_service, headers, new_body)

    def add_rule_panel(self, rule):
        panel = RulePanel(rule, self.remove_rule_panel)
        self._rule_panels.append(panel)
        self._rules_container.add(panel)
        self._rules_container.revalidate()
        self._rules_container.repaint()

    def remove_rule_panel(self, panel):
        if panel in self._rule_panels:
            self._rule_panels.remove(panel)
            self._rules_container.remove(panel)
            self._rules_container.revalidate()
            self._rules_container.repaint()

    def get_active_rules(self):
        rules = []
        for panel in self._rule_panels:
            rule = panel.get_rule()
            if rule.enabled and rule.search:
                rules.append(rule)
        return rules

    def toggle_running(self):
        if self._running:
            self._running = False
            self._start_btn.setText("   START   ")
            self._start_btn.setForeground(Color(0, 130, 0))
            self._status_label.setText("  STOPPED")
            self._status_label.setForeground(Color(150, 0, 0))
            print("[+] DeserAuth STOPPED")
        else:
            rules = self.get_active_rules()
            if not rules:
                JOptionPane.showMessageDialog(None,
                    "Add at least one enabled rule with a search value.",
                    "No Rules", JOptionPane.WARNING_MESSAGE)
                return
            self._running = True
            self._start_btn.setText("   STOP   ")
            self._start_btn.setForeground(Color(180, 0, 0))
            self._status_label.setText("  RUNNING (%d rules)" % len(rules))
            self._status_label.setForeground(Color(0, 130, 0))
            print("[+] DeserAuth STARTED (%d rules)" % len(rules))

    def is_in_scope(self, tool_flag):
        if tool_flag == self._callbacks.TOOL_PROXY and self._scope_proxy.isSelected():
            return True
        if tool_flag == self._callbacks.TOOL_REPEATER and self._scope_repeater.isSelected():
            return True
        if tool_flag == self._callbacks.TOOL_INTRUDER and self._scope_intruder.isSelected():
            return True
        if tool_flag == self._callbacks.TOOL_SCANNER and self._scope_scanner.isSelected():
            return True
        if tool_flag == self._callbacks.TOOL_SEQUENCER and self._scope_sequencer.isSelected():
            return True
        if tool_flag == self._callbacks.TOOL_SPIDER and self._scope_spider.isSelected():
            return True
        if tool_flag == self._callbacks.TOOL_EXTENDER and self._scope_extender.isSelected():
            return True
        if tool_flag == self._callbacks.TOOL_TARGET and self._scope_target.isSelected():
            return True
        return False

    def get_tool_name(self, tool_flag):
        if tool_flag == self._callbacks.TOOL_PROXY:
            return "Proxy"
        if tool_flag == self._callbacks.TOOL_REPEATER:
            return "Repeater"
        if tool_flag == self._callbacks.TOOL_INTRUDER:
            return "Intruder"
        if tool_flag == self._callbacks.TOOL_SCANNER:
            return "Scanner"
        if tool_flag == self._callbacks.TOOL_SEQUENCER:
            return "Sequencer"
        if tool_flag == self._callbacks.TOOL_SPIDER:
            return "Spider"
        if tool_flag == self._callbacks.TOOL_EXTENDER:
            return "Extender"
        if tool_flag == self._callbacks.TOOL_TARGET:
            return "Target"
        return "Tool-%d" % tool_flag

    def to_java_chars(self, text):
        result = ""
        for c in text:
            result += chr(0x00) + c
        return result

    def apply_swap_same(self, data_str, search_str, replace_str):
        java_search = self.to_java_chars(search_str)
        java_replace = self.to_java_chars(replace_str)
        data_str = data_str.replace(java_search, java_replace)
        data_str = data_str.replace(search_str, replace_str)
        return data_str

    def apply_swap_any(self, data_str, search_str, replace_str):
        java_search = self.to_java_chars(search_str)

        search_pos = 0
        while True:
            idx = data_str.find(java_search, search_pos)
            if idx == -1:
                break

            end_of_string = idx + len(java_search)
            padding_end = end_of_string
            while padding_end + 1 < len(data_str):
                if data_str[padding_end] == chr(0x00) and data_str[padding_end + 1] == chr(0x00):
                    padding_end += 2
                else:
                    break

            available_space = (padding_end - idx) // 2

            if len(replace_str) <= available_space:
                java_replace = self.to_java_chars(replace_str)
                remaining_nulls = (available_space - len(replace_str)) * 2
                replacement = java_replace + (chr(0x00) * remaining_nulls)
                data_str = data_str[:idx] + replacement + data_str[padding_end:]
            else:
                java_replace = self.to_java_chars(replace_str)
                data_str = data_str[:idx] + java_replace + data_str[padding_end:]

                array_size_offset = idx - 4
                if array_size_offset >= 0:
                    old_size_bytes = data_str[array_size_offset:array_size_offset + 4]
                    old_size = (ord(old_size_bytes[0]) << 24) | (ord(old_size_bytes[1]) << 16) | (ord(old_size_bytes[2]) << 8) | ord(old_size_bytes[3])
                    new_size = len(replace_str)

                    if old_size < 10000:
                        new_size_bytes = chr((new_size >> 24) & 0xFF) + chr((new_size >> 16) & 0xFF) + chr((new_size >> 8) & 0xFF) + chr(new_size & 0xFF)
                        data_str = data_str[:array_size_offset] + new_size_bytes + data_str[array_size_offset + 4:]

                search_pos = idx + len(java_replace)
                continue

            search_pos = idx + len(java_replace)

        start = 0
        while True:
            idx = data_str.find(search_str, start)
            if idx == -1:
                break

            if idx >= 3:
                marker = ord(data_str[idx - 3])
                len_hi = ord(data_str[idx - 2])
                len_lo = ord(data_str[idx - 1])
                stored_len = (len_hi << 8) | len_lo

                if marker == 0x74 and stored_len == len(search_str):
                    new_len = len(replace_str)
                    new_len_bytes = chr((new_len >> 8) & 0xFF) + chr(new_len & 0xFF)
                    data_str = data_str[:idx - 2] + new_len_bytes + replace_str + data_str[idx + len(search_str):]
                    start = idx + len(replace_str)
                    continue

            data_str = data_str[:idx] + replace_str + data_str[idx + len(search_str):]
            start = idx + len(replace_str)

        return data_str

    def apply_rules(self, body):
        data_str = self._helpers.bytesToString(body)

        rules = self.get_active_rules()
        for rule in rules:
            java_search = self.to_java_chars(rule.search)
            if java_search not in data_str and rule.search not in data_str:
                continue

            if rule.mode == "same":
                data_str = self.apply_swap_same(data_str, rule.search, rule.replace)
            else:
                data_str = self.apply_swap_any(data_str, rule.search, rule.replace)

        return self._helpers.stringToBytes(data_str)

    def compare_responses(self, orig_response, mod_response):
        if orig_response is None or mod_response is None:
            return "DIFFERENT", "100%"

        orig_info = self._helpers.analyzeResponse(orig_response)
        mod_info = self._helpers.analyzeResponse(mod_response)

        orig_status = orig_info.getStatusCode()
        mod_status = mod_info.getStatusCode()
        orig_body_len = len(orig_response) - orig_info.getBodyOffset()
        mod_body_len = len(mod_response) - mod_info.getBodyOffset()

        if orig_status == mod_status and orig_body_len == mod_body_len:
            return "SAME", "0%"
        elif orig_status == mod_status:
            diff_pct = abs(orig_body_len - mod_body_len) * 100.0 / max(orig_body_len, 1)
            pct_str = "%.1f%%" % diff_pct
            if diff_pct < 5:
                return "SIMILAR", pct_str
            else:
                return "DIFFERENT", pct_str
        else:
            diff_pct = abs(orig_body_len - mod_body_len) * 100.0 / max(orig_body_len, 1)
            return "DIFFERENT", "%.1f%%" % diff_pct

    def _safe_str(self, val):
        if val is None:
            return ""
        if isinstance(val, str):
            result = ""
            for ch in val:
                o = ord(ch)
                if 32 <= o < 127:
                    result += ch
                elif o == 10:
                    result += "\n"
                elif o == 13:
                    result += "\r"
                elif o == 9:
                    result += "\t"
                else:
                    result += "\\x%02x" % o
            return result
        return str(val)

    def _get_field_value(self, entry, field):
        if field == "orig_request_body":
            if entry.orig_request:
                info = self._helpers.analyzeRequest(entry.orig_request)
                raw = self._helpers.bytesToString(entry.orig_request[info.getBodyOffset():])
                return self._safe_str(raw)
            return ""
        elif field == "orig_response_body":
            if entry.orig_response:
                info = self._helpers.analyzeResponse(entry.orig_response)
                raw = self._helpers.bytesToString(entry.orig_response[info.getBodyOffset():])
                return self._safe_str(raw)
            return ""
        elif field == "mod_request_body":
            if entry.mod_request:
                info = self._helpers.analyzeRequest(entry.mod_request)
                raw = self._helpers.bytesToString(entry.mod_request[info.getBodyOffset():])
                return self._safe_str(raw)
            return ""
        elif field == "mod_response_body":
            if entry.mod_response:
                info = self._helpers.analyzeResponse(entry.mod_response)
                raw = self._helpers.bytesToString(entry.mod_response[info.getBodyOffset():])
                return self._safe_str(raw)
            return ""
        elif field == "orig_headers":
            return self._safe_str(entry.orig_headers)
        elif field == "mod_headers":
            return self._safe_str(entry.mod_headers)
        else:
            return str(getattr(entry, field, ""))

    def _escape_csv(self, val):
        val = val.replace('"', '""')
        if ',' in val or '"' in val or '\n' in val:
            return '"' + val + '"'
        return val

    def _escape_html(self, val):
        return val.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def _escape_xml(self, val):
        return val.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")

    def show_export_dialog(self):
        log = self._table_model.getLog()
        if not log:
            JOptionPane.showMessageDialog(None, "No data to export.", "Export", JOptionPane.INFORMATION_MESSAGE)
            return

        export_panel = JPanel()
        export_panel.setLayout(BoxLayout(export_panel, BoxLayout.Y_AXIS))

        export_panel.add(JLabel("Select fields to include:"))
        export_panel.add(Box.createVerticalStrut(5))

        cb_tool = JCheckBox("Tool", True)
        cb_method = JCheckBox("Method", True)
        cb_host = JCheckBox("Host", True)
        cb_path = JCheckBox("Path", True)
        cb_url = JCheckBox("Full URL", True)
        cb_orig_status = JCheckBox("Original Status", True)
        cb_orig_length = JCheckBox("Original Length", True)
        cb_mod_status = JCheckBox("Modified Status", True)
        cb_mod_length = JCheckBox("Modified Length", True)
        cb_difference = JCheckBox("Difference", True)
        cb_diff_pct = JCheckBox("Diff %", True)
        cb_time = JCheckBox("Time", True)
        cb_orig_headers = JCheckBox("Original Headers", False)
        cb_mod_headers = JCheckBox("Modified Headers", False)
        cb_orig_request = JCheckBox("Original Request Body", False)
        cb_orig_response = JCheckBox("Original Response Body", False)
        cb_mod_request = JCheckBox("Modified Request Body", False)
        cb_mod_response = JCheckBox("Modified Response Body", False)

        export_panel.add(cb_tool)
        export_panel.add(cb_method)
        export_panel.add(cb_host)
        export_panel.add(cb_path)
        export_panel.add(cb_url)
        export_panel.add(cb_orig_status)
        export_panel.add(cb_orig_length)
        export_panel.add(cb_mod_status)
        export_panel.add(cb_mod_length)
        export_panel.add(cb_difference)
        export_panel.add(cb_diff_pct)
        export_panel.add(cb_time)
        export_panel.add(cb_orig_headers)
        export_panel.add(cb_mod_headers)
        export_panel.add(cb_orig_request)
        export_panel.add(cb_orig_response)
        export_panel.add(cb_mod_request)
        export_panel.add(cb_mod_response)

        export_panel.add(Box.createVerticalStrut(10))
        export_panel.add(JLabel("Export format:"))
        format_combo = JComboBox(["CSV", "HTML", "XML", "Excel (HTML)"])
        export_panel.add(format_combo)

        result = JOptionPane.showConfirmDialog(None, export_panel, "DeserAuth - Export Options",
                                               JOptionPane.OK_CANCEL_OPTION)
        if result != JOptionPane.OK_OPTION:
            return

        fields = []
        if cb_tool.isSelected():
            fields.append("tool")
        if cb_method.isSelected():
            fields.append("method")
        if cb_host.isSelected():
            fields.append("host")
        if cb_path.isSelected():
            fields.append("path")
        if cb_url.isSelected():
            fields.append("url")
        if cb_orig_status.isSelected():
            fields.append("orig_status")
        if cb_orig_length.isSelected():
            fields.append("orig_length")
        if cb_mod_status.isSelected():
            fields.append("mod_status")
        if cb_mod_length.isSelected():
            fields.append("mod_length")
        if cb_difference.isSelected():
            fields.append("difference")
        if cb_diff_pct.isSelected():
            fields.append("diff_pct")
        if cb_time.isSelected():
            fields.append("timestamp")
        if cb_orig_headers.isSelected():
            fields.append("orig_headers")
        if cb_mod_headers.isSelected():
            fields.append("mod_headers")
        if cb_orig_request.isSelected():
            fields.append("orig_request_body")
        if cb_orig_response.isSelected():
            fields.append("orig_response_body")
        if cb_mod_request.isSelected():
            fields.append("mod_request_body")
        if cb_mod_response.isSelected():
            fields.append("mod_response_body")

        if not fields:
            JOptionPane.showMessageDialog(None, "Select at least one field.", "Export", JOptionPane.WARNING_MESSAGE)
            return

        fmt = format_combo.getSelectedIndex()
        extensions = [["csv"], ["html"], ["xml"], ["xls"]]
        descriptions = ["CSV Files", "HTML Files", "XML Files", "Excel Files"]
        ext = extensions[fmt][0]

        chooser = JFileChooser()
        chooser.setFileFilter(FileNameExtensionFilter(descriptions[fmt], extensions[fmt]))
        chooser.setSelectedFile(File("deserauth_export." + ext))

        if chooser.showSaveDialog(None) != JFileChooser.APPROVE_OPTION:
            return

        filepath = chooser.getSelectedFile().getAbsolutePath()
        if not filepath.endswith("." + ext):
            filepath = filepath + "." + ext

        try:
            if fmt == 0:
                self._export_csv(filepath, log, fields)
            elif fmt == 1:
                self._export_html(filepath, log, fields)
            elif fmt == 2:
                self._export_xml(filepath, log, fields)
            elif fmt == 3:
                self._export_excel_html(filepath, log, fields)

            JOptionPane.showMessageDialog(None,
                "Exported %d entries to:\n%s" % (len(log), filepath),
                "Export Complete", JOptionPane.INFORMATION_MESSAGE)
            print("[+] Exported %d entries to %s" % (len(log), filepath))
        except Exception as e:
            JOptionPane.showMessageDialog(None,
                "Export failed: %s" % str(e),
                "Error", JOptionPane.ERROR_MESSAGE)
            print("[!] Export error: %s" % str(e))

    def _export_csv(self, filepath, log, fields):
        f = open(filepath, 'wb')
        header = ",".join(fields) + "\n"
        f.write(header.encode('utf-8'))
        for entry in log:
            row = []
            for field in fields:
                val = self._get_field_value(entry, field)
                row.append(self._escape_csv(val))
            line = ",".join(row) + "\n"
            f.write(line.encode('utf-8'))
        f.close()

    def _export_html(self, filepath, log, fields):
        f = open(filepath, 'wb')
        out = "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>DeserAuth Export</title>\n"
        out += "<style>body{font-family:sans-serif;margin:20px}table{border-collapse:collapse;width:100%}"
        out += "th,td{border:1px solid #ddd;padding:8px;text-align:left;font-size:12px}"
        out += "th{background:#333;color:white}tr:nth-child(even){background:#f9f9f9}"
        out += ".SAME{background:#c8ffc8}.SIMILAR{background:#ffffb4}.DIFFERENT{background:#ffc8c8}"
        out += "td.body{max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;font-size:10px}"
        out += "</style></head><body>\n"
        out += "<h2>DeserAuth - Deserialization Authorization Analyzer Report</h2>\n"
        out += "<p>Generated: %s | Entries: %d</p>\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), len(log))
        out += "<table><tr>"
        for field in fields:
            out += "<th>%s</th>" % self._escape_html(field)
        out += "</tr>\n"
        f.write(out.encode('utf-8'))

        body_fields = ["orig_request_body", "orig_response_body", "mod_request_body", "mod_response_body"]

        for entry in log:
            css_class = entry.difference
            row_out = '<tr class="%s">' % css_class
            for field in fields:
                val = self._get_field_value(entry, field)
                if field in body_fields:
                    display_val = val[:500]
                    if len(val) > 500:
                        display_val += "... [truncated %d chars]" % len(val)
                    row_out += '<td class="body">%s</td>' % self._escape_html(display_val)
                else:
                    row_out += "<td>%s</td>" % self._escape_html(val)
            row_out += "</tr>\n"
            f.write(row_out.encode('utf-8'))

        f.write("</table></body></html>".encode('utf-8'))
        f.close()

    def _export_xml(self, filepath, log, fields):
        f = open(filepath, 'wb')
        out = '<?xml version="1.0" encoding="UTF-8"?>\n'
        out += '<deserauth_export generator="DeserAuth v1.2" date="%s" count="%d">\n' % (time.strftime("%Y-%m-%d %H:%M:%S"), len(log))
        f.write(out.encode('utf-8'))

        for i, entry in enumerate(log):
            entry_out = "  <entry id=\"%d\">\n" % (i + 1)
            for field in fields:
                val = self._get_field_value(entry, field)
                entry_out += "    <%s>%s</%s>\n" % (field, self._escape_xml(val), field)
            entry_out += "  </entry>\n"
            f.write(entry_out.encode('utf-8'))

        f.write("</deserauth_export>\n".encode('utf-8'))
        f.close()

    def _export_excel_html(self, filepath, log, fields):
        f = open(filepath, 'wb')
        out = "<html xmlns:o=\"urn:schemas-microsoft-com:office:office\" "
        out += "xmlns:x=\"urn:schemas-microsoft-com:office:excel\">\n"
        out += "<head><meta charset=\"UTF-8\">\n"
        out += "<!--[if gte mso 9]><xml><x:ExcelWorkbook><x:ExcelWorksheets>"
        out += "<x:ExcelWorksheet><x:Name>DeserAuth</x:Name>"
        out += "</x:ExcelWorksheet></x:ExcelWorksheets></x:ExcelWorkbook></xml><![endif]-->\n"
        out += "<style>td{mso-number-format:\\@;border:1px solid #ccc;padding:4px;font-size:11px}"
        out += "th{background:#333;color:white;padding:6px;font-size:11px}"
        out += ".SAME{background:#c8ffc8}.SIMILAR{background:#ffffb4}.DIFFERENT{background:#ffc8c8}"
        out += "</style></head><body>\n"
        out += "<table><tr>"
        for field in fields:
            out += "<th>%s</th>" % self._escape_html(field)
        out += "</tr>\n"
        f.write(out.encode('utf-8'))

        for entry in log:
            css_class = entry.difference
            row_out = '<tr class="%s">' % css_class
            for field in fields:
                val = self._get_field_value(entry, field)
                row_out += "<td>%s</td>" % self._escape_html(val)
            row_out += "</tr>\n"
            f.write(row_out.encode('utf-8'))

        f.write("</table></body></html>".encode('utf-8'))
        f.close()

    def processHttpMessage(self, tool_flag, is_request, message_info):
        if not self._running:
            return
        if is_request:
            return
        if not self.is_in_scope(tool_flag):
            return

        comment = message_info.getComment()
        if comment and comment.startswith("SSA-"):
            return

        request = message_info.getRequest()
        if request is None:
            return

        response = message_info.getResponse()
        if response is None:
            return

        info = self._helpers.analyzeRequest(message_info.getHttpService(), request)
        body_offset = info.getBodyOffset()

        if body_offset >= len(request):
            return

        body = request[body_offset:]
        if len(body) < 4:
            return

        body_str = self._helpers.bytesToString(body)

        rules = self.get_active_rules()
        has_match = False
        for rule in rules:
            if rule.search in body_str or self.to_java_chars(rule.search) in body_str:
                has_match = True
                break

        if not has_match:
            return

        orig_request = request[:]
        orig_response = response[:]
        http_service = message_info.getHttpService()
        url = str(info.getUrl())
        method = info.getMethod()
        tool_name = self.get_tool_name(tool_flag)
        host = http_service.getHost()
        path = str(info.getUrl().getPath())

        thread = Thread(target=self._process_match,
                       args=(orig_request, orig_response, http_service,
                             url, method, tool_name, body_offset, host, path))
        thread.setDaemon(True)
        thread.start()

    def _process_match(self, orig_request, orig_response, http_service,
                       url, method, tool_name, body_offset, host, path):
        try:
            headers = list(self._helpers.analyzeRequest(orig_request).getHeaders())
            body = orig_request[body_offset:]

            new_body = self.apply_rules(body)

            orig_body_str = self._helpers.bytesToString(body)
            new_body_str = self._helpers.bytesToString(new_body)
            if orig_body_str == new_body_str:
                return

            updated_headers = []
            for h in headers:
                if h.lower().startswith("content-length:"):
                    updated_headers.append("Content-Length: " + str(len(new_body)))
                else:
                    updated_headers.append(h)

            mod_request = self._helpers.buildHttpMessage(updated_headers, new_body)

            mod_response_obj = self._callbacks.makeHttpRequest(http_service, mod_request)
            mod_response_obj.setComment("SSA-auto")
            mod_response = mod_response_obj.getResponse()

            orig_analyzed = self._helpers.analyzeResponse(orig_response)
            orig_status = str(orig_analyzed.getStatusCode())
            orig_body_length = str(len(orig_response) - orig_analyzed.getBodyOffset())

            mod_status = "0"
            mod_body_length = "0"
            if mod_response:
                mod_analyzed = self._helpers.analyzeResponse(mod_response)
                mod_status = str(mod_analyzed.getStatusCode())
                mod_body_length = str(len(mod_response) - mod_analyzed.getBodyOffset())

            difference, diff_pct = self.compare_responses(orig_response, mod_response)

            timestamp = time.strftime("%H:%M:%S")

            orig_headers_str = "\n".join(headers)
            mod_headers_str = "\n".join(updated_headers)

            entry = LogEntry(
                tool=tool_name,
                method=method,
                host=host,
                path=path,
                url=url,
                orig_status=orig_status,
                orig_length=orig_body_length,
                mod_status=mod_status,
                mod_length=mod_body_length,
                difference=difference,
                diff_pct=diff_pct,
                timestamp=timestamp,
                orig_request=orig_request,
                orig_response=orig_response,
                mod_request=mod_request,
                mod_response=mod_response,
                http_service=http_service,
                orig_headers=orig_headers_str,
                mod_headers=mod_headers_str
            )

            SwingUtilities.invokeLater(AddEntryRunnable(self._table_model, entry))

        except Exception as e:
            print("[!] Error: %s" % str(e))
