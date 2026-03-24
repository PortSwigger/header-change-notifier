# -*- coding: utf-8 -*-
# Header Change Notifier - Burp Suite Extension
# Version: 2.1.0
# Author: Mohamed Essam
# Description: Detects and alerts when HTTP response headers change between requests (Passive Scanner)

from burp import IBurpExtender, ITab, IScannerCheck, IScanIssue, IMessageEditorController
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, Color, Font
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JButton, JLabel, JTextField,
                         JCheckBox, JOptionPane, JFileChooser, JSplitPane, JList, DefaultListModel,
                         ListSelectionModel, BorderFactory, SwingConstants, UIManager, JTextArea)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing import SwingUtilities
from javax.swing import ListCellRenderer
from javax.swing.event import ListSelectionListener
from java.io import File
from java.net import URL
from java.util import Date
import threading
import time
import csv


def _get_risk_colors(risk_level):
    """
    Return (foreground, background) colors for a risk level that work in both
    Burp light and dark themes.  We use saturated foreground text on a
    transparent/default background rather than tinted cell backgrounds so that
    the colours remain readable regardless of the theme's base palette.
    """
    colors = {
        "Critical": (Color(200, 50,  50),  None),   # Bold red fg
        "High":     (Color(210, 120, 30),  None),   # Orange fg
        "Medium":   (Color(160, 130, 0),   None),   # Dark yellow fg
        "Low":      (Color(40,  140, 60),  None),   # Green fg
    }
    return colors.get(risk_level, (None, None))


class BurpExtender(IBurpExtender, ITab, IScannerCheck, IMessageEditorController):

    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        self.EXTENSION_NAME = "Header Change Notifier"
        self.VERSION = "2.1.0"

        callbacks.setExtensionName(self.EXTENSION_NAME)

        # Data structures
        self._header_storage   = {}
        self._detected_changes = []          # list of change_record dicts
        self._scan_issues      = {}          # change_record id -> HeaderChangeScanIssue
        self._lock             = threading.Lock()

        self._tracked_headers = {
            'set-cookie':                True,
            'content-security-policy':   True,
            'x-frame-options':           True,
            'x-content-type-options':    True,
            'referrer-policy':           True,
            'strict-transport-security': True,
            'x-xss-protection':          True,
            'access-control-allow-origin': True,
            'server':                    True,
            'x-powered-by':              True,
        }

        # Currently selected request/response for the message editors
        self._current_request_response = None

        self._init_ui()
        callbacks.registerScannerCheck(self)
        callbacks.addSuiteTab(self)

        print("[+] Header Change Notifier v{} loaded successfully!".format(self.VERSION))

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _init_ui(self):
        self._main_panel  = JPanel(BorderLayout())
        self._tabbed_pane = JTabbedPane()
        self._create_changes_tab()
        self._create_settings_tab()
        self._main_panel.add(self._tabbed_pane, BorderLayout.CENTER)

    def _create_changes_tab(self):
        outer = JPanel(BorderLayout())

        # ── toolbar ──────────────────────────────────────────────────
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))

        clear_btn = JButton("Clear All", actionPerformed=self._clear_all_data)
        clear_btn.setPreferredSize(Dimension(100, 30))

        export_btn = JButton("Export CSV", actionPerformed=self._export_to_csv)
        export_btn.setPreferredSize(Dimension(130, 30))          # fix: was too narrow

        self._stats_label = JLabel("Changes detected: 0  |  URLs monitored: 0")
        self._stats_label.setFont(Font("Dialog", Font.PLAIN, 12))

        toolbar.add(clear_btn)
        toolbar.add(export_btn)
        toolbar.add(JLabel("  |  "))
        toolbar.add(self._stats_label)

        # ── table ─────────────────────────────────────────────────────
        self._changes_table_model = ReadOnlyTableModel(
            [], ["Timestamp", "URL", "Header", "Old Value", "New Value", "Risk Level"]
        )

        self._changes_table = JTable(self._changes_table_model)
        self._changes_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self._changes_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        col_widths = [150, 300, 200, 250, 250, 100]
        for i, w in enumerate(col_widths):
            self._changes_table.getColumnModel().getColumn(i).setPreferredWidth(w)

        self._changes_table.getColumnModel().getColumn(5).setCellRenderer(
            RiskLevelCellRenderer()
        )

        # Selection listener → update detail/editor panels
        self._changes_table.getSelectionModel().addListSelectionListener(
            TableSelectionHandler(self)
        )

        table_scroll = JScrollPane(self._changes_table)

        # ── detail panel (issue info + request/response editors) ──────
        detail_panel = self._create_detail_panel()

        # ── split pane ────────────────────────────────────────────────
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, detail_panel)
        split.setResizeWeight(0.45)
        split.setDividerLocation(300)

        outer.add(toolbar, BorderLayout.NORTH)
        outer.add(split,   BorderLayout.CENTER)

        self._tabbed_pane.addTab("Header Changes", outer)

    def _create_detail_panel(self):
        """
        Returns a tabbed pane with:
          • Issue Details  textual summary of the selected change / ScanIssue
          • Request        Burp message editor (read-only)
          • Response       Burp message editor (read-only)
        """
        self._detail_tabs = JTabbedPane()

        # Issue details
        self._detail_text = JTextArea()
        self._detail_text.setEditable(False)
        self._detail_text.setLineWrap(True)
        self._detail_text.setWrapStyleWord(True)
        self._detail_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._detail_text.setText("Select a row to view issue details.")
        self._detail_tabs.addTab("Issue Details", JScrollPane(self._detail_text))

        # Request / Response editors (Burp native viewers)
        self._request_editor  = self._callbacks.createMessageEditor(self, False)
        self._response_editor = self._callbacks.createMessageEditor(self, False)
        self._detail_tabs.addTab("Request",  self._request_editor.getComponent())
        self._detail_tabs.addTab("Response", self._response_editor.getComponent())

        return self._detail_tabs

    def _create_settings_tab(self):
        settings_panel = JPanel(BorderLayout())

        top = JPanel(GridBagLayout())
        gbc = GridBagConstraints()

        title_label = JLabel("Header Tracking Configuration")
        title_label.setFont(Font("Dialog", Font.BOLD, 16))
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2
        gbc.insets = Insets(10, 10, 15, 10)
        top.add(title_label, gbc)

        # ── dynamic header list ───────────────────────────────────────
        list_label = JLabel("Tracked Headers")
        list_label.setFont(Font("Dialog", Font.PLAIN, 12))
        gbc.gridy = 1; gbc.insets = Insets(0, 20, 4, 20)
        top.add(list_label, gbc)

        self._header_list_model = DefaultListModel()
        self._header_jlist      = JList(self._header_list_model)
        self._header_jlist.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._header_jlist.setCellRenderer(HeaderListCellRenderer(self._tracked_headers))

        # Populate list
        for h in sorted(self._tracked_headers.keys()):
            self._header_list_model.addElement(h)

        list_scroll = JScrollPane(self._header_jlist)
        list_scroll.setPreferredSize(Dimension(500, 200))

        gbc.gridy = 2; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(0, 20, 10, 20)
        top.add(list_scroll, gbc)

        # Toggle + Remove buttons
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        toggle_btn = JButton("Toggle Enable/Disable", actionPerformed=self._toggle_header)
        remove_btn = JButton("Remove Selected",       actionPerformed=self._remove_header)
        btn_panel.add(toggle_btn)
        btn_panel.add(remove_btn)

        gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE
        gbc.insets = Insets(0, 20, 15, 20)
        top.add(btn_panel, gbc)

        # ── add custom header ─────────────────────────────────────────
        add_label = JLabel("Add Custom Header:")
        add_label.setFont(Font("Dialog", Font.BOLD, 12))
        gbc.gridy = 4; gbc.gridwidth = 2
        gbc.insets = Insets(5, 20, 5, 20)
        top.add(add_label, gbc)

        self._custom_header_field = JTextField(25)
        add_btn = JButton("Add", actionPerformed=self._add_custom_header)

        custom_row = JPanel(FlowLayout(FlowLayout.LEFT))
        custom_row.add(self._custom_header_field)
        custom_row.add(add_btn)

        gbc.gridy = 5
        gbc.insets = Insets(0, 20, 20, 20)
        top.add(custom_row, gbc)

        settings_panel.add(top, BorderLayout.NORTH)
        self._tabbed_pane.addTab("Settings", settings_panel)

    # ------------------------------------------------------------------
    # IMessageEditorController
    # ------------------------------------------------------------------

    def getHttpService(self):
        if self._current_request_response:
            return self._current_request_response.getHttpService()
        return None

    def getRequest(self):
        if self._current_request_response:
            return self._current_request_response.getRequest()
        return None

    def getResponse(self):
        if self._current_request_response:
            return self._current_request_response.getResponse()
        return None

    # ------------------------------------------------------------------
    # Table selection handler (called from TableSelectionHandler)
    # ------------------------------------------------------------------

    def _on_row_selected(self, row_index):
        if row_index < 0 or row_index >= len(self._detected_changes):
            return

        change_record = self._detected_changes[row_index]
        issue         = self._scan_issues.get(id(change_record))

        # Update request/response editors
        brr = change_record.get('baseRequestResponse')
        if brr:
            self._current_request_response = brr
            self._request_editor.setMessage(brr.getRequest(),  True)
            self._response_editor.setMessage(brr.getResponse(), False)
        else:
            self._current_request_response = None
            self._request_editor.setMessage(bytearray(), True)
            self._response_editor.setMessage(bytearray(), False)

        # Update issue details text
        old_val = change_record['old_value'] or "(header was not present)"
        new_val = change_record['new_value'] or "(header was removed)"
        lines = [
            "Header      : {}".format(change_record['header']),
            "URL         : {}".format(change_record['url']),
            "Risk Level  : {}".format(change_record['risk_level']),
            "Detected    : {}".format(change_record['timestamp'].toString()),
            "",
            "Previous Value:",
            "  {}".format(old_val),
            "",
            "New Value:",
            "  {}".format(new_val),
        ]

        if issue:
            lines += [
                "",
                "Scanner Issue",
                "Name        : {}".format(issue.getIssueName()),
                "Severity    : {}".format(issue.getSeverity()),
                "Confidence  : {}".format(issue.getConfidence()),
                "",
                "Background:",
            ]
            # Strip basic HTML tags for plain-text display
            bg = issue.getIssueBackground()
            for tag in ["<p>","</p>","<ul>","</ul>","<li>","</li>","<b>","</b>","<pre>","</pre>"]:
                bg = bg.replace(tag, "")
            lines += [l.strip() for l in bg.strip().splitlines() if l.strip()]

        self._detail_text.setText("\n".join(lines))
        self._detail_text.setCaretPosition(0)

    # ------------------------------------------------------------------
    # IScannerCheck
    # ------------------------------------------------------------------

    def doPassiveScan(self, baseRequestResponse):
        try:
            response = baseRequestResponse.getResponse()
            if response is None:
                return None

            response_info = self._helpers.analyzeResponse(response)
            headers       = response_info.getHeaders()

            url      = str(baseRequestResponse.getUrl())
            url_obj  = URL(url)
            url_path = url_obj.getPath() or '/'
            base_url = "{}://{}{}".format(url_obj.getProtocol(), url_obj.getHost(), url_path)

            issues = self._process_headers_passive(base_url, headers, baseRequestResponse)
            return issues if issues else None

        except Exception as e:
            print("[-] Error in passive scan: {}".format(str(e)))
            return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getUrl() == newIssue.getUrl() and
                existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        return 0

    # ------------------------------------------------------------------
    # Header processing
    # ------------------------------------------------------------------

    def _process_headers_passive(self, url, headers, baseRequestResponse):
        issues = []

        with self._lock:
            current_headers = {}
            for header in headers[1:]:
                if ':' in header:
                    name, value = header.split(':', 1)
                    name  = name.strip().lower()
                    value = value.strip()
                    if name in self._tracked_headers and self._tracked_headers[name]:
                        current_headers[name] = value

            if url in self._header_storage:
                previous_headers = self._header_storage[url]['headers']
                change_records   = self._compare_headers_passive(
                    url, previous_headers, current_headers, baseRequestResponse
                )

                for cr in change_records:
                    issue = HeaderChangeScanIssue(
                        baseRequestResponse, self._helpers, self._callbacks, cr
                    )
                    issues.append(issue)
                    self._scan_issues[id(cr)] = issue
                    self._detected_changes.append(cr)
                    SwingUtilities.invokeLater(lambda _cr=cr: self._add_change_to_table(_cr))

            self._header_storage[url] = {
                'headers':   current_headers,
                'timestamp': time.time(),
            }
            SwingUtilities.invokeLater(self._update_stats)

        return issues if issues else None

    def _compare_headers_passive(self, url, old_headers, new_headers, baseRequestResponse):
        changes     = []
        all_headers = set(old_headers.keys()) | set(new_headers.keys())

        for header in all_headers:
            old_value = old_headers.get(header, '')
            new_value = new_headers.get(header, '')

            if old_value != new_value:
                cr = {
                    'timestamp':           Date(),
                    'url':                 url,
                    'header':              header,
                    'old_value':           old_value,
                    'new_value':           new_value,
                    'risk_level':          self._assess_risk_level(header, old_value, new_value),
                    'baseRequestResponse': baseRequestResponse,
                }
                changes.append(cr)

        return changes

    def _assess_risk_level(self, header, old_value, new_value):
        critical_headers = ['content-security-policy', 'x-frame-options']
        if header in critical_headers:
            return 'Critical' if (old_value and not new_value) else 'High'

        high_risk_headers = ['strict-transport-security', 'set-cookie']
        if header in high_risk_headers:
            if 'secure' in old_value.lower() and 'secure' not in new_value.lower():
                return 'High'
            if 'httponly' in old_value.lower() and 'httponly' not in new_value.lower():
                return 'High'
            return 'Medium'

        medium_risk_headers = ['referrer-policy', 'x-content-type-options']
        if header in medium_risk_headers:
            return 'Medium'

        return 'Low'

    # ------------------------------------------------------------------
    # UI helpers
    # ------------------------------------------------------------------

    def _add_change_to_table(self, cr):
        row = [
            cr['timestamp'].toString(),
            cr['url'],
            cr['header'],
            cr['old_value'][:100] + ('...' if len(cr['old_value']) > 100 else ''),
            cr['new_value'][:100] + ('...' if len(cr['new_value']) > 100 else ''),
            cr['risk_level'],
        ]
        self._changes_table_model.addRow(row)

    def _update_stats(self):
        self._stats_label.setText(
            "Changes detected: {}  |  URLs monitored: {}".format(
                len(self._detected_changes), len(self._header_storage)
            )
        )

    # ------------------------------------------------------------------
    # Button / action handlers
    # ------------------------------------------------------------------

    def _clear_all_data(self, event):
        with self._lock:
            self._header_storage.clear()
            self._detected_changes[:] = []
            self._scan_issues.clear()
            self._changes_table_model.setRowCount(0)
            self._update_stats()

        self._detail_text.setText("Select a row to view issue details.")
        self._current_request_response = None
        self._request_editor.setMessage(bytearray(), True)
        self._response_editor.setMessage(bytearray(), False)

        JOptionPane.showMessageDialog(
            self._main_panel, "All data cleared successfully!",
            "Clear Complete", JOptionPane.INFORMATION_MESSAGE
        )

    def _export_to_csv(self, event):
        if not self._detected_changes:
            JOptionPane.showMessageDialog(
                self._main_panel, "No changes to export!",
                "Export Error", JOptionPane.WARNING_MESSAGE
            )
            return

        chooser = JFileChooser()
        chooser.setSelectedFile(File("header_changes.csv"))

        if chooser.showSaveDialog(self._main_panel) == JFileChooser.APPROVE_OPTION:
            try:
                path = chooser.getSelectedFile().getAbsolutePath()
                with open(path, 'wb') as f:
                    w = csv.writer(f)
                    w.writerow(['Timestamp', 'URL', 'Header', 'Old Value', 'New Value', 'Risk Level'])
                    for cr in self._detected_changes:
                        w.writerow([
                            str(cr['timestamp']), cr['url'], cr['header'],
                            cr['old_value'], cr['new_value'], cr['risk_level']
                        ])

                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Changes exported successfully to:\n{}".format(path),
                    "Export Complete", JOptionPane.INFORMATION_MESSAGE
                )
            except Exception as e:
                JOptionPane.showMessageDialog(
                    self._main_panel, "Export failed: {}".format(str(e)),
                    "Export Error", JOptionPane.ERROR_MESSAGE
                )

    # ── dynamic settings actions ───────────────────────────────────────

    def _add_custom_header(self, event):
        """Add header to both the live dict and the JList immediately."""
        header_name = self._custom_header_field.getText().strip().lower()

        if not header_name:
            JOptionPane.showMessageDialog(
                self._main_panel, "Please enter a header name!",
                "Invalid Input", JOptionPane.WARNING_MESSAGE
            )
            return

        if header_name in self._tracked_headers:
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Header '{}' is already being tracked!".format(header_name),
                "Duplicate Header", JOptionPane.WARNING_MESSAGE
            )
            return

        # Update the live dict and the list model – no restart required
        self._tracked_headers[header_name] = True
        self._header_list_model.addElement(header_name)
        self._custom_header_field.setText("")

        JOptionPane.showMessageDialog(
            self._main_panel,
            "Header '{}' added and is now being tracked.".format(header_name),
            "Header Added", JOptionPane.INFORMATION_MESSAGE
        )

    def _toggle_header(self, event):
        """Toggle the enabled state of the selected header in-place."""
        selected = self._header_jlist.getSelectedValue()
        if selected is None:
            return
        self._tracked_headers[selected] = not self._tracked_headers.get(selected, True)
        # Repaint to reflect the new state
        self._header_jlist.repaint()

    def _remove_header(self, event):
        """Remove the selected header from tracking entirely."""
        selected = self._header_jlist.getSelectedValue()
        if selected is None:
            return
        confirm = JOptionPane.showConfirmDialog(
            self._main_panel,
            "Remove '{}' from tracking?".format(selected),
            "Confirm Remove", JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self._tracked_headers.pop(selected, None)
            self._header_list_model.removeElement(selected)

    # ------------------------------------------------------------------
    # ITab
    # ------------------------------------------------------------------

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self._main_panel


# ──────────────────────────────────────────────────────────────────────
# Read-only table model  (subclassing is the correct Jython approach;
# monkey-patching isCellEditable raises TypeError on Java methods)
# ──────────────────────────────────────────────────────────────────────

class ReadOnlyTableModel(DefaultTableModel):

    def __init__(self, data, columns):
        DefaultTableModel.__init__(self, data, columns)

    def isCellEditable(self, row, column):
        return False


# ──────────────────────────────────────────────────────────────────────
# Helper: table row selection listener
# ──────────────────────────────────────────────────────────────────────

class TableSelectionHandler(ListSelectionListener):

    def __init__(self, extender):
        self._extender = extender

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        row = self._extender._changes_table.getSelectedRow()
        if row >= 0:
            SwingUtilities.invokeLater(lambda: self._extender._on_row_selected(row))


# ──────────────────────────────────────────────────────────────────────
# Risk level cell renderer – foreground colour only, theme-safe
# ──────────────────────────────────────────────────────────────────────

class RiskLevelCellRenderer(DefaultTableCellRenderer):

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col
        )
        comp.setFont(Font("Dialog", Font.BOLD, 12))
        if not isSelected:
            # Reset to table defaults first
            comp.setBackground(table.getBackground())
            fg, _ = _get_risk_colors(str(value) if value else "")
            comp.setForeground(fg if fg else table.getForeground())
        else:
            comp.setForeground(table.getSelectionForeground())
            comp.setBackground(table.getSelectionBackground())
        return comp


# ──────────────────────────────────────────────────────────────────────
# Settings list renderer – shows checkbox state inline
# ──────────────────────────────────────────────────────────────────────

class HeaderListCellRenderer(JCheckBox, ListCellRenderer):
    """
    Renders each header entry as a checkbox showing its enabled state.
    Must explicitly declare ListCellRenderer in the class signature so Jython
    exposes it to Java's type system — inheriting JCheckBox alone is not enough.
    """

    def __init__(self, tracked_headers):
        JCheckBox.__init__(self)
        self._tracked = tracked_headers
        self.setOpaque(True)

    def getListCellRendererComponent(self, lst, value, index, isSelected, cellHasFocus):
        self.setText(str(value))
        self.setSelected(self._tracked.get(str(value), False))
        if isSelected:
            self.setBackground(lst.getSelectionBackground())
            self.setForeground(lst.getSelectionForeground())
        else:
            self.setBackground(lst.getBackground())
            self.setForeground(lst.getForeground())
        return self


# ──────────────────────────────────────────────────────────────────────
# Custom IScanIssue
# ──────────────────────────────────────────────────────────────────────

class HeaderChangeScanIssue(IScanIssue):

    def __init__(self, baseRequestResponse, helpers, callbacks, change_record):
        self._brr          = baseRequestResponse
        self._helpers      = helpers
        self._callbacks    = callbacks
        self._cr           = change_record
        self._url          = baseRequestResponse.getUrl()
        self._httpService  = baseRequestResponse.getHttpService()

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "HTTP Header Change Detected: {}".format(self._cr['header'])

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        mapping = {"Critical": "High", "High": "Medium", "Medium": "Low", "Low": "Information"}
        return mapping.get(self._cr['risk_level'], "Information")

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return (
            "<p>The HTTP response header <b>{}</b> changed between requests to the same URL.</p>"
            "<p>This may indicate security misconfigurations, server changes, load balancer "
            "behaviour, or policy drift. Security header changes should be reviewed to ensure "
            "they do not introduce vulnerabilities.</p>"
        ).format(self._cr['header'])

    def getRemediationBackground(self):
        return (
            "<p>Review header changes carefully:</p>"
            "<ul>"
            "<li>Ensure security headers are not weakened or removed.</li>"
            "<li>Verify cookie attributes remain secure (HttpOnly, Secure, SameSite).</li>"
            "<li>Check that CSP policies are not relaxed unnecessarily.</li>"
            "<li>Confirm all changes are intentional and documented.</li>"
            "</ul>"
        )

    def getIssueDetail(self):
        old = self._cr['old_value'][:200] + ("..." if len(self._cr['old_value']) > 200 else "")
        new = self._cr['new_value'][:200] + ("..." if len(self._cr['new_value']) > 200 else "")
        return (
            "<p><b>Header:</b> {}</p>"
            "<p><b>Risk Level:</b> {}</p>"
            "<p><b>Previous Value:</b></p><pre>{}</pre>"
            "<p><b>New Value:</b></p><pre>{}</pre>"
            "<p><b>Detected:</b> {}</p>"
        ).format(
            self._cr['header'],
            self._cr['risk_level'],
            old if old else "(header was not present)",
            new if new else "(header was removed)",
            self._cr['timestamp'].toString(),
        )

    def getRemediationDetail(self):
        recs = {
            'content-security-policy':    'Ensure CSP directives are not weakened. Avoid unsafe-inline or unsafe-eval.',
            'x-frame-options':            'Maintain DENY or SAMEORIGIN to prevent clickjacking.',
            'set-cookie':                 'Ensure cookies carry Secure, HttpOnly, and SameSite attributes.',
            'strict-transport-security':  'Keep HSTS enabled with an appropriate max-age value.',
            'x-content-type-options':     'Maintain "nosniff" to prevent MIME-type confusion attacks.',
        }
        return "<p>{}</p>".format(
            recs.get(self._cr['header'],
                     "Review this header change against your security policy.")
        )

    def getHttpMessages(self):
        return [self._brr]

    def getHttpService(self):
        return self._httpService
