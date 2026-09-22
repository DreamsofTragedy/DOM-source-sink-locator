package com.example.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Static source triage for HTML and JavaScript visible in Burp responses. */
public class DomSourceSinkLocator implements BurpExtension {
    private static final int MAX_PROXY_BODY_CHARS = 2_000_000;
    private static final int MAX_TABLE_ROWS = 5000;
    private JTextArea inputArea;
    private JTable findingsTable;
    private DefaultTableModel tableModel;
    private JLabel statusLabel;
    private JTabbedPane suiteTabs;
    private JCheckBox autoProxyScan;
    private volatile boolean autoProxyScanEnabled = true;
    private final AtomicInteger proxyResponsesScanned = new AtomicInteger();
    private final AtomicInteger proxyFindingsAdded = new AtomicInteger();
    private final ExecutorService scanExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "DOM-source-sink-locator proxy scanner");
        thread.setDaemon(true);
        return thread;
    });

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("DOM-source-sink-locator");
        SwingUtilities.invokeLater(() -> buildUi(api));
        api.userInterface().registerContextMenuItemsProvider(new SourceContextMenuProvider());
        api.http().registerHttpHandler(new AutomaticProxyScanner());
        api.logging().logToOutput("DOM-source-sink-locator loaded.");
    }

    private void buildUi(MontoyaApi api) {
        JPanel root = new JPanel(new BorderLayout());
        JTabbedPane tabs = new JTabbedPane();
        suiteTabs = tabs;
        JPanel inputPanel = new JPanel(new BorderLayout());
        inputArea = new JTextArea();
        inputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        inputArea.setLineWrap(false);

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton scan = new JButton("Find DOM Sources");
        JButton clear = new JButton("Clear");
        JButton sample = new JButton("Load Sample");
        controls.add(scan); controls.add(clear); controls.add(sample);
        statusLabel = new JLabel("Paste HTML/JavaScript or send a Burp response here.");
        scan.addActionListener(e -> analyzePastedText());
        clear.addActionListener(e -> { inputArea.setText(""); tableModel.setRowCount(0); statusLabel.setText("Cleared."); });
        sample.addActionListener(e -> inputArea.setText(sampleInput()));
        inputPanel.add(controls, BorderLayout.NORTH);
        inputPanel.add(new JScrollPane(inputArea), BorderLayout.CENTER);
        inputPanel.add(statusLabel, BorderLayout.SOUTH);

        JPanel results = new JPanel(new BorderLayout());
        String[] columns = {"Source", "Candidate sink(s) in response", "Signal", "Location", "Code snippet", "Why it matters", "Trace next"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        findingsTable = new JTable(tableModel);
        findingsTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths = {190, 230, 90, 250, 420, 280, 350};
        for (int i = 0; i < widths.length; i++) findingsTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);

        JPanel resultControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton copy = new JButton("Copy Selected");
        JButton export = new JButton("Copy All as TSV");
        JButton exportCsv = new JButton("Export CSV");
        autoProxyScan = new JCheckBox("Auto-scan Proxy responses", autoProxyScanEnabled);
        autoProxyScan.addActionListener(e -> {
            autoProxyScanEnabled = autoProxyScan.isSelected();
            statusLabel.setText(autoProxyScanEnabled ? "Automatic Proxy response scanning enabled." : "Automatic Proxy response scanning paused.");
        });
        resultControls.add(copy); resultControls.add(export); resultControls.add(exportCsv); resultControls.add(autoProxyScan);
        copy.addActionListener(e -> copySelected());
        export.addActionListener(e -> copyAll());
        exportCsv.addActionListener(e -> exportCsv());
        results.add(resultControls, BorderLayout.NORTH);
        results.add(new JScrollPane(findingsTable), BorderLayout.CENTER);
        tabs.addTab("Input", inputPanel);
        tabs.addTab("Sources/Sinks/postMessage", results);
        root.add(tabs, BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("DOM-source-sink-locator", root);
    }

    private class SourceContextMenuProvider implements ContextMenuItemsProvider {
        @Override public List<Component> provideMenuItems(ContextMenuEvent event) {
            JMenuItem sendToInput = new JMenuItem("Send response to Input tab for analysis");
            sendToInput.addActionListener(e -> loadResponsesIntoInput(event.selectedRequestResponses()));
            JMenuItem analyzeNow = new JMenuItem("Analyze selected response now");
            analyzeNow.addActionListener(e -> analyzeResponses(event.selectedRequestResponses()));
            return List.of(sendToInput, analyzeNow);
        }
    }

    private void loadResponsesIntoInput(List<HttpRequestResponse> selected) {
        if (selected == null || selected.isEmpty()) {
            statusLabel.setText("No Proxy response was selected.");
            return;
        }
        StringBuilder content = new StringBuilder();
        int loaded = 0;
        for (HttpRequestResponse rr : selected) {
            HttpResponse response = rr.response();
            if (response == null) continue;
            if (content.length() > 0) content.append("\n\n");
            content.append(response.bodyToString());
            loaded++;
        }
        if (loaded == 0) {
            statusLabel.setText("The selected Proxy item has no response body.");
            return;
        }
        inputArea.setText(content.toString());
        suiteTabs.setSelectedIndex(0);
        statusLabel.setText("Loaded " + loaded + " response body/bodies into Input. Click Find DOM Sources to analyze.");
    }

    private void analyzeResponses(List<HttpRequestResponse> selected) {
        tableModel.setRowCount(0);
        int count = 0;
        if (selected != null) for (HttpRequestResponse rr : selected) {
            HttpResponse response = rr.response();
            if (response == null) continue;
            List<Finding> found = analyze(response.bodyToString(), "response:" + rr.request().url());
            addFindings(found); count += found.size();
        }
        statusLabel.setText("Scanned selected response bodies. Source/sink indicators: " + count + ".");
    }

    private class AutomaticProxyScanner implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            if (!autoProxyScanEnabled || !responseReceived.toolSource().isFromTool(ToolType.PROXY)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            String contentType = responseReceived.headerValue("Content-Type");
            if (!looksTextual(contentType)) return ResponseReceivedAction.continueWith(responseReceived);

            String body = responseReceived.bodyToString();
            if (body == null || body.isEmpty() || body.length() > MAX_PROXY_BODY_CHARS) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
            String url;
            try {
                url = responseReceived.initiatingRequest().url();
            } catch (RuntimeException ex) {
                url = "Proxy response #" + responseReceived.messageId();
            }
            final String responseUrl = url;
            proxyResponsesScanned.incrementAndGet();

            scanExecutor.submit(() -> {
                List<Finding> found = analyze(body, "proxy:" + responseUrl);
                found.removeIf(f -> f.signal.equals("INFO"));
                if (found.isEmpty()) return;
                SwingUtilities.invokeLater(() -> {
                    if (tableModel == null || statusLabel == null) return;
                    int available = MAX_TABLE_ROWS - tableModel.getRowCount();
                    if (available > 0) {
                        List<Finding> visible = found.size() > available ? found.subList(0, available) : found;
                        addFindings(visible);
                        proxyFindingsAdded.addAndGet(visible.size());
                    }
                    if (statusLabel != null) {
                        statusLabel.setText("Proxy auto-scan: " + proxyResponsesScanned.get() + " text responses checked; "
                                + proxyFindingsAdded.get() + " leads added. Results capped at " + MAX_TABLE_ROWS + " rows.");
                    }
                });
            });
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }

    private boolean looksTextual(String contentType) {
        if (contentType == null || contentType.isBlank()) return true;
        String type = contentType.toLowerCase();
        return type.startsWith("text/") || type.contains("javascript") || type.contains("ecmascript")
                || type.contains("json") || type.contains("xml") || type.contains("html") || type.contains("svg");
    }

    private void analyzePastedText() {
        String text = inputArea.getText();
        if (text == null || text.isBlank()) { statusLabel.setText("Nothing to scan."); return; }
        tableModel.setRowCount(0);
        String body = extractBody(text);
        List<Finding> found = analyze(body, "pasted-input");
        addFindings(found);
        statusLabel.setText("Scan complete. Source/sink indicators: " + found.size() + ". These are leads, not confirmed vulnerabilities.");
    }

    private String extractBody(String text) {
        int split = text.indexOf("\r\n\r\n");
        if (split >= 0) return text.substring(split + 4);
        split = text.indexOf("\n\n");
        return split >= 0 ? text.substring(split + 2) : text;
    }

    private List<Finding> analyze(String text, String location) {
        List<Finding> found = new ArrayList<>();
        List<SinkCandidate> sinks = findSinks(text);
        String sinkSummary = sinks.isEmpty() ? "—" : String.join("; ", sinks.stream().map(s -> s.name).distinct().toList())
                + " (same response; flow unverified)";
        // Patterns are intentionally indicators: static matching cannot prove controllability or execution.
        add(found, text, location, "URL location", "HIGH", "(?i)(?:window\\s*\\.\\s*)?location\\s*\\.\\s*(?:search|hash|href|pathname|(?:host|hostname|origin|protocol))", "URL-controlled data may be available to client-side code.", "Place a unique marker in the query/hash/path and trace its runtime value.", sinkSummary);
        add(found, text, location, "document URL", "MED", "(?i)document\\s*\\.\\s*(?:URL|documentURI|baseURI|referrer)", "The current or referring URL can carry attacker-controlled input.", "Test query, fragment, path, and referrer values separately; follow transformations.", sinkSummary);
        add(found, text, location, "URLSearchParams", "HIGH", "(?is)(?:new\\s+)?URLSearchParams\\s*\\([^)]{0,180}\\)|(?:searchParams|URLSearchParams)\\s*\\.\\s*get(?:All)?\\s*\\(", "Query parameters are being parsed by JavaScript.", "Set a canary parameter and trace the returned value into later DOM operations.", sinkSummary);
        add(found, text, location, "postMessage data", "HIGH", "(?is)(?:addEventListener\\s*\\(\\s*['\"]message['\"]|onmessage\\s*=)[^;{}]{0,500}|(?:event|e|message)\\s*\\.\\s*data", "Cross-window message data may be controlled by another frame or window.", "Inspect the full handler, origin/source checks, data validation, and any downstream use.", sinkSummary);
        add(found, text, location, "window.name", "MED", "(?i)(?:window\\s*\\.\\s*name|window\\s*\\[\\s*['\"]name['\"]\\s*\\])", "Window name can persist across navigation and may be set by an opener.", "Check the actual read site and whether a value survives navigation into this page.", sinkSummary);
        add(found, text, location, "document.referrer", "MED", "(?i)document\\s*\\.\\s*referrer", "Referrer content can be influenced by navigation context, subject to browser policy.", "Determine whether a controllable referrer is read and how it is used.", sinkSummary);
        add(found, text, location, "Web Storage", "MED", "(?i)(?:localStorage|sessionStorage)\\s*\\.\\s*(?:getItem|key)\\s*\\(|(?:localStorage|sessionStorage)\\s*\\[[^]]+\\]", "Stored values may be writable by earlier app flows or other scripts on the origin.", "Identify who can write the key, then trace reads to a sensitive DOM operation.", sinkSummary);
        add(found, text, location, "Cookie read", "LOW", "(?i)document\\s*\\.\\s*cookie\\b", "JavaScript-readable cookies can be an input source, depending on cookie flags and app behavior.", "Check whether the value is attacker-writable and where it flows; HttpOnly cookies are not readable here.", sinkSummary);
        add(found, text, location, "DOM value/attribute", "MED", "(?i)(?:\\.value|\\.textContent|\\.innerText|\\.getAttribute\\s*\\(|\\.dataset(?:\\.[A-Za-z_$][\\w$]*)?)", "Values read from DOM nodes or attributes can be influenced by page content or user interaction.", "Trace the specific node and identify whether untrusted content can set its value/attribute.", sinkSummary);
        add(found, text, location, "Network response data", "LOW", "(?i)(?:response|responseText|\\.json\\s*\\(|\\.text\\s*\\(\\s*\\)|\\.data)\\b", "Network-derived data may be attacker-controlled if it includes user content or untrusted API fields.", "Follow the specific response property; do not treat every response as attacker-controlled.", sinkSummary);
        add(found, text, location, "Framework route/query", "MED", "(?i)(?:route|router|activatedRoute)\\s*\\.(?:queryParams|params|query)|useSearchParams\\s*\\(|useParams\\s*\\(", "Framework routing state may expose URL parameters to application code.", "Trace the returned parameter through component state and rendering.", sinkSummary);

        for (SinkCandidate sink : sinks) {
            int line = lineNumber(text, sink.start);
            String snippet = excerpt(text, sink.start, sink.end);
            found.add(new Finding("—", sink.name, "SINK", location + ":" + line, snippet,
                    "Candidate DOM/code-execution sink detected; its argument may or may not be attacker-controlled.",
                    "Trace arguments backward to a source and verify runtime behavior."));
        }
        if (found.isEmpty()) found.add(new Finding("—", "—", "INFO", location,
                "No configured source or sink patterns matched.", "This scanner uses static text patterns and may miss minified, indirect, or framework-specific flows.",
                "Try the JavaScript response directly, use DOM Invader, and inspect runtime behavior."));
        return dedupe(found);
    }

    private void add(List<Finding> found, String text, String location, String kind, String signal,
                     String regex, String why, String next, String sinkSummary) {
        Matcher matcher = Pattern.compile(regex).matcher(text);
        while (matcher.find()) {
            int start = Math.max(0, matcher.start() - 100);
            int end = Math.min(text.length(), matcher.end() + 140);
            String snippet = excerpt(text, start, end);
            int line = lineNumber(text, matcher.start());
            found.add(new Finding(sourceExpression(kind, matcher.group()), sinkSummary, signal,
                    location + ":" + line, snippet, why, next));
        }
    }

    private List<SinkCandidate> findSinks(String text) {
        String[][] patterns = {
                {"innerHTML", "(?i)\\binnerHTML\\b"},
                {"outerHTML", "(?i)\\bouterHTML\\b"},
                {"insertAdjacentHTML()", "(?i)\\binsertAdjacentHTML\\s*\\("},
                {"document.write()", "(?i)\\bdocument\\s*\\.\\s*(?:write|writeln)\\s*\\("},
                {"eval()", "(?i)\\beval\\s*\\("},
                {"new Function()", "(?i)\\bnew\\s+Function\\s*\\("},
                {"string timer", "(?i)\\b(?:setTimeout|setInterval)\\s*\\(\\s*(['\"`])"},
                {"createContextualFragment()", "(?i)\\bcreateContextualFragment\\s*\\("},
                {"jQuery html()", "(?i)\\.\\s*html\\s*\\("}
        };
        List<SinkCandidate> found = new ArrayList<>();
        for (String[] pattern : patterns) {
            Matcher matcher = Pattern.compile(pattern[1]).matcher(text);
            while (matcher.find()) found.add(new SinkCandidate(pattern[0], matcher.start(), matcher.end()));
        }
        return found;
    }

    private String sourceExpression(String kind, String raw) {
        String normalized = raw.replaceAll("\\s*\\.\\s*", ".").replaceAll("\\s+", " ").trim();
        if (kind.equals("URL location")) {
            Matcher m = Pattern.compile("(?i)(?:window\\.)?location\\.(search|hash|href|pathname|host|hostname|origin|protocol)").matcher(normalized);
            return m.find() ? "location." + m.group(1).toLowerCase() : "location";
        }
        if (kind.equals("document URL")) {
            Matcher m = Pattern.compile("(?i)document\\.(URL|documentURI|baseURI|referrer)").matcher(normalized);
            return m.find() ? "document." + m.group(1) : "document URL";
        }
        if (kind.equals("URLSearchParams")) return normalized.contains(".get") ? "URLSearchParams.get()" : "new URLSearchParams(...)";
        if (kind.equals("postMessage data")) return normalized.contains(".data") ? "event.data" : "message event data";
        if (kind.equals("window.name")) return "window.name";
        if (kind.equals("document.referrer")) return "document.referrer";
        if (kind.equals("Web Storage")) {
            Matcher m = Pattern.compile("(?i)(localStorage|sessionStorage)").matcher(normalized);
            String storage = m.find() ? m.group(1) : "Storage";
            return normalized.contains("getItem") ? storage + ".getItem()" : storage + "[...]";
        }
        if (kind.equals("Cookie read")) return "document.cookie";
        if (kind.equals("DOM value/attribute")) {
            Matcher m = Pattern.compile("(?i)\\.(value|textContent|innerText|dataset)\\b|\\.getAttribute\\s*\\(").matcher(normalized);
            return m.find() ? "DOM." + m.group().replaceAll("^\\.", "") : "DOM value/attribute";
        }
        if (kind.equals("Network response data")) {
            Matcher m = Pattern.compile("(?i)(responseText|\\.json\\s*\\(|\\.text\\s*\\(|\\.data)").matcher(normalized);
            return m.find() ? m.group(1).replaceAll("\\s+", "") : "response data";
        }
        if (kind.equals("Framework route/query")) return normalized.length() > 90 ? normalized.substring(0, 90) : normalized;
        return kind;
    }

    private int lineNumber(String text, int offset) {
        int line = 1;
        for (int i = 0; i < offset && i < text.length(); i++) if (text.charAt(i) == '\n') line++;
        return line;
    }

    private String excerpt(String text, int start, int end) {
        start = Math.max(0, start);
        end = Math.min(text.length(), end);
        return truncate(text.substring(start, end).replaceAll("[\\r\\n\\t]+", " ").replaceAll("\\s{2,}", " ").trim(), 360);
    }

    private List<Finding> dedupe(List<Finding> in) {
        List<Finding> out = new ArrayList<>();
        for (Finding f : in) {
            boolean seen = false;
            for (Finding x : out) if (x.source.equals(f.source) && x.sink.equals(f.sink) && x.location.equals(f.location) && x.snippet.equals(f.snippet)) { seen = true; break; }
            if (!seen) out.add(f);
        }
        return out;
    }

    private void addFindings(List<Finding> findings) {
        for (Finding f : findings) {
            Vector<String> row = new Vector<>();
            row.add(f.source); row.add(f.sink); row.add(f.signal); row.add(f.location); row.add(f.snippet); row.add(f.why); row.add(f.next);
            tableModel.addRow(row);
        }
    }

    private void copySelected() {
        int row = findingsTable.getSelectedRow();
        if (row < 0) { statusLabel.setText("Select a source row first."); return; }
        StringBuilder out = new StringBuilder();
        for (int c = 0; c < tableModel.getColumnCount(); c++) out.append(tableModel.getColumnName(c)).append(": ").append(tableModel.getValueAt(row, c)).append('\n');
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(out.toString()), null);
        statusLabel.setText("Selected source copied to clipboard.");
    }

    private void copyAll() {
        StringBuilder out = new StringBuilder();
        for (int c = 0; c < tableModel.getColumnCount(); c++) { if (c > 0) out.append('\t'); out.append(tableModel.getColumnName(c)); }
        out.append('\n');
        for (int r = 0; r < tableModel.getRowCount(); r++) {
            for (int c = 0; c < tableModel.getColumnCount(); c++) { if (c > 0) out.append('\t'); out.append(String.valueOf(tableModel.getValueAt(r, c)).replace('\t', ' ')); }
            out.append('\n');
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(out.toString()), null);
        statusLabel.setText("All source indicators copied as TSV.");
    }

    private void exportCsv() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export DOM-source-sink-locator findings as CSV");
        chooser.setSelectedFile(new java.io.File("dom-source-sink-findings.csv"));
        if (chooser.showSaveDialog(findingsTable) != JFileChooser.APPROVE_OPTION) return;

        Path output = chooser.getSelectedFile().toPath();
        if (Files.exists(output)) {
            int choice = JOptionPane.showConfirmDialog(findingsTable, "Replace the existing file?", "Confirm CSV overwrite",
                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) return;
        }
        try (BufferedWriter writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8)) {
            for (int c = 0; c < tableModel.getColumnCount(); c++) {
                if (c > 0) writer.write(',');
                writer.write(csvCell(tableModel.getColumnName(c)));
            }
            writer.write("\r\n");
            for (int r = 0; r < tableModel.getRowCount(); r++) {
                for (int c = 0; c < tableModel.getColumnCount(); c++) {
                    if (c > 0) writer.write(',');
                    writer.write(csvCell(String.valueOf(tableModel.getValueAt(r, c))));
                }
                writer.write("\r\n");
            }
            statusLabel.setText("Exported " + tableModel.getRowCount() + " rows to CSV.");
        } catch (IOException ex) {
            statusLabel.setText("CSV export failed: " + ex.getMessage());
        }
    }

    private String csvCell(String value) {
        String safe = value == null ? "" : value;
        return "\"" + safe.replace("\"", "\"\"") + "\"";
    }

    private String truncate(String text, int max) { return text.length() <= max ? text : text.substring(0, max) + "..."; }

    private String sampleInput() {
        return "<script>\n" +
                "const term = new URLSearchParams(location.search).get('q');\n" +
                "window.addEventListener('message', (event) => { console.log(event.data); });\n" +
                "const fragment = location.hash;\n" +
                "const saved = localStorage.getItem('displayName');\n" +
                "document.querySelector('#result').textContent = term;\n" +
                "</script>\n";
    }

    private static class Finding {
        final String source, sink, signal, location, snippet, why, next;
        Finding(String source, String sink, String signal, String location, String snippet, String why, String next) {
            this.source = source; this.sink = sink; this.signal = signal; this.location = location;
            this.snippet = snippet; this.why = why; this.next = next;
        }
    }

    private static class SinkCandidate {
        final String name;
        final int start, end;
        SinkCandidate(String name, int start, int end) {
            this.name = name; this.start = start; this.end = end;
        }
    }
}
