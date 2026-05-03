import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;


public class MiniSOCDashboard extends JFrame {

    private JTable logTable;
    private DefaultTableModel tableModel;
    private JTextArea alertConsole;

    // Configurable size of the subset we sample from a (potentially huge) CIC CSV.
    private static final int SUBSET_SIZE = 200;

    // CIC-IDS-2017 protocol numbers -> friendly names
    private static final Map<String, String> PROTO_MAP = new HashMap<>();
    static {
        PROTO_MAP.put("6", "TCP");
        PROTO_MAP.put("17", "UDP");
        PROTO_MAP.put("1", "ICMP");
        PROTO_MAP.put("0", "HOPOPT");
    }

    public MiniSOCDashboard() {
        setTitle("Mini SOC Dashboard - Security Operations Center");
        setSize(1100, 650);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        // --- TOP PANEL: Tools & Controls ---
        JPanel controlPanel = new JPanel();
        controlPanel.setBorder(BorderFactory.createTitledBorder("SOC Tools"));

        JButton btnLoadLogs = new JButton("Load CIC-IDS-2017 CSV Subset");
        JButton btnNmapScan = new JButton("Run Nmap Scan (Simulated)");
        JButton btnWireshark = new JButton("Live Packet Capture (Simulated)");
        JButton btnClear = new JButton("Clear Dashboard");

        controlPanel.add(btnLoadLogs);
        controlPanel.add(btnNmapScan);
        controlPanel.add(btnWireshark);
        controlPanel.add(btnClear);
        add(controlPanel, BorderLayout.NORTH);

        // --- CENTER PANEL: Logs Dashboard ---
        String[] columnNames = {"Timestamp", "Source IP", "Destination IP",
                "Protocol", "Length", "Label (Status)"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };
        logTable = new JTable(tableModel);
        logTable.setFillsViewportHeight(true);
        logTable.setAutoCreateRowSorter(true); // click headers to sort

        JScrollPane tableScrollPane = new JScrollPane(logTable);
        tableScrollPane.setBorder(BorderFactory.createTitledBorder("Network Traffic Logs"));
        add(tableScrollPane, BorderLayout.CENTER);

        // --- BOTTOM PANEL: Alert Console ---
        alertConsole = new JTextArea(12, 50);
        alertConsole.setEditable(false);
        alertConsole.setBackground(Color.BLACK);
        alertConsole.setForeground(Color.GREEN);
        alertConsole.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JScrollPane alertScrollPane = new JScrollPane(alertConsole);
        alertScrollPane.setBorder(BorderFactory.createTitledBorder("Alerts & Tool Output"));
        alertScrollPane.setPreferredSize(new Dimension(1100, 220));
        add(alertScrollPane, BorderLayout.SOUTH);

        // --- EVENT LISTENERS ---
        btnLoadLogs.addActionListener(e -> loadCICIDSData());
        btnNmapScan.addActionListener(e -> runNmapScan());
        btnWireshark.addActionListener(e -> simulateLiveTraffic());
        btnClear.addActionListener(e -> {
            tableModel.setRowCount(0);
            alertConsole.setText("");
            log("[SYSTEM] Dashboard cleared.");
        });

        log("[SYSTEM] SOC Dashboard Initialized. Awaiting commands...");
        log("[SYSTEM] Tip: Download MachineLearningCSV.zip from");
        log("         https://www.unb.ca/cic/datasets/ids-2017.html");
        log("         and load any of the daily .csv files.");
    }

    //  CIC-IDS-2017 CSV LOADER

    private void loadCICIDSData() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select a CIC-IDS-2017 CSV file");
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "CSV files (*.csv)", "csv"));
        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            log("[SYSTEM] Load cancelled by user.");
            return;
        }
        File csvFile = chooser.getSelectedFile();
        log("\n[SYSTEM] Reading subset from: " + csvFile.getName());

        // Read the file in a background thread so the UI doesn't freeze

        new SwingWorker<List<Object[]>, Void>() {
            String[] header;

            @Override
            protected List<Object[]> doInBackground() throws Exception {
                return parseCsvSubset(csvFile);
            }

            @Override
            protected void done() {
                try {
                    List<Object[]> rows = get();
                    if (rows.isEmpty()) {
                        log("[ERROR] No usable rows found. Check the file format.");
                        return;
                    }
                    Map<String, Integer> attackCounts = new TreeMap<>();
                    for (Object[] row : rows) {
                        tableModel.addRow(row);
                        String label = String.valueOf(row[5]);
                        attackCounts.merge(label, 1, Integer::sum);
                        analyzeLog(row);
                    }
                    log("[SYSTEM] Subset loaded: " + rows.size() + " rows displayed.");
                    log("[SYSTEM] --- Label distribution in subset ---");
                    for (Map.Entry<String, Integer> e : attackCounts.entrySet()) {
                        log(String.format("           %-25s %d", e.getKey(), e.getValue()));
                    }
                } catch (Exception ex) {
                    log("[ERROR] Failed to load CSV: " + ex.getMessage());
                    ex.printStackTrace();
                }
            }
        }.execute();
    }


    private List<Object[]> parseCsvSubset(File csvFile) throws IOException {
        List<Object[]> benign = new ArrayList<>();
        Map<String, List<Object[]>> attacks = new LinkedHashMap<>();

        try (BufferedReader br = new BufferedReader(new FileReader(csvFile))) {
            String headerLine = br.readLine();
            if (headerLine == null) {
                throw new IOException("Empty CSV file");
            }
            String[] headers = splitCsv(headerLine);


            int idxSrcIP   = findColumn(headers, "Source IP");
            int idxDstIP   = findColumn(headers, "Destination IP");
            int idxProto   = findColumn(headers, "Protocol");
            int idxTime    = findColumn(headers, "Timestamp");
            int idxLength  = findColumn(headers, "Total Length of Fwd Packets");
            int idxLabel   = findColumn(headers, "Label");

            if (idxLabel < 0) {
                throw new IOException("Could not find 'Label' column. " +
                        "Is this really a CIC-IDS-2017 CSV?");
            }

            String line;
            int lineNum = 1;
            while ((line = br.readLine()) != null) {
                lineNum++;
                if (line.trim().isEmpty()) continue;
                String[] cols = splitCsv(line);
                if (cols.length <= idxLabel) continue; // malformed row, skip

                String timestamp = safeGet(cols, idxTime, "N/A");
                String srcIP     = safeGet(cols, idxSrcIP, "N/A");
                String dstIP     = safeGet(cols, idxDstIP, "N/A");
                String protoNum  = safeGet(cols, idxProto, "");
                String protoName = PROTO_MAP.getOrDefault(protoNum.trim(),
                        protoNum.isEmpty() ? "?" : protoNum);
                String length    = safeGet(cols, idxLength, "0");
                String label     = safeGet(cols, idxLabel, "BENIGN").trim();

                Object[] row = {timestamp, srcIP, dstIP, protoName, length, label};

                if (label.equalsIgnoreCase("BENIGN")) {
                    benign.add(row);
                } else {
                    attacks.computeIfAbsent(label, k -> new ArrayList<>()).add(row);
                }
            }
            log("[SYSTEM] Parsed " + (lineNum - 1) + " data rows from file.");
        }

        // Build stratified subset
        List<Object[]> subset = new ArrayList<>();
        Random rng = new Random(42); // reproducible

        int benignQuota = SUBSET_SIZE / 2;
        Collections.shuffle(benign, rng);
        for (int i = 0; i < Math.min(benignQuota, benign.size()); i++) {
            subset.add(benign.get(i));
        }

        int attackQuota = SUBSET_SIZE - subset.size();
        if (!attacks.isEmpty()) {
            int perClass = Math.max(1, attackQuota / attacks.size());
            for (List<Object[]> rows : attacks.values()) {
                Collections.shuffle(rows, rng);
                for (int i = 0; i < Math.min(perClass, rows.size()); i++) {
                    subset.add(rows.get(i));
                    if (subset.size() >= SUBSET_SIZE) break;
                }
                if (subset.size() >= SUBSET_SIZE) break;
            }
        }

        // Sort by timestamp string so the table reads chronologically
        subset.sort(Comparator.comparing(r -> String.valueOf(r[0])));
        return subset;
    }

    /** Find a column index by name, tolerating leading/trailing whitespace. */
    private int findColumn(String[] headers, String wanted) {
        for (int i = 0; i < headers.length; i++) {
            if (headers[i].trim().equalsIgnoreCase(wanted)) return i;
        }
        return -1;
    }

    private String safeGet(String[] arr, int idx, String fallback) {
        if (idx < 0 || idx >= arr.length) return fallback;
        String v = arr[idx];
        return v == null ? fallback : v.trim();
    }


    private String[] splitCsv(String line) {
        return line.split(",", -1);
    }

    //  ANALYSIS / ALERTS
    private void analyzeLog(Object[] logEntry) {
        String sourceIP = String.valueOf(logEntry[1]);
        String dstIP    = String.valueOf(logEntry[2]);
        String label    = String.valueOf(logEntry[5]);
        if (label.equalsIgnoreCase("BENIGN")) return;

        String severity = severityFor(label);
        log(String.format("[ALERT - %s] %s | %s -> %s",
                severity, label, sourceIP, dstIP));
    }

    /** Crude severity mapping based on the attack family name. */
    private String severityFor(String label) {
        String l = label.toLowerCase();
        if (l.contains("heartbleed") || l.contains("infiltration")
                || l.contains("sql") || l.contains("ddos")) {
            return "CRITICAL";
        }
        if (l.contains("dos") || l.contains("bot") || l.contains("patator")
                || l.contains("xss") || l.contains("brute")) {
            return "HIGH";
        }
        if (l.contains("portscan") || l.contains("scan")) {
            return "MEDIUM";
        }
        return "LOW";
    }

    //  EXTRA SOC TOOLS
    private void runNmapScan() {
        log("\n[NMAP] Starting simulated Nmap scan on subnet 192.168.10.0/24...");
        log("[NMAP] Nmap scan report for 192.168.10.50");
        log("[NMAP] Host is up (0.0020s latency).");
        log("[NMAP] PORT     STATE SERVICE");
        log("[NMAP] 21/tcp   open  ftp");
        log("[NMAP] 22/tcp   open  ssh");
        log("[NMAP] 80/tcp   open  http");
        log("[NMAP] 443/tcp  open  https");
        log("[NMAP] Warning: Open FTP port matches target of FTP-Patator attacks in CIC-IDS-2017.");
    }

    private void simulateLiveTraffic() {
        String timestamp = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date());
        Object[] livePacket = {timestamp,
                "192.168.10." + (int)(Math.random()*100),
                "1.1.1.1", "ICMP", "74", "BENIGN"};
        tableModel.addRow(livePacket);
        log("[WIRESHARK] Captured live packet: " + livePacket[1]
                + " -> " + livePacket[2] + " (" + livePacket[3] + ")");
    }

    private void log(String message) {
        alertConsole.append(message + "\n");
        alertConsole.setCaretPosition(alertConsole.getDocument().getLength());
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            MiniSOCDashboard dashboard = new MiniSOCDashboard();
            dashboard.setVisible(true);
        });
    }
}