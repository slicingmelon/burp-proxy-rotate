/**
 * Burp SOCKS Proxy Rotator
 * 
 * This extension routes each HTTP request through a different SOCKS proxy from a provided list.
 */
package slicingmelon.burpsocksrotate;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;

/**
 * Main Burp extension class for SOCKS proxy rotation.
 */
public class BurpSocksRotate implements BurpExtension {
    
    // Core components
    private MontoyaApi api;
    private List<ProxyEntry> proxyList;
    private final ReadWriteLock proxyListLock = new ReentrantReadWriteLock();
    private SocksProxyService socksProxyService;
    
    // UI components
    private ProxyTableModel proxyTableModel;
    private JTextArea logTextArea;
    private JButton startServerButton;
    private JButton stopServerButton;
    private JTextField portField;
    
    // Configuration 
    private int configuredLocalPort = 1080;
    
    // Persistence keys
    private static final String PROXY_LIST_KEY = "proxyList";
    private static final String PORT_KEY = "localPort";

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Burp SOCKS Proxy Rotator");
        
        // Initialize proxy list
        proxyList = new ArrayList<>();
        
        // Load saved proxies and settings
        loadSavedProxies();
        
        // Initialize the SOCKS Proxy Service - much simpler now
        socksProxyService = new SocksProxyService(proxyList, proxyListLock, api.logging());
        socksProxyService.setExtension(this);

        // Create and register the UI
        SwingUtilities.invokeLater(() -> {
            JComponent panel = createUserInterface();
            api.userInterface().registerSuiteTab("SOCKS Rotator", panel);
            updateServerButtons();
        });
        
        // Add shutdown hook
        api.extension().registerUnloadingHandler(this::shutdown);
        
        logMessage("SOCKS Proxy Rotator extension loaded successfully");
    }
    
    /**
     * Loads saved proxies and settings from Montoya persistence.
     */
    private void loadSavedProxies() {
        String savedProxies = api.persistence().preferences().getString(PROXY_LIST_KEY);
        if (savedProxies != null && !savedProxies.isEmpty()) {
            String[] proxies = savedProxies.split("\n");
            for (String proxy : proxies) {
                String[] parts = proxy.split(":");
                if (parts.length == 2) {
                    try {
                        String host = parts[0].trim();
                        int port = Integer.parseInt(parts[1].trim());
                        if (!host.isEmpty() && port > 0 && port <= 65535) {
                            proxyListLock.writeLock().lock();
                            try {
                                proxyList.add(new ProxyEntry(host, port));
                            } finally {
                                proxyListLock.writeLock().unlock();
                            }
                        }
                    } catch (NumberFormatException e) {
                        // Skip invalid entries
                    }
                }
            }
        }
        
        String portSetting = api.persistence().preferences().getString(PORT_KEY);
        if (portSetting != null) {
            try {
                int port = Integer.parseInt(portSetting);
                if (port > 0 && port < 65536) {
                    configuredLocalPort = port;
                }
            } catch (NumberFormatException e) {
                // Ignore, use default port
            }
        }
    }
    
    /**
     * Saves proxies and settings to Montoya persistence.
     */
    private void saveProxies() {
        StringBuilder sb = new StringBuilder();
        proxyListLock.readLock().lock();
        try {
            for (ProxyEntry entry : proxyList) {
                sb.append(entry.getHost()).append(":").append(entry.getPort()).append("\n");
            }
        } finally {
            proxyListLock.readLock().unlock();
        }
        
        api.persistence().preferences().setString(PROXY_LIST_KEY, sb.toString());
        api.persistence().preferences().setString(PORT_KEY, String.valueOf(configuredLocalPort));
    }
    
    /**
     * Creates the user interface components.
     */
    private JComponent createUserInterface() {
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Create server control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JPanel serverControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        serverControls.add(new JLabel("Local Port:"));
        
        portField = new JTextField(String.valueOf(configuredLocalPort), 5);
        serverControls.add(portField);
        
        startServerButton = new JButton("Start Proxy Server");
        startServerButton.addActionListener(e -> startProxyServer());
        serverControls.add(startServerButton);
        
        stopServerButton = new JButton("Stop Proxy Server");
        stopServerButton.addActionListener(e -> stopProxyServer());
        stopServerButton.setEnabled(false);
        serverControls.add(stopServerButton);
        
        controlPanel.add(serverControls);
        
        // Create proxy table
        proxyTableModel = new ProxyTableModel();
        JTable proxyTable = new JTable(proxyTableModel);
        setupTableRenderer(proxyTable);
        JScrollPane tableScrollPane = new JScrollPane(proxyTable);
        tableScrollPane.setPreferredSize(new Dimension(300, 200));
        
        // Create proxy input panel
        JPanel inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        JLabel hostLabel = new JLabel("Host:");
        JTextField hostField = new JTextField(15);
        JLabel portLabel = new JLabel("Port:");
        JTextField addPortField = new JTextField(5);
        JButton addButton = new JButton("Add Proxy");
        JButton validateAllButton = new JButton("Validate All");
        
        gbc.gridx = 0;
        gbc.gridy = 0;
        inputPanel.add(hostLabel, gbc);
        
        gbc.gridx = 1;
        inputPanel.add(hostField, gbc);
        
        gbc.gridx = 2;
        inputPanel.add(portLabel, gbc);
        
        gbc.gridx = 3;
        inputPanel.add(addPortField, gbc);
        
        gbc.gridx = 4;
        inputPanel.add(addButton, gbc);
        
        gbc.gridx = 5;
        inputPanel.add(validateAllButton, gbc);
        
        addButton.addActionListener(e -> {
            String host = hostField.getText().trim();
            String portText = addPortField.getText().trim();
            
            if (host.isEmpty()) {
                JOptionPane.showMessageDialog(mainPanel, "Host cannot be empty", "Validation Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            try {
                int port = Integer.parseInt(portText);
                if (port <= 0 || port > 65535) {
                    JOptionPane.showMessageDialog(mainPanel, "Port must be between 1 and 65535", "Validation Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                ProxyEntry proxy = new ProxyEntry(host, port);
                addProxy(proxy);
                
                // Validate the newly added proxy
                new Thread(() -> {
                    validateProxy(proxy, 3);
                    updateProxyTable();
                }).start();
                
                hostField.setText("");
                addPortField.setText("");
                
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(mainPanel, "Port must be a valid number", "Validation Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        validateAllButton.addActionListener(e -> validateAllProxies());
        
        // Bulk add panel
        JPanel bulkPanel = new JPanel(new BorderLayout(5, 5));
        JTextArea bulkTextArea = new JTextArea(5, 30);
        bulkTextArea.setToolTipText("Enter one proxy per line in format host:port");
        JScrollPane bulkScrollPane = new JScrollPane(bulkTextArea);
        JButton bulkAddButton = new JButton("Add Multiple Proxies");
        
        bulkPanel.add(new JLabel("Add multiple proxies (format: host:port, one per line):"), BorderLayout.NORTH);
        bulkPanel.add(bulkScrollPane, BorderLayout.CENTER);
        bulkPanel.add(bulkAddButton, BorderLayout.SOUTH);
        
        bulkAddButton.addActionListener(e -> {
            String bulk = bulkTextArea.getText().trim();
            if (bulk.isEmpty()) {
                return;
            }
            
            String[] lines = bulk.split("\n");
            int added = 0;
            List<ProxyEntry> proxiesToAdd = new ArrayList<>();

            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                
                String[] parts = line.split(":");
                if (parts.length != 2) {
                    logMessage("Skipping invalid bulk entry: " + line);
                    continue;
                }
                
                try {
                    String host = parts[0].trim();
                    int port = Integer.parseInt(parts[1].trim());
                    
                    if (!host.isEmpty() && port > 0 && port <= 65535) {
                        boolean exists = false;
                        proxyListLock.readLock().lock();
                        try {
                            for (ProxyEntry existing : proxyList) {
                                if (existing.getHost().equalsIgnoreCase(host) && existing.getPort() == port) {
                                    exists = true;
                                    break;
                                }
                            }
                        } finally {
                            proxyListLock.readLock().unlock();
                        }
                        if (!exists) {
                            proxiesToAdd.add(new ProxyEntry(host, port));
                        } else {
                            logMessage("Skipping duplicate proxy: " + host + ":" + port);
                        }
                    } else {
                        logMessage("Skipping invalid bulk entry (host/port): " + line);
                    }
                } catch (NumberFormatException ex) {
                    logMessage("Skipping invalid bulk entry (port format): " + line);
                }
            }

            // Add collected proxies in one go
            if (!proxiesToAdd.isEmpty()) {
                proxyListLock.writeLock().lock();
                try {
                    proxyList.addAll(proxiesToAdd);
                    added = proxiesToAdd.size();
                } finally {
                    proxyListLock.writeLock().unlock();
                }
            }

            if (added > 0) {
                bulkTextArea.setText("");
                updateProxyTable();
                saveProxies();
                logMessage("Added " + added + " new proxies from bulk input.");
            } else {
                logMessage("No new proxies were added from bulk input.");
            }
        });
        
        // Management buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton deleteButton = new JButton("Delete Selected");
        JButton clearButton = new JButton("Clear All");
        
        deleteButton.addActionListener(e -> {
            int selectedRow = proxyTable.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = proxyTable.convertRowIndexToModel(selectedRow);
                if (modelRow >= 0 && modelRow < proxyList.size()) {
                    removeProxy(modelRow);
                }
            } else {
                JOptionPane.showMessageDialog(mainPanel, "Please select a proxy to delete.", "Delete Proxy", JOptionPane.WARNING_MESSAGE);
            }
        });
        
        clearButton.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(
                    mainPanel,
                    "Are you sure you want to remove all proxies?",
                    "Confirm Clear",
                    JOptionPane.YES_NO_OPTION
            );
            
            if (confirm == JOptionPane.YES_OPTION) {
                clearAllProxies();
            }
        });
        
        buttonPanel.add(deleteButton);
        buttonPanel.add(clearButton);
        
        // Log area
        logTextArea = new JTextArea(10, 40);
        logTextArea.setEditable(false);
        JScrollPane logScrollPane = new JScrollPane(logTextArea);
        
        // Create tabs
        JTabbedPane tabbedPane = new JTabbedPane();
        
        JPanel proxyManagementPanel = new JPanel(new BorderLayout(10, 10));
        proxyManagementPanel.add(tableScrollPane, BorderLayout.CENTER);
        
        JPanel controlsPanel = new JPanel(new BorderLayout());
        controlsPanel.add(inputPanel, BorderLayout.NORTH);
        controlsPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        proxyManagementPanel.add(controlsPanel, BorderLayout.SOUTH);
        
        tabbedPane.addTab("Proxy List", proxyManagementPanel);
        tabbedPane.addTab("Bulk Add", bulkPanel);
        tabbedPane.addTab("Log", logScrollPane);
        
        mainPanel.add(controlPanel, BorderLayout.NORTH);
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        
        // Update table with existing proxies
        updateProxyTable();
        
        return mainPanel;
    }
    
    /**
     * Starts the proxy server.
     */
    private void startProxyServer() {
        proxyListLock.readLock().lock();
        boolean hasActiveProxy;
        try {
            hasActiveProxy = proxyList.stream().anyMatch(ProxyEntry::isActive);
            if (proxyList.isEmpty() || !hasActiveProxy) {
                JOptionPane.showMessageDialog(null,
                    proxyList.isEmpty() ? "Please add at least one proxy before starting the server." : 
                    "Please add or validate at least one proxy before starting the server.",
                    "No Active Proxies",
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
        } finally {
            proxyListLock.readLock().unlock();
        }

        // Read port from UI
        int portToUse;
        try {
            portToUse = Integer.parseInt(portField.getText().trim());
            if (portToUse <= 0 || portToUse > 65535) {
                throw new NumberFormatException("Port out of range");
            }
            configuredLocalPort = portToUse;
            saveProxies();
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(null, 
                "Invalid port number. Please enter a number between 1-65535.",
                "Invalid Port", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // Define callbacks for success and failure
        Runnable onSuccessCallback = () -> {
            SwingUtilities.invokeLater(() -> {
                updateServerButtons();
                JOptionPane.showMessageDialog(null,
                    "SOCKS Proxy Rotator started on localhost:" + portToUse + "\n\n" +
                    "To use it:\n" +
                    "1. Go to Burp Settings > Network > Connections > SOCKS Proxy\n" +
                    "2. Check 'Use SOCKS proxy'\n" +
                    "3. Set Host to 'localhost' and Port to '" + portToUse + "'\n\n" +
                    "The rotator will route each request through a different active SOCKS proxy from your list.",
                    "Proxy Server Started",
                    JOptionPane.INFORMATION_MESSAGE);
            });
        };

        Consumer<String> onFailureCallback = (errorMessage) -> {
            SwingUtilities.invokeLater(() -> {
                logMessage("Proxy service failed to start: " + errorMessage);
                JOptionPane.showMessageDialog(null, 
                    "Failed to start proxy server: " + errorMessage,
                    "Server Error", 
                    JOptionPane.ERROR_MESSAGE);
                updateServerButtons();
            });
        };

        // Start the proxy service with callbacks
        try {
            logMessage("Attempting to start SOCKS proxy service on port " + portToUse + "...");
            socksProxyService.start(portToUse, onSuccessCallback, onFailureCallback);
        } catch (Exception ex) {
            logMessage("Unexpected error trying to initiate proxy service start: " + ex.getMessage());
            JOptionPane.showMessageDialog(null,
                "An unexpected error occurred trying to start the proxy service: " + ex.getMessage(),
                "Start Error",
                JOptionPane.ERROR_MESSAGE);
            updateServerButtons();
        }
    }
    
    /**
     * Stops the proxy server.
     */
    private void stopProxyServer() {
        logMessage("Stopping SOCKS Proxy Rotator server...");
        socksProxyService.stop();
        updateServerButtons();
        logMessage("SOCKS Proxy Rotator server stopped.");
    }
    
    /**
     * Updates the server control buttons based on service state.
     */
    private void updateServerButtons() {
        SwingUtilities.invokeLater(() -> {
            if (startServerButton != null && stopServerButton != null && portField != null) {
                boolean running = socksProxyService != null && socksProxyService.isRunning();
                startServerButton.setEnabled(!running);
                stopServerButton.setEnabled(running);
                portField.setEnabled(!running);
            }
        });
    }

    /**
     * Performs shutdown operations.
     */
    private void shutdown() {
        logMessage("Extension unloading. Stopping proxy service...");
         
        if (socksProxyService != null) {
            stopProxyServer();
        }
        saveProxies();
        logMessage("SOCKS Proxy Rotator extension shut down.");
    }
    
    /**
     * Adds a proxy to the list.
     */
    private void addProxy(ProxyEntry proxy) {
        boolean added = false;
        proxyListLock.writeLock().lock();
        try {
            // Prevent duplicates
            boolean exists = proxyList.stream().anyMatch(p -> 
                p.getHost().equalsIgnoreCase(proxy.getHost()) && p.getPort() == proxy.getPort());
            if (!exists) {
                proxyList.add(proxy);
                added = true;
            } else {
                logMessage("Proxy " + proxy.getHost() + ":" + proxy.getPort() + " already exists.");
            }
        } finally {
            proxyListLock.writeLock().unlock();
        }
         
        if (added) {
            updateProxyTable();
            saveProxies();
            logMessage("Added proxy: " + proxy.getHost() + ":" + proxy.getPort());
        }
    }
    
    /**
     * Removes a proxy from the list.
     */
    private void removeProxy(int index) {
        ProxyEntry removed = null;
        proxyListLock.writeLock().lock();
        try {
            if (index >= 0 && index < proxyList.size()) {
                removed = proxyList.remove(index);
            }
        } finally {
            proxyListLock.writeLock().unlock();
        }
        
        if (removed != null) {
            updateProxyTable();
            saveProxies();
            logMessage("Removed proxy: " + removed.getHost() + ":" + removed.getPort());
        }
    }
    
    /**
     * Clears all proxies from the list.
     */
    private void clearAllProxies() {
        int count = 0;
        proxyListLock.writeLock().lock();
        try {
            count = proxyList.size();
            proxyList.clear();
        } finally {
            proxyListLock.writeLock().unlock();
        }
        
        if (count > 0) {
            updateProxyTable();
            saveProxies();
            logMessage("Cleared all " + count + " proxies.");
        }
    }
    
    /**
     * Updates the proxy table model.
     */
    private void updateProxyTable() {
        if (proxyTableModel != null) {
            SwingUtilities.invokeLater(() -> {
                proxyTableModel.fireTableDataChanged();
                updateServerButtons();
            });
        }
    }
    
    /**
     * Logs a message to both the UI and Burp's output.
     */
    private void logMessage(String message) {
        if (api != null && api.logging() != null) {
            api.logging().logToOutput(message);
        }
        
        if (logTextArea != null) {
            SwingUtilities.invokeLater(() -> {
                logTextArea.append(message + "\n");
                logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
            });
        }
    }
    
    /**
     * Table model for displaying proxies.
     */
    private class ProxyTableModel extends AbstractTableModel {
        private final String[] columnNames = {"Host", "Port", "Status"};
        
        @Override
        public int getRowCount() {
            proxyListLock.readLock().lock();
            try {
                return proxyList.size();
            } finally {
                proxyListLock.readLock().unlock();
            }
        }
        
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }
        
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ProxyEntry entry = null;
            proxyListLock.readLock().lock();
            try {
                if (rowIndex >= 0 && rowIndex < proxyList.size()) {
                    entry = proxyList.get(rowIndex);
                }
            } finally {
                proxyListLock.readLock().unlock();
            }

            if (entry != null) {
                switch (columnIndex) {
                    case 0: return entry.getHost();
                    case 1: return entry.getPort();
                    case 2:
                        String status = entry.isActive() ? "Active" : "Inactive";
                        String error = entry.getErrorMessage();
                        return status + (error != null && !error.isEmpty() ? ": " + error : "");
                    default: return null;
                }
            }
            return null;
        }
        
        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 1) return Integer.class;
            return String.class;
        }
    }
    
    /**
     * Sets up the table renderer.
     */
    private void setupTableRenderer(JTable proxyTable) {
        proxyTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                
                c.setForeground(table.getForeground());
                 
                int modelRow = table.convertRowIndexToModel(row);
                 
                ProxyEntry entry = null;
                proxyListLock.readLock().lock();
                try {
                    if (modelRow >= 0 && modelRow < proxyList.size()) {
                        entry = proxyList.get(modelRow);
                    }
                } finally {
                    proxyListLock.readLock().unlock();
                }

                if (entry != null && !entry.isActive()) {
                    c.setForeground(Color.RED);
                }
                 
                if (column == 1) {
                    ((JLabel) c).setHorizontalAlignment(SwingConstants.CENTER);
                } else {
                    ((JLabel) c).setHorizontalAlignment(SwingConstants.LEFT);
                }

                return c;
            }
        });
        proxyTable.setAutoCreateRowSorter(true);
    }
    
    /**
     * Validates all proxies in the list.
     */
    private void validateAllProxies() {
        List<ProxyEntry> proxiesToValidate;
        proxyListLock.readLock().lock();
        try {
            if (proxyList.isEmpty()) {
                JOptionPane.showMessageDialog(null,
                    "No proxies to validate.",
                    "Validation",
                    JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            proxiesToValidate = new ArrayList<>(proxyList);
        } finally {
            proxyListLock.readLock().unlock();
        }

        new Thread(() -> {
            int total = proxiesToValidate.size();
            final int[] activeCount = new int[1];
            final int[] completedCount = new int[1];
            
            logMessage("Starting validation for " + total + " proxies...");
            
            ExecutorService validationPool = Executors.newFixedThreadPool(
                Math.min(10, Runtime.getRuntime().availableProcessors()));
            
            for (ProxyEntry proxy : proxiesToValidate) {
                validationPool.submit(() -> {
                    try {
                        boolean isActive = validateProxy(proxy, 2);
                        if (isActive) {
                            synchronized (activeCount) {
                                activeCount[0]++;
                            }
                        }
                        updateProxyTable();
                        synchronized (completedCount) {
                            completedCount[0]++;
                            if (completedCount[0] % 5 == 0 || completedCount[0] == total) {
                                logMessage("Proxy validation progress: " + completedCount[0] + "/" + total + " completed");
                            }
                        }
                    } catch (Exception e) {
                        logMessage("Error validating proxy " + proxy.getHost() + ":" + proxy.getPort() + 
                                  " - " + e.getMessage());
                        proxy.setActive(false);
                        proxy.setErrorMessage("Validation error: " + e.getMessage());
                        updateProxyTable();
                        synchronized (completedCount) {
                            completedCount[0]++;
                        }
                    }
                });
            }
            
            validationPool.shutdown();
            try {
                validationPool.awaitTermination(30, java.util.concurrent.TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            final int finalActiveCount = activeCount[0];
            logMessage("Validation complete. " + finalActiveCount + " of " + total + " proxies are active.");
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(null, 
                    "Validation complete. " + finalActiveCount + " of " + total + " proxies are active.",
                    "Validation Results", 
                    JOptionPane.INFORMATION_MESSAGE);
            });
        }).start();
    }
    
    /**
     * Validates a single proxy.
     */
    private boolean validateProxy(ProxyEntry proxy, int maxAttempts) {
        logMessage("Validating proxy: " + proxy.getHost() + ":" + proxy.getPort());
        proxy.setErrorMessage("Validating...");
        updateProxyTable();

        boolean success = false;
        String finalErrorMessage = "Validation failed";

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            Socket socket = null;
            try {
                socket = new Socket();
                socket.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()), 3000);
                socket.setSoTimeout(3000);

                OutputStream out = socket.getOutputStream();
                InputStream in = socket.getInputStream();
                
                // Send SOCKS5 greeting (No Auth)
                out.write(new byte[]{0x05, 0x01, 0x00});
                out.flush();
                
                byte[] response = new byte[2];
                int bytesRead = in.read(response);
                
                if (bytesRead == 2 && response[0] == 0x05 && response[1] == 0x00) {
                    logMessage("Proxy validated successfully: " + proxy.getHost() + ":" + proxy.getPort());
                    success = true;
                    finalErrorMessage = "";
                    break;
                } else if (bytesRead > 0 && response[0] == 'H') {
                    finalErrorMessage = "Not a SOCKS proxy (received HTTP response)";
                    logMessage("Proxy validation failed: " + proxy.getHost() + ":" + proxy.getPort() + 
                             " - " + finalErrorMessage);
                    break;
                } else {
                    finalErrorMessage = "Invalid SOCKS response";
                    logMessage("Attempt " + attempt + "/" + maxAttempts + " failed: " + finalErrorMessage);
                }
            } catch (IOException e) {
                finalErrorMessage = e.getMessage();
                if (finalErrorMessage == null || finalErrorMessage.isEmpty()) {
                    finalErrorMessage = e.getClass().getSimpleName();
                }
                logMessage("Attempt " + attempt + "/" + maxAttempts + " failed: " + finalErrorMessage);
            } finally {
                if (socket != null) {
                    try { socket.close(); } catch (IOException e) { /* ignore */ }
                }
            }
            
            if (!success && attempt < maxAttempts) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    finalErrorMessage = "Validation interrupted";
                    break;
                }
            }
        }

        proxy.setActive(success);
        proxy.setErrorMessage(finalErrorMessage);
        updateProxyTable();

        return success;
    }

    /**
     * Notify that a proxy has failed.
     */
    public void notifyProxyFailure(String host, int port, String errorMessage) {
        SwingUtilities.invokeLater(() -> {
            proxyListLock.writeLock().lock();
            try {
                for (ProxyEntry proxy : proxyList) {
                    if (proxy.getHost().equals(host) && proxy.getPort() == port) {
                        proxy.setActive(false);
                        proxy.setErrorMessage(errorMessage != null ? errorMessage : "Connection failed");
                        logMessage("Proxy marked inactive: " + host + ":" + port + " - " + proxy.getErrorMessage());
                        break;
                    }
                }
            } finally {
                proxyListLock.writeLock().unlock();
            }
            updateProxyTable();
        });
    }
    
    /**
     * Notify that a proxy has been reactivated.
     */
    public void notifyProxyReactivated(String host, int port) {
        SwingUtilities.invokeLater(() -> {
            proxyListLock.writeLock().lock();
            try {
                for (ProxyEntry proxy : proxyList) {
                    if (proxy.getHost().equals(host) && proxy.getPort() == port && !proxy.isActive()) {
                        proxy.setActive(true);
                        proxy.setErrorMessage("");
                        logMessage("Proxy reactivated: " + host + ":" + port);
                        break;
                    }
                }
            } finally {
                proxyListLock.writeLock().unlock();
            }
            updateProxyTable();
        });
    }
}