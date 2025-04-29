/**
 * Burp SOCKS Proxy Rotate
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
    
    // Regular expression for proxy format validation
    private static final String PROXY_URL_REGEX = "^(socks[45])://([^:]+):(\\d+)$";
    private static final String PROXY_HOST_PORT_REGEX = "^([^:]+):(\\d+)$";
    
    // Configuration 
    private int configuredLocalPort = 1080;
    
    // Settings with defaults
    private int bufferSize = 8092; // 8KB
    private int connectionTimeoutSec = 20;
    private int socketTimeoutSec = 120; 
    private int maxRetryCount = 2;
    private int maxConnectionsPerProxy = 50;
    private boolean loggingEnabled = true;
    
    // UI components for settings
    private JSpinner bufferSizeSpinner;
    private JSpinner connectionTimeoutSpinner;
    private JSpinner socketTimeoutSpinner;
    private JSpinner maxRetrySpinner;
    private JSpinner maxConnectionsPerProxySpinner;
    private JCheckBox enableLoggingCheckbox;
    
    // Persistence keys
    private static final String PROXY_LIST_KEY = "proxyList";
    private static final String PORT_KEY = "localPort";
    private static final String BUFFER_SIZE_KEY = "bufferSize";
    private static final String CONNECTION_TIMEOUT_KEY = "connectionTimeout";
    private static final String SOCKET_TIMEOUT_KEY = "socketTimeout";
    private static final String MAX_RETRY_KEY = "maxRetry";
    private static final String MAX_CONNECTIONS_PER_PROXY_KEY = "maxConnectionsPerProxy";
    private static final String LOGGING_ENABLED_KEY = "loggingEnabled";
    
    // Add a timer field at the class level
    private javax.swing.Timer statsUpdateTimer;
    private JLabel statsLabel;

    // Add default constants
    private static final int DEFAULT_BUFFER_SIZE = 8092;
    private static final int DEFAULT_CONNECTION_TIMEOUT = 20;
    private static final int DEFAULT_SOCKET_TIMEOUT = 120;
    private static final int DEFAULT_MAX_RETRY = 2;
    private static final int DEFAULT_MAX_CONNECTIONS_PER_PROXY = 50;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Burp SOCKS Rotate");
        
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
            api.userInterface().registerSuiteTab("SOCKS Rotate", panel);
            updateServerButtons();
        });
        
        // Add shutdown hook
        api.extension().registerUnloadingHandler(this::shutdown);
        
        logMessage("Burp SOCKS Proxy Rotate extension loaded successfully");
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
                if (parts.length >= 2) {
                    try {
                        String protocol = "socks5";
                        String host;
                        int port;
                        
                        if (parts.length >= 3 && parts[0].startsWith("socks")) {
                            // Format: socks5://host:port
                            protocol = parts[0];
                            host = parts[1].substring(2);
                            port = Integer.parseInt(parts[2].trim());
                        } else {
                            // Legacy format: host:port
                            host = parts[0].trim();
                            port = Integer.parseInt(parts[1].trim());
                        }
                        
                        if (!host.isEmpty() && port > 0 && port <= 65535) {
                            proxyListLock.writeLock().lock();
                            try {
                                proxyList.add(new ProxyEntry(host, port, protocol));
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
        
        // Load settings
        String bufferSizeSetting = api.persistence().preferences().getString(BUFFER_SIZE_KEY);
        if (bufferSizeSetting != null) {
            try {
                bufferSize = Integer.parseInt(bufferSizeSetting);
            } catch (NumberFormatException e) {
                // Use default
            }
        }
        
        String connectionTimeoutSetting = api.persistence().preferences().getString(CONNECTION_TIMEOUT_KEY);
        if (connectionTimeoutSetting != null) {
            try {
                connectionTimeoutSec = Integer.parseInt(connectionTimeoutSetting);
            } catch (NumberFormatException e) {
                // Use default
            }
        }
        
        String socketTimeoutSetting = api.persistence().preferences().getString(SOCKET_TIMEOUT_KEY);
        if (socketTimeoutSetting != null) {
            try {
                socketTimeoutSec = Integer.parseInt(socketTimeoutSetting);
            } catch (NumberFormatException e) {
                // Use default
            }
        }
        
        String maxRetrySetting = api.persistence().preferences().getString(MAX_RETRY_KEY);
        if (maxRetrySetting != null) {
            try {
                maxRetryCount = Integer.parseInt(maxRetrySetting);
            } catch (NumberFormatException e) {
                // Use default
            }
        }
        
        String maxConnectionsPerProxySetting = api.persistence().preferences().getString(MAX_CONNECTIONS_PER_PROXY_KEY);
        if (maxConnectionsPerProxySetting != null) {
            try {
                maxConnectionsPerProxy = Integer.parseInt(maxConnectionsPerProxySetting);
            } catch (NumberFormatException e) {
                // Use default
            }
        }
        
        String loggingEnabledSetting = api.persistence().preferences().getString(LOGGING_ENABLED_KEY);
        if (loggingEnabledSetting != null) {
            loggingEnabled = Boolean.parseBoolean(loggingEnabledSetting);
        }
    }
    
    /**
     * Saves proxies and settings to Montoya persistence.
     */
    private void saveProxies() {
        api.persistence().preferences().setString(PROXY_LIST_KEY, proxyListToString());
        api.persistence().preferences().setString(PORT_KEY, String.valueOf(configuredLocalPort));
    }
    
    /**
     * Converts the proxy list to a string for storage.
     */
    private String proxyListToString() {
        StringBuilder sb = new StringBuilder();
        proxyListLock.readLock().lock();
        try {
            for (ProxyEntry entry : proxyList) {
                sb.append(entry.getProtocol()).append("://")
                  .append(entry.getHost()).append(":")
                  .append(entry.getPort()).append("\n");
            }
        } finally {
            proxyListLock.readLock().unlock();
        }
        
        return sb.toString();
    }
    
    private void saveSettings() {
        // Save each setting
        api.persistence().preferences().setString(PROXY_LIST_KEY, proxyListToString());
        api.persistence().preferences().setString(PORT_KEY, String.valueOf(configuredLocalPort));
        api.persistence().preferences().setString(BUFFER_SIZE_KEY, String.valueOf(bufferSize));
        api.persistence().preferences().setString(CONNECTION_TIMEOUT_KEY, String.valueOf(connectionTimeoutSec));
        api.persistence().preferences().setString(SOCKET_TIMEOUT_KEY, String.valueOf(socketTimeoutSec));
        api.persistence().preferences().setString(MAX_RETRY_KEY, String.valueOf(maxRetryCount));
        api.persistence().preferences().setString(MAX_CONNECTIONS_PER_PROXY_KEY, String.valueOf(maxConnectionsPerProxy));
        api.persistence().preferences().setString(LOGGING_ENABLED_KEY, String.valueOf(loggingEnabled));
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
        startServerButton.addActionListener(_ -> startProxyServer());
        serverControls.add(startServerButton);
        
        stopServerButton = new JButton("Stop Proxy Server");
        stopServerButton.addActionListener(_ -> stopProxyServer());
        stopServerButton.setEnabled(false);
        serverControls.add(stopServerButton);
        
        // Add a stats label
        statsLabel = new JLabel("Connection pool not active");
        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statsPanel.add(statsLabel);
        
        controlPanel.add(serverControls);
        controlPanel.add(statsPanel);
        
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
        
        JLabel protocolLabel = new JLabel("Protocol:");
        JComboBox<String> protocolCombo = new JComboBox<>(new String[]{"socks5", "socks4"});
        JLabel hostLabel = new JLabel("Host:");
        JTextField hostField = new JTextField(15);
        JLabel portLabel = new JLabel("Port:");
        JTextField addPortField = new JTextField(5);
        JButton addButton = new JButton("Add Proxy");
        JButton validateAllButton = new JButton("Validate All");
        
        gbc.gridx = 0;
        gbc.gridy = 0;
        inputPanel.add(protocolLabel, gbc);
        
        gbc.gridx = 1;
        inputPanel.add(protocolCombo, gbc);
        
        gbc.gridx = 2;
        inputPanel.add(hostLabel, gbc);
        
        gbc.gridx = 3;
        inputPanel.add(hostField, gbc);
        
        gbc.gridx = 4;
        inputPanel.add(portLabel, gbc);
        
        gbc.gridx = 5;
        inputPanel.add(addPortField, gbc);
        
        gbc.gridx = 6;
        inputPanel.add(addButton, gbc);
        
        gbc.gridx = 7;
        inputPanel.add(validateAllButton, gbc);
        
        addButton.addActionListener(_ -> {
            String protocol = (String) protocolCombo.getSelectedItem();
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
                
                ProxyEntry proxy = new ProxyEntry(host, port, protocol);
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
        
        validateAllButton.addActionListener(_ -> validateAllProxies());
        
        // Bulk add panel
        JPanel bulkPanel = new JPanel(new BorderLayout(5, 5));
        JTextArea bulkTextArea = new JTextArea(5, 30);
        bulkTextArea.setToolTipText("Enter one proxy per line in format socks5://host:port or socks4://host:port");
        JScrollPane bulkScrollPane = new JScrollPane(bulkTextArea);
        JButton bulkAddButton = new JButton("Add Multiple Proxies");
        
        bulkPanel.add(new JLabel("Add multiple proxies (format: socks5://host:port, one per line):"), BorderLayout.NORTH);
        bulkPanel.add(bulkScrollPane, BorderLayout.CENTER);
        bulkPanel.add(bulkAddButton, BorderLayout.SOUTH);
        
        bulkAddButton.addActionListener(_ -> {
            String bulk = bulkTextArea.getText().trim();
            if (bulk.isEmpty()) {
                return;
            }
            
            String[] lines = bulk.split("\n");
            int added = 0;
            List<ProxyEntry> proxiesToAdd = new ArrayList<>();
            List<String> invalidLines = new ArrayList<>();

            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                
                try {
                    ProxyEntry proxy = parseProxyUrl(line);
                    if (proxy != null) {
                        boolean exists = false;
                        proxyListLock.readLock().lock();
                        try {
                            for (ProxyEntry existing : proxyList) {
                                if (existing.getHost().equalsIgnoreCase(proxy.getHost()) && 
                                    existing.getPort() == proxy.getPort() &&
                                    existing.getProtocol().equals(proxy.getProtocol())) {
                                    exists = true;
                                    break;
                                }
                            }
                        } finally {
                            proxyListLock.readLock().unlock();
                        }
                        if (!exists) {
                            proxiesToAdd.add(proxy);
                        } else {
                            logMessage("Skipping duplicate proxy: " + proxy.getProtocol() + "://" + proxy.getHost() + ":" + proxy.getPort());
                        }
                    } else {
                        invalidLines.add(line);
                    }
                } catch (Exception ex) {
                    invalidLines.add(line);
                }
            }

            // Display errors for invalid lines
            if (!invalidLines.isEmpty()) {
                StringBuilder errorMsg = new StringBuilder("Invalid proxy format in the following lines:\n");
                for (int i = 0; i < Math.min(5, invalidLines.size()); i++) {
                    errorMsg.append(" - ").append(invalidLines.get(i)).append("\n");
                }
                if (invalidLines.size() > 5) {
                    errorMsg.append(" - ... and ").append(invalidLines.size() - 5).append(" more\n");
                }
                errorMsg.append("\nExpected format: socks5://host:port or socks4://host:port");
                
                JOptionPane.showMessageDialog(null, errorMsg.toString(), "Invalid Proxy Format", JOptionPane.ERROR_MESSAGE);
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
        
        deleteButton.addActionListener(_ -> {
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
        
        clearButton.addActionListener(_ -> {
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
        
        // Create settings panel
        JPanel settingsPanel = createSettingsPanel();
        
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
        tabbedPane.addTab("Settings", settingsPanel);
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
                    "Burp SOCKS Rotate started on localhost:" + portToUse + "\n\n" +
                    "To use it:\n" +
                    "1. Go to Burp Settings > Network > Connections > SOCKS Proxy\n" +
                    "2. Check 'Use SOCKS proxy'\n" +
                    "3. Set Host to 'localhost' and Port to '" + portToUse + "'\n\n" +
                    "Burp SOCKS Rotate Proxy Service will route each request through a different active SOCKS proxy from your list.",
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
            
            // Initialize service with current settings
            socksProxyService.setSettings(
                bufferSize,
                connectionTimeoutSec * 1000, // Convert to milliseconds
                socketTimeoutSec * 1000,     // Convert to milliseconds
                maxRetryCount,
                maxConnectionsPerProxy
            );
            
            // Set up a timer to update stats less frequently (5 seconds instead of 2)
            if (statsLabel != null) {
                if (statsUpdateTimer == null) {
                    statsUpdateTimer = new javax.swing.Timer(5000, _ -> {
                        if (socksProxyService != null && socksProxyService.isRunning()) {
                            String stats = socksProxyService.getConnectionPoolStats();
                            statsLabel.setText(stats);
                            
                            // Only log stats when there's significant activity and logging is enabled
                            if (loggingEnabled) {
                                int activeConnections = socksProxyService.getActiveConnectionCount();
                                // Only log if more than 5 connections or every 30 seconds
                                if (activeConnections > 5 || (System.currentTimeMillis() / 1000) % 30 == 0) {
                                    logMessage(stats);
                                }
                            }
                        }
                    });
                }
                statsUpdateTimer.start();
            }
            
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
        logMessage("Stopping Burp SOCKS Rotate server...");
        socksProxyService.stop();
        updateServerButtons();
        logMessage("Burp SOCKS Rotate server stopped.");

        if (statsUpdateTimer != null && statsUpdateTimer.isRunning()) {
            statsUpdateTimer.stop();
        }
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
        logMessage("Burp SOCKS Rotate extension shut down.");

        if (statsUpdateTimer != null && statsUpdateTimer.isRunning()) {
            statsUpdateTimer.stop();
        }
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
        // Only log to Burp output if logging is enabled
        if (api != null && api.logging() != null && loggingEnabled) {
            api.logging().logToOutput(message);
        }
        
        // Always log to the UI text area
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
        private final String[] columnNames = {"Protocol", "Host", "Port", "Status"};
        
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
                    case 0: return entry.getProtocol();
                    case 1: return entry.getHost();
                    case 2: return entry.getPort();
                    case 3:
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
            if (columnIndex == 2) return Integer.class;
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
        logMessage("Validating proxy: " + proxy.getProtocol() + "://" + proxy.getHost() + ":" + proxy.getPort());
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
                
                // Send greeting based on protocol
                int protocolVersion = proxy.getProtocolVersion();
                
                if (protocolVersion == 5) {
                    // SOCKS5 greeting (No Auth)
                    out.write(new byte[]{0x05, 0x01, 0x00});
                    out.flush();
                    
                    byte[] response = new byte[2];
                    int bytesRead = in.read(response);
                    
                    if (bytesRead == 2 && response[0] == 0x05 && response[1] == 0x00) {
                        logMessage("SOCKS5 proxy validated successfully: " + proxy.getHost() + ":" + proxy.getPort());
                        success = true;
                        finalErrorMessage = "";
                        break;
                    } else if (bytesRead > 0 && response[0] == 'H') {
                        finalErrorMessage = "Not a SOCKS proxy (received HTTP response)";
                        logMessage("Proxy validation failed: " + proxy.getHost() + ":" + proxy.getPort() + 
                                 " - " + finalErrorMessage);
                        break;
                    } else {
                        finalErrorMessage = "Invalid SOCKS5 response";
                        logMessage("Attempt " + attempt + "/" + maxAttempts + " failed: " + finalErrorMessage);
                    }
                } else if (protocolVersion == 4) {
                    // SOCKS4 doesn't have a simple handshake we can use to just test the connection
                    // We have to send a connect request to a real host
                    
                    // Send a request to connect to a test host (e.g., google.com:80)
                    // This is just a test connect, we're not actually going to use the connection
                    out.write(new byte[] {
                        0x04, // SOCKS version
                        0x01, // CONNECT command
                        0x00, 0x50, // Port 80 (web)
                        0x08, 0x08, 0x08, 0x08, // IP 8.8.8.8 (Google DNS)
                        0x00  // User ID (empty)
                    });
                    out.flush();
                    
                    byte[] response = new byte[8];
                    int bytesRead = in.read(response);
                    
                    // We just want to verify we get a SOCKS4 response, not that it succeeds
                    if (bytesRead == 8 && response[0] == 0x00) {
                        // This is a SOCKS4 proxy - even if it returns an error code, we know it speaks SOCKS4
                        logMessage("SOCKS4 proxy validated successfully: " + proxy.getHost() + ":" + proxy.getPort());
                        success = true;
                        finalErrorMessage = "";
                        break;
                    } else if (bytesRead > 0 && response[0] == 'H') {
                        finalErrorMessage = "Not a SOCKS proxy (received HTTP response)";
                        logMessage("Proxy validation failed: " + proxy.getHost() + ":" + proxy.getPort() + 
                                 " - " + finalErrorMessage);
                        break;
                    } else {
                        finalErrorMessage = "Invalid SOCKS4 response";
                        logMessage("Attempt " + attempt + "/" + maxAttempts + " failed: " + finalErrorMessage);
                    }
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
     * Parse a proxy URL string into a ProxyEntry object.
     * Accepts formats like:
     * - socks5://host:port
     * - socks4://host:port
     * - host:port (defaults to socks5)
     * 
     * @param proxyUrl the proxy URL string
     * @return a ProxyEntry object or null if the format is invalid
     */
    private ProxyEntry parseProxyUrl(String proxyUrl) {
        if (proxyUrl == null || proxyUrl.trim().isEmpty()) {
            return null;
        }
        
        // Check if the URL has protocol specification
        if (proxyUrl.startsWith("socks")) {
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(PROXY_URL_REGEX);
            java.util.regex.Matcher matcher = pattern.matcher(proxyUrl);
            
            if (matcher.matches()) {
                String protocol = matcher.group(1);
                String host = matcher.group(2);
                int port = Integer.parseInt(matcher.group(3));
                
                // Validate port range
                if (port > 0 && port <= 65535) {
                    return new ProxyEntry(host, port, protocol);
                }
            }
        } else {
            // Try the legacy format host:port
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(PROXY_HOST_PORT_REGEX);
            java.util.regex.Matcher matcher = pattern.matcher(proxyUrl);
            
            if (matcher.matches()) {
                String host = matcher.group(1);
                int port = Integer.parseInt(matcher.group(2));
                
                // Validate port range
                if (port > 0 && port <= 65535) {
                    return new ProxyEntry(host, port, "socks5"); // Default to socks5
                }
            }
        }
        
        return null;
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

    /**
     * Creates the settings panel with all configuration options.
     */
    private JPanel createSettingsPanel() {
        JPanel settingsPanel = new JPanel(new BorderLayout(10, 10));
        settingsPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Create a panel with GridBagLayout for the settings
        JPanel controlsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Buffer Size
        gbc.gridx = 0;
        gbc.gridy = 0;
        controlsPanel.add(new JLabel("Buffer Size (bytes):"), gbc);
        
        SpinnerNumberModel bufferModel = new SpinnerNumberModel(bufferSize, 1024, 1048576, 1024); // 1KB to 1MB
        bufferSizeSpinner = new JSpinner(bufferModel);
        bufferSizeSpinner.addChangeListener(_ -> {
            bufferSize = (Integer) bufferSizeSpinner.getValue();
            saveSettings();
            logMessage("Buffer size updated to " + bufferSize + " bytes");
        });
        
        gbc.gridx = 1;
        controlsPanel.add(bufferSizeSpinner, gbc);
        
        // Connection Timeout
        gbc.gridx = 0;
        gbc.gridy = 1;
        controlsPanel.add(new JLabel("Connection Timeout (seconds):"), gbc);
        
        SpinnerNumberModel connTimeoutModel = new SpinnerNumberModel(connectionTimeoutSec, 1, 300, 1); // 1-300 seconds
        connectionTimeoutSpinner = new JSpinner(connTimeoutModel);
        connectionTimeoutSpinner.addChangeListener(_ -> {
            connectionTimeoutSec = (Integer) connectionTimeoutSpinner.getValue();
            saveSettings();
            logMessage("Connection timeout updated to " + connectionTimeoutSec + " seconds");
        });
        
        gbc.gridx = 1;
        controlsPanel.add(connectionTimeoutSpinner, gbc);
        
        // Socket Timeout
        gbc.gridx = 0;
        gbc.gridy = 2;
        controlsPanel.add(new JLabel("Socket Timeout (seconds):"), gbc);
        
        SpinnerNumberModel socketTimeoutModel = new SpinnerNumberModel(socketTimeoutSec, 1, 300, 1); // 1-300 seconds
        socketTimeoutSpinner = new JSpinner(socketTimeoutModel);
        socketTimeoutSpinner.addChangeListener(_ -> {
            socketTimeoutSec = (Integer) socketTimeoutSpinner.getValue();
            saveSettings();
            logMessage("Socket timeout updated to " + socketTimeoutSec + " seconds");
        });
        
        gbc.gridx = 1;
        controlsPanel.add(socketTimeoutSpinner, gbc);
        
        // Max Retry Count
        gbc.gridx = 0;
        gbc.gridy = 3;
        controlsPanel.add(new JLabel("Max Retry Count:"), gbc);
        
        SpinnerNumberModel maxRetryModel = new SpinnerNumberModel(maxRetryCount, 0, 10, 1); // 0-10 retries
        maxRetrySpinner = new JSpinner(maxRetryModel);
        maxRetrySpinner.addChangeListener(_ -> {
            maxRetryCount = (Integer) maxRetrySpinner.getValue();
            saveSettings();
            logMessage("Max retry count updated to " + maxRetryCount);
        });
        
        gbc.gridx = 1;
        controlsPanel.add(maxRetrySpinner, gbc);
        
        // Max Connections Per Proxy
        gbc.gridx = 0;
        gbc.gridy = 4;
        controlsPanel.add(new JLabel("Max Connections Per Proxy:"), gbc);
        
        SpinnerNumberModel maxConnectionsPerProxyModel = new SpinnerNumberModel(maxConnectionsPerProxy, 5, 1000, 5); // 5-1000 connections
        maxConnectionsPerProxySpinner = new JSpinner(maxConnectionsPerProxyModel);
        maxConnectionsPerProxySpinner.addChangeListener(_ -> {
            maxConnectionsPerProxy = (Integer) maxConnectionsPerProxySpinner.getValue();
            saveSettings();
            logMessage("Max connections per proxy updated to " + maxConnectionsPerProxy);
        });
        
        gbc.gridx = 1;
        controlsPanel.add(maxConnectionsPerProxySpinner, gbc);
        
        // Enable Logging
        gbc.gridx = 0;
        gbc.gridy = 5;
        controlsPanel.add(new JLabel("Enable Logging:"), gbc);
        
        enableLoggingCheckbox = new JCheckBox();
        enableLoggingCheckbox.setSelected(loggingEnabled);
        enableLoggingCheckbox.addActionListener(_ -> {
            loggingEnabled = enableLoggingCheckbox.isSelected();
            saveSettings();
            logMessage("Logging " + (loggingEnabled ? "enabled" : "disabled"));
        });
        
        gbc.gridx = 1;
        controlsPanel.add(enableLoggingCheckbox, gbc);
        
        // Reset Default Settings Button
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        JButton resetButton = new JButton("Reset Default Settings");
        resetButton.addActionListener(_ -> resetDefaultSettings());
        controlsPanel.add(resetButton, gbc);
        
        // Add explanatory text
        JTextArea explanationText = new JTextArea(
            "Changes take effect immediately and will be used for all new connections.\n" +
            "Existing connections will continue to use their current settings.\n\n" +
            "Max Connections Per Proxy limits how many connections each proxy can handle\n" +
            "before requests are routed to a different proxy."
        );
        explanationText.setEditable(false);
        explanationText.setLineWrap(true);
        explanationText.setWrapStyleWord(true);
        explanationText.setBackground(settingsPanel.getBackground());
        explanationText.setBorder(new EmptyBorder(10, 5, 5, 5));
        
        // Add components to settings panel
        settingsPanel.add(controlsPanel, BorderLayout.NORTH);
        settingsPanel.add(explanationText, BorderLayout.CENTER);
        
        return settingsPanel;
    }
    
    /**
     * Resets all settings to their default values except for logging setting.
     */
    private void resetDefaultSettings() {
        // Store current logging state
        boolean currentLoggingState = loggingEnabled;
        
        // Reset to defaults
        bufferSize = DEFAULT_BUFFER_SIZE;
        connectionTimeoutSec = DEFAULT_CONNECTION_TIMEOUT;
        socketTimeoutSec = DEFAULT_SOCKET_TIMEOUT;
        maxRetryCount = DEFAULT_MAX_RETRY;
        maxConnectionsPerProxy = DEFAULT_MAX_CONNECTIONS_PER_PROXY;
        
        // Restore logging state
        loggingEnabled = currentLoggingState;
        
        // Update UI
        bufferSizeSpinner.setValue(bufferSize);
        connectionTimeoutSpinner.setValue(connectionTimeoutSec);
        socketTimeoutSpinner.setValue(socketTimeoutSec);
        maxRetrySpinner.setValue(maxRetryCount);
        maxConnectionsPerProxySpinner.setValue(maxConnectionsPerProxy);
        
        // Save settings
        saveSettings();
        
        logMessage("Settings reset to defaults (except logging)");
        
        // Show confirmation dialog
        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, 
            "Settings have been reset to default values:\n\n" +
            "• Buffer Size: " + bufferSize + " bytes\n" +
            "• Connection Timeout: " + connectionTimeoutSec + " seconds\n" +
            "• Socket Timeout: " + socketTimeoutSec + " seconds\n" +
            "• Max Retry Count: " + maxRetryCount + "\n" +
            "• Max Connections Per Proxy: " + maxConnectionsPerProxy + "\n\n" +
            "Logging setting was preserved: " + (loggingEnabled ? "Enabled" : "Disabled"),
            "Settings Reset", 
            JOptionPane.INFORMATION_MESSAGE));
    }
}