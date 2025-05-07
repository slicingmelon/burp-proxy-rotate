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
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.Random;

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
    private JButton enableButton;
    private JButton disableButton;
    private JLabel statusLabel;
    
    // Regular expression for proxy format validation
    private static final String PROXY_URL_REGEX = "^(socks[45])://([^:]+):(\\d+)$";
    private static final String PROXY_HOST_PORT_REGEX = "^([^:]+):(\\d+)$";
    
    // Configuration 
    private int configuredLocalPort = 0;
    
    // Settings with defaults
    private int bufferSize = 8092; // 8KB
    private int connectionTimeoutSec = 20;
    private int socketTimeoutSec = 120; 
    private int maxRetryCount = 2;
    private int maxConnectionsPerProxy = 50;
    private boolean loggingEnabled = true;
    private boolean bypassCollaborator = true; // Default to bypass Collaborator
    
    // UI components for settings
    private JSpinner bufferSizeSpinner;
    private JSpinner connectionTimeoutSpinner;
    private JSpinner socketTimeoutSpinner;
    private JSpinner maxRetrySpinner;
    private JSpinner maxConnectionsPerProxySpinner;
    private JCheckBox enableLoggingCheckbox;
    private JCheckBox bypassCollaboratorCheckbox;
    private JTextArea bypassDomainsTextArea;
    
    // Persistence keys
    private static final String PROXY_LIST_KEY = "proxyList";
    private static final String PORT_KEY = "localPort";
    private static final String BUFFER_SIZE_KEY = "bufferSize";
    private static final String CONNECTION_TIMEOUT_KEY = "connectionTimeout";
    private static final String SOCKET_TIMEOUT_KEY = "socketTimeout";
    private static final String MAX_RETRY_KEY = "maxRetry";
    private static final String MAX_CONNECTIONS_PER_PROXY_KEY = "maxConnectionsPerProxy";
    private static final String LOGGING_ENABLED_KEY = "loggingEnabled";
    private static final String BYPASS_COLLABORATOR_KEY = "bypassCollaborator";
    private static final String BYPASS_DOMAINS_KEY = "bypassDomains";
    
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
        
        // Set bypass collaborator setting
        socksProxyService.setBypassCollaborator(bypassCollaborator);
        
        // Set logging status
        socksProxyService.setLoggingEnabled(loggingEnabled);

        // Create and register the UI
        SwingUtilities.invokeLater(() -> {
            JComponent panel = createUserInterface();
            api.userInterface().registerSuiteTab("SOCKS Rotate", panel);
            updateServerButtons();
        });
        
        // Add shutdown hook
        api.extension().registerUnloadingHandler(this::shutdown);
        
        logMessage("Burp SOCKS Rotate extension loaded successfully");
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
                                proxyList.add(ProxyEntry.createWithProtocol(host, port, protocol));
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
        
        String bypassCollaboratorSetting = api.persistence().preferences().getString(BYPASS_COLLABORATOR_KEY);
        if (bypassCollaboratorSetting != null) {
            bypassCollaborator = Boolean.parseBoolean(bypassCollaboratorSetting);
        }
    }
    
    /**
     * Loads the bypass domains from persistence and updates the UI.
     */
    private void loadBypassDomains() {
        String savedDomains = api.persistence().preferences().getString(BYPASS_DOMAINS_KEY);
        if (savedDomains != null && !savedDomains.isEmpty()) {
            bypassDomainsTextArea.setText(savedDomains);
            updateBypassDomains(savedDomains);
        } else {
            // Default domains
            String defaultDomains = "burpcollaborator.net\noastify.com";
            bypassDomainsTextArea.setText(defaultDomains);
            updateBypassDomains(defaultDomains);
        }
    }

    /**
     * Updates the bypass domains in the SOCKS proxy service.
     */
    private void updateBypassDomains(String domainsText) {
        if (socksProxyService != null) {
            // Set bypass mode
            socksProxyService.setBypassCollaborator(bypassCollaborator);
            
            // Clear existing domains
            // Note: This assumes there's a clearBypassDomains() method in SocksProxyService
            // You may need to add this or handle it differently
            
            // Add each domain
            String[] domains = domainsText.trim().split("\n");
            for (String domain : domains) {
                domain = domain.trim();
                if (!domain.isEmpty()) {
                    socksProxyService.addBypassDomain(domain);
                }
            }
        }
        
        // Save to persistence
        api.persistence().preferences().setString(BYPASS_DOMAINS_KEY, domainsText);
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
        api.persistence().preferences().setString(BYPASS_COLLABORATOR_KEY, String.valueOf(bypassCollaborator));
    }
    
    /**
     * Creates the user interface components.
     */
    private JComponent createUserInterface() {
        // Create main panel with border layout
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Create top control panel
        JPanel controlPanel = new JPanel(new GridBagLayout());
        
        // Create bottom panel for proxies
        JPanel proxyPanel = new JPanel(new BorderLayout());
        proxyPanel.setBorder(BorderFactory.createTitledBorder("SOCKS Proxies"));
        
        // Create GridBagConstraints for the control panel
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        // Port input - now marked as "Auto" by default
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        controlPanel.add(new JLabel("Local port:"), gbc);
        
        // Use a text field with checkbox to toggle auto/manual
        JCheckBox randomPortCheckbox = new JCheckBox("Random Port", true);
        JSpinner portSpinner = new JSpinner(new SpinnerNumberModel(
                configuredLocalPort > 0 ? configuredLocalPort : 9090, 
                1024, 65535, 1));
        portSpinner.setEnabled(!randomPortCheckbox.isSelected());
        
        randomPortCheckbox.addActionListener(_ -> {
            boolean random = randomPortCheckbox.isSelected();
            portSpinner.setEnabled(!random);
            if (random) {
                configuredLocalPort = 0; // Reset to auto mode
            } else {
                configuredLocalPort = (Integer) portSpinner.getValue();
            }
            api.persistence().preferences().setString(PORT_KEY, String.valueOf(configuredLocalPort));
        });
        
        portSpinner.addChangeListener(_ -> {
            if (!randomPortCheckbox.isSelected()) {
                configuredLocalPort = (Integer) portSpinner.getValue();
                api.persistence().preferences().setString(PORT_KEY, String.valueOf(configuredLocalPort));
            }
        });
        
        // Create a panel for port controls
        JPanel portPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        portPanel.add(randomPortCheckbox);
        portPanel.add(portSpinner);
        
        gbc.gridx = 1;
        gbc.gridy = 0;
        controlPanel.add(portPanel, gbc);
        
        // If we've got a configured port, disable auto mode
        if (configuredLocalPort > 0) {
            randomPortCheckbox.setSelected(false);
            portSpinner.setEnabled(true);
        } else {
            randomPortCheckbox.setSelected(true);
            portSpinner.setEnabled(false);
        }
        
        // Status label
        statusLabel = new JLabel("Status: Stopped");
        gbc.gridx = 2;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        controlPanel.add(statusLabel, gbc);
        
        // Stats label
        statsLabel = new JLabel("No active connections");
        gbc.gridx = 2;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        controlPanel.add(statsLabel, gbc);
        
        // Enable/Disable buttons
        enableButton = new JButton("Start Proxy");
        enableButton.addActionListener(_ -> enableSocksRotate());
        
        disableButton = new JButton("Stop Proxy");
        disableButton.addActionListener(_ -> disableSocksRotate());
        disableButton.setEnabled(false);
        
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        controlPanel.add(enableButton, gbc);
        
        gbc.gridx = 1;
        controlPanel.add(disableButton, gbc);
        
        // Proxy list/table
        proxyTableModel = new ProxyTableModel();
        JTable proxyTable = new JTable(proxyTableModel);
        proxyTable.setFillsViewportHeight(true);
        proxyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        // Setup custom rendering
        setupTableRenderer(proxyTable);
        
        JScrollPane scrollPane = new JScrollPane(proxyTable);
        scrollPane.setPreferredSize(new Dimension(600, 200));
        
        // Create tabbed pane for different proxy addition methods
        JTabbedPane proxyAddTabs = new JTabbedPane();
        
        // Single proxy panel
        JPanel singleAddPanel = new JPanel(new BorderLayout());
        
        // Create a panel for the single unified input
        JPanel unifiedInputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel unifiedLabel = new JLabel("Proxy URL:");
        JTextField unifiedField = new JTextField(25);
        unifiedField.setToolTipText("Format: socks5://host:port or socks4://host:port");
        
        // Add placeholder text
        unifiedField.setText("socks5://host:port");
        unifiedField.setForeground(Color.GRAY);
        unifiedField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (unifiedField.getText().equals("socks5://host:port")) {
                    unifiedField.setText("");
                    unifiedField.setForeground(Color.BLACK);
                }
            }
            
            @Override
            public void focusLost(FocusEvent e) {
                if (unifiedField.getText().isEmpty()) {
                    unifiedField.setText("socks5://host:port");
                    unifiedField.setForeground(Color.GRAY);
                }
            }
        });
        
        JButton unifiedAddButton = new JButton("Add");
        
        unifiedInputPanel.add(unifiedLabel);
        unifiedInputPanel.add(unifiedField);
        unifiedInputPanel.add(unifiedAddButton);
        
        unifiedAddButton.addActionListener(_ -> {
            String proxyUrl = unifiedField.getText().trim();
            if (proxyUrl.isEmpty() || proxyUrl.equals("socks5://host:port")) {
                JOptionPane.showMessageDialog(mainPanel, "Please enter a proxy URL", "Validation Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            ProxyEntry proxy = parseProxyUrl(proxyUrl);
            if (proxy == null) {
                JOptionPane.showMessageDialog(mainPanel, 
                    "Invalid proxy format. Please use socks5://host:port or socks4://host:port", 
                    "Validation Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            addProxy(proxy);
            
            // Validate the newly added proxy
            new Thread(() -> {
                validateProxy(proxy, 3);
                updateProxyTable();
            }).start();
            
            unifiedField.setText("");
            unifiedField.setText("socks5://host:port");
            unifiedField.setForeground(Color.GRAY);
        });
        
        // Add the panels to the singleAddPanel
        singleAddPanel.add(unifiedInputPanel, BorderLayout.CENTER);
        
        // Bulk proxy panel
        JPanel bulkPanel = new JPanel(new BorderLayout(5, 5));
        JTextArea bulkTextArea = new JTextArea(5, 30);
        bulkTextArea.setToolTipText("Enter one proxy per line in format socks5://host:port or socks4://host:port");
        
        // Add placeholder text to make it clearer what's expected
        bulkTextArea.setText("# Enter one proxy per line\n# Examples:\n# socks5://192.168.1.1:1080\n# socks4://proxy.example.com:1080");
        bulkTextArea.setForeground(Color.GRAY);
        bulkTextArea.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (bulkTextArea.getText().startsWith("# Enter")) {
                    bulkTextArea.setText("");
                    bulkTextArea.setForeground(Color.BLACK);
                }
            }
            
            @Override
            public void focusLost(FocusEvent e) {
                if (bulkTextArea.getText().trim().isEmpty()) {
                    bulkTextArea.setText("# Enter one proxy per line\n# Examples:\n# socks5://192.168.1.1:1080\n# socks4://proxy.example.com:1080");
                    bulkTextArea.setForeground(Color.GRAY);
                }
            }
        });
        
        JScrollPane bulkScrollPane = new JScrollPane(bulkTextArea);
        JButton bulkAddButton = new JButton("Add Multiple Proxies");
        
        bulkPanel.add(new JLabel("Enter multiple proxies (one per line):"), BorderLayout.NORTH);
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
        
        // Add tabs
        proxyAddTabs.addTab("Single Proxy", singleAddPanel);
        proxyAddTabs.addTab("Bulk Add", bulkPanel);
        
        // Button panel for the proxy list
        JPanel buttonPanel = new JPanel();
        
        JButton removeButton = new JButton("Remove Selected");
        removeButton.addActionListener(_ -> {
            int selectedRow = proxyTable.getSelectedRow();
            if (selectedRow >= 0) {
                removeProxy(selectedRow);
            }
        });
        
        JButton clearButton = new JButton("Clear All");
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
        
        JButton validateButton = new JButton("Validate All");
        validateButton.addActionListener(_ -> validateAllProxies());
        
        buttonPanel.add(removeButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(validateButton);
        
        JPanel proxyAddPanel = new JPanel(new BorderLayout());
        proxyAddPanel.add(proxyAddTabs, BorderLayout.CENTER);
        
        // Proxy panel with table and controls
        JPanel proxyTablePanel = new JPanel(new BorderLayout());
        proxyTablePanel.add(scrollPane, BorderLayout.CENTER);
        proxyTablePanel.add(buttonPanel, BorderLayout.SOUTH);
        
        // Split panel for table and add controls
        JSplitPane proxySplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, 
                                                 proxyTablePanel, proxyAddPanel);
        proxySplitPane.setResizeWeight(0.7); // Give more space to table
        
        proxyPanel.add(proxySplitPane, BorderLayout.CENTER);
        
        // Log panel
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Log"));
        
        logTextArea = new JTextArea();
        logTextArea.setEditable(false);
        logTextArea.setLineWrap(true);
        logTextArea.setWrapStyleWord(true);
        
        JScrollPane logScrollPane = new JScrollPane(logTextArea);
        logScrollPane.setPreferredSize(new Dimension(600, 150));
        
        logPanel.add(logScrollPane, BorderLayout.CENTER);
        
        // Settings panel
        JPanel settingsPanel = createSettingsPanel();
        
        // Create a tabbed pane for the main UI
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Main tab
        JPanel mainTab = new JPanel(new BorderLayout());
        mainTab.add(controlPanel, BorderLayout.NORTH);
        mainTab.add(proxyPanel, BorderLayout.CENTER);
        mainTab.add(logPanel, BorderLayout.SOUTH);
        
        tabbedPane.addTab("Main", mainTab);
        tabbedPane.addTab("Settings", settingsPanel);
        
        // Add tabbed pane to main panel
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        
        // Setup stats update timer
        statsUpdateTimer = new javax.swing.Timer(1000, _ -> {
            if (socksProxyService != null && socksProxyService.isRunning()) {
                statsLabel.setText(socksProxyService.getConnectionPoolStats());
            } else {
                statsLabel.setText("No active connections");
            }
        });
        statsUpdateTimer.start();
        
        // Update the proxy table
        updateProxyTable();
        
        return mainPanel;
    }
    
    /**
     * Updates Burp Suite's SOCKS proxy settings to use our local proxy.
     */
    private void updateBurpSocksSettings(String host, int port, boolean useProxy) {
        try {
            // Reconstruct settings in JSON format
            String socksHostJson = "{\"user_options\":{\"connections\":{\"socks_proxy\":{\"host\":\"" + host + "\"}}}}";
            String socksPortJson = "{\"user_options\":{\"connections\":{\"socks_proxy\":{\"port\":" + port + "}}}}";
            String useProxyJson = "{\"user_options\":{\"connections\":{\"socks_proxy\":{\"use_proxy\":" + useProxy + "}}}}";
            String useDnsJson = "{\"user_options\":{\"connections\":{\"socks_proxy\":{\"dns_over_socks\":false}}}}";
            
            // Import settings into Burp
            api.burpSuite().importUserOptionsFromJson(socksHostJson);
            api.burpSuite().importUserOptionsFromJson(socksPortJson);
            api.burpSuite().importUserOptionsFromJson(useProxyJson);
            api.burpSuite().importUserOptionsFromJson(useDnsJson);
            
            logMessage("Burp SOCKS proxy settings updated: " + (useProxy ? "enabled" : "disabled") + 
                      (useProxy ? ", using localhost:" + port : ""));
        } catch (Exception e) {
            logMessage("Error updating Burp SOCKS settings: " + e.getMessage());
        }
    }
    
    /**
     * Finds an available port to use.
     */
    private int findAvailablePort() {
        // Try to use a port in the range 10000-65000 to avoid conflicts
        Random random = new Random();
        for (int i = 0; i < 20; i++) { // Try up to 20 times
            int port = 10000 + random.nextInt(55000);
            try (ServerSocket socket = new ServerSocket(port)) {
                // If we can bind to it, it's available
                return socket.getLocalPort();
            } catch (IOException e) {
                // Port is in use, try another one
            }
        }
        // If we can't find a random port, try the default as a fallback
        return 13560;
    }

    /**
     * Enables the SOCKS rotation service.
     */
    private void enableSocksRotate() {
        // Don't start if service is already running
        if (socksProxyService != null && socksProxyService.isRunning()) {
            logMessage("SOCKS Rotate service is already running");
            return;
        }
        
        if (proxyList.isEmpty()) {
            JOptionPane.showMessageDialog(
                    null,
                    "Please add at least one proxy before enabling the service.",
                    "No Proxies Available",
                    JOptionPane.WARNING_MESSAGE
            );
            logMessage("Cannot start SOCKS Rotate service: No proxies available");
            return;
        }
        
        // Always use a random port if configuredLocalPort is 0, otherwise use the configured port
        int portToUse;
        if (configuredLocalPort <= 0) {
            portToUse = findAvailablePort();
            if (portToUse <= 0) {
                JOptionPane.showMessageDialog(
                        null,
                        "Could not find an available port. Please specify a port manually.",
                        "Port Error",
                        JOptionPane.ERROR_MESSAGE
                );
                return;
            }
        } else {
            portToUse = configuredLocalPort;
        }
        
        final int finalPortToUse = portToUse;
        
        // Configure the service
        socksProxyService.setSettings(
                bufferSize,
                connectionTimeoutSec * 1000, // Convert to milliseconds
                socketTimeoutSec * 1000,     // Convert to milliseconds
                maxRetryCount,
                maxConnectionsPerProxy
        );
        
        // Configure bypass settings
        socksProxyService.setBypassCollaborator(bypassCollaborator);
        socksProxyService.clearBypassDomains();
        String domainsText = bypassDomainsTextArea.getText();
        if (domainsText != null && !domainsText.isEmpty()) {
            String[] domains = domainsText.trim().split("\n");
            for (String domain : domains) {
                domain = domain.trim();
                if (!domain.isEmpty()) {
                    socksProxyService.addBypassDomain(domain);
                }
            }
        }
        
        // Start the service
        socksProxyService.start(finalPortToUse, 
                // Success callback
                () -> {
                    SwingUtilities.invokeLater(() -> {
                        // Update Burp settings
                        updateBurpSocksSettings("127.0.0.1", finalPortToUse, true);
                        
                        // Update UI
                        statusLabel.setText("Status: Running on 127.0.0.1:" + finalPortToUse);
                        enableButton.setEnabled(false);
                        disableButton.setEnabled(true);
                        
                        logMessage("SOCKS Rotate service started on 127.0.0.1:" + finalPortToUse);
                    });
                },
                // Failure callback
                errorMessage -> {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("Status: Failed to start");
                        JOptionPane.showMessageDialog(
                                null,
                                "Failed to start SOCKS Rotate service: " + errorMessage,
                                "Service Error",
                                JOptionPane.ERROR_MESSAGE
                        );
                        logMessage("Failed to start SOCKS Rotate service: " + errorMessage);
                    });
                }
        );
    }
    
    /**
     * Disables the SOCKS rotation service.
     */
    private void disableSocksRotate() {
        if (socksProxyService == null || !socksProxyService.isRunning()) {
            logMessage("SOCKS Rotate service is not running");
            return;
        }
        
        try {
            logMessage("Stopping SOCKS Rotate service...");
            
            // Stop the service
            socksProxyService.stop();
            
            // Update Burp settings
            updateBurpSocksSettings("", 0, false);
            
            // Update UI
            statusLabel.setText("Status: Stopped");
            enableButton.setEnabled(true);
            disableButton.setEnabled(false);
            
            logMessage("SOCKS Rotate service stopped");
            
        } catch (Exception ex) {
            logMessage("Error stopping SOCKS Rotate service: " + ex.getMessage());
            JOptionPane.showMessageDialog(null,
                    "An error occurred while stopping the service: " + ex.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * Updates the server control buttons based on service state.
     */
    private void updateServerButtons() {
        SwingUtilities.invokeLater(() -> {
            if (enableButton != null && disableButton != null) {
                boolean running = socksProxyService != null && socksProxyService.isRunning();
                enableButton.setEnabled(!running);
                disableButton.setEnabled(running);
            }
        });
    }

    /**
     * Performs shutdown operations.
     */
    private void shutdown() {
        logMessage("Extension unloading. Stopping proxy service...");
         
        if (socksProxyService != null) {
            disableSocksRotate();
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
                    return ProxyEntry.createWithProtocol(host, port, protocol);
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
                    return ProxyEntry.createWithProtocol(host, port, "socks5"); // Default to socks5
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
        JPanel settingsPanel = new JPanel(new BorderLayout());
        settingsPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        JPanel controlsPanel = new JPanel(new GridBagLayout());
        controlsPanel.setBorder(BorderFactory.createTitledBorder("Connection Settings"));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        // Buffer Size
        gbc.gridx = 0;
        gbc.gridy = 0;
        controlsPanel.add(new JLabel("Buffer Size (bytes):"), gbc);
        
        bufferSizeSpinner = new JSpinner(new SpinnerNumberModel(bufferSize, 1024, 65536, 1024));
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
        controlsPanel.add(new JLabel("Connection Timeout (sec):"), gbc);
        
        connectionTimeoutSpinner = new JSpinner(new SpinnerNumberModel(connectionTimeoutSec, 1, 300, 1));
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
        controlsPanel.add(new JLabel("Socket Timeout (sec):"), gbc);
        
        socketTimeoutSpinner = new JSpinner(new SpinnerNumberModel(socketTimeoutSec, 10, 3600, 10));
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
        
        maxRetrySpinner = new JSpinner(new SpinnerNumberModel(maxRetryCount, 0, 10, 1));
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
        
        maxConnectionsPerProxySpinner = new JSpinner(new SpinnerNumberModel(maxConnectionsPerProxy, 1, 500, 10));
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
            if (socksProxyService != null) {
                socksProxyService.setLoggingEnabled(loggingEnabled);
            }
        });
        
        gbc.gridx = 1;
        controlsPanel.add(enableLoggingCheckbox, gbc);
        
        // Bypass Collaborator
        gbc.gridx = 0;
        gbc.gridy = 6;
        controlsPanel.add(new JLabel("Bypass Collaborator:"), gbc);
        
        bypassCollaboratorCheckbox = new JCheckBox();
        bypassCollaboratorCheckbox.setSelected(bypassCollaborator);
        bypassCollaboratorCheckbox.addActionListener(_ -> {
            bypassCollaborator = bypassCollaboratorCheckbox.isSelected();
            socksProxyService.setBypassCollaborator(bypassCollaborator);
            saveSettings();
            logMessage("Bypass Collaborator " + (bypassCollaborator ? "enabled" : "disabled"));
        });
        
        gbc.gridx = 1;
        controlsPanel.add(bypassCollaboratorCheckbox, gbc);
        
        // Bypass Domains section
        JPanel bypassPanel = new JPanel(new BorderLayout());
        bypassPanel.setBorder(BorderFactory.createTitledBorder("Bypass Domains (one per line)"));
        
        bypassDomainsTextArea = new JTextArea(5, 30);
        bypassDomainsTextArea.setToolTipText("Enter one domain per line");
        JScrollPane bypassScrollPane = new JScrollPane(bypassDomainsTextArea);
        
        JButton updateDomainsButton = new JButton("Update Domains");
        updateDomainsButton.addActionListener(_ -> {
            String domains = bypassDomainsTextArea.getText();
            updateBypassDomains(domains);
            logMessage("Bypass domains updated");
        });
        
        bypassPanel.add(bypassScrollPane, BorderLayout.CENTER);
        bypassPanel.add(updateDomainsButton, BorderLayout.SOUTH);
        
        // Load saved domains
        loadBypassDomains();
        
        // Reset Default Settings Button
        gbc.gridx = 0;
        gbc.gridy = 8;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        
        JButton resetButton = new JButton("Reset to Default Settings");
        resetButton.addActionListener(_ -> resetDefaultSettings());
        
        controlsPanel.add(resetButton, gbc);
        
        // Add all panels to the settings panel
        settingsPanel.add(controlsPanel, BorderLayout.NORTH);
        settingsPanel.add(bypassPanel, BorderLayout.CENTER);
        
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
        bypassCollaborator = true; // Default to bypass Collaborator
        
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
            "Logging setting was preserved: " + (loggingEnabled ? "Enabled" : "Disabled") + "\n" +
            "Bypass Collaborator setting was preserved: " + (bypassCollaborator ? "Enabled" : "Disabled"),
            "Settings Reset", 
            JOptionPane.INFORMATION_MESSAGE));
    }
}