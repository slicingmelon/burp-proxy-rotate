/**
 * Burp Proxy Rotate
 * Author: slicingmelon 
 * https://github.com/slicingmelon
 * https://x.com/pedro_infosec
 * 
 * This burp extension routes each HTTP request through a different proxy from a provided list.
 */
package slicingmelon.burpproxyrotate;

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
 * Main Burp Extension class
 */
public class BurpProxyRotate implements BurpExtension {
    
    // Core components
    private MontoyaApi api;
    private List<ProxyEntry> proxyList;
    private final ReadWriteLock proxyListLock = new ReentrantReadWriteLock();
    private ProxyRotateService socksProxyService;
    
    // UI components
    private ProxyTableModel proxyTableModel;
    private JTextArea logTextArea;
    private JButton enableButton;
    private JButton disableButton;
    private JLabel statusLabel;
    
    // Validate proxies
    private static final String PROXY_URL_REGEX = "^(socks[45]|http)://(?:([^:@]+):([^@]+)@)?([^:]+):(\\d+)$";
    private static final String PROXY_HOST_PORT_REGEX = "^([^:]+):(\\d+)$";
    
    // Used to allocate a random port available
    private int configuredLocalPort = 0;
    
    // Settings with defaults
    private int bufferSize = DEFAULT_BUFFER_SIZE;
    private int idleTimeoutSec = DEFAULT_IDLE_TIMEOUT;
    private int maxConnectionsPerProxy = DEFAULT_MAX_CONNECTIONS_PER_PROXY;
    private boolean loggingEnabled = DEFAULT_LOGGING_ENABLED;
    private boolean bypassCollaborator = DEFAULT_BYPASS_COLLABORATOR;
    private boolean useRandomProxySelection = DEFAULT_RANDOM_PROXY_SELECTION;
    
    // UI components for settings
    private JSpinner bufferSizeSpinner;
    private JSpinner idleTimeoutSpinner;
    private JSpinner maxConnectionsPerProxySpinner;
    private JCheckBox enableLoggingCheckbox;
    private JCheckBox bypassCollaboratorCheckbox;
    private JComboBox<String> proxySelectionModeComboBox;
    private JTextArea bypassDomainsTextArea;
    
    // Persistence keys
    private static final String PROXY_LIST_KEY = "proxyList";
    private static final String PORT_KEY = "localPort";
    private static final String BUFFER_SIZE_KEY = "bufferSize";
    private static final String IDLE_TIMEOUT_KEY = "idleTimeout";
    private static final String MAX_CONNECTIONS_PER_PROXY_KEY = "maxConnectionsPerProxy";
    private static final String LOGGING_ENABLED_KEY = "loggingEnabled";
    private static final String BYPASS_COLLABORATOR_KEY = "bypassCollaborator";
    private static final String BYPASS_DOMAINS_KEY = "bypassDomains";
    private static final String PROXY_SELECTION_MODE_KEY = "proxySelectionMode";
    
    private javax.swing.Timer statsUpdateTimer;
    private javax.swing.Timer uiUpdateTimer;
    private JLabel statsLabel;
    private volatile boolean uiUpdatePending = false;

    // default constants for ALL settings
    private static final int DEFAULT_BUFFER_SIZE = 8092;
    private static final int DEFAULT_IDLE_TIMEOUT = 60;
    private static final int DEFAULT_MAX_CONNECTIONS_PER_PROXY = 50;
    private static final boolean DEFAULT_LOGGING_ENABLED = false;
    private static final boolean DEFAULT_BYPASS_COLLABORATOR = true;
    private static final boolean DEFAULT_RANDOM_PROXY_SELECTION = true;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Burp Proxy Rotate");
        
        proxyList = new ArrayList<>();
        
        // Reset/disable Burp's SOCKS proxy settings on startup to ensure clean state
        resetBurpSocksSettings();
        
        loadSavedProxies();
        
        socksProxyService = new ProxyRotateService(proxyList, proxyListLock, api.logging());
        socksProxyService.setExtension(this);
        
        socksProxyService.setBypassCollaborator(bypassCollaborator);
        
        socksProxyService.setLoggingEnabled(loggingEnabled);

        // Create and register the UI
        SwingUtilities.invokeLater(() -> {
            JComponent panel = createUserInterface();
            api.userInterface().registerSuiteTab("Proxy Rotate", panel);
            updateServerButtons();
        });
        
        api.extension().registerUnloadingHandler(this::shutdown);
        
        logMessage("Burp Proxy Rotate extension loaded successfully");
    }
    
    /**
     * Loads saved proxies and settings (from persistence)
     */
    private void loadSavedProxies() {
        String savedProxies = api.persistence().preferences().getString(PROXY_LIST_KEY);
        if (savedProxies != null && !savedProxies.isEmpty()) {
            String[] proxies = savedProxies.split("\n");
            for (String proxy : proxies) {
                try {
                    // Pattern match: protocol://[username:password@]host:port
                    if (proxy.contains("://")) {
                        // Parse URL-style proxy specification
                        String protocol, username = null, password = null, host;
                        int port;
                        
                        // Extract protocol
                        String[] protocolSplit = proxy.split("://", 2);
                        protocol = protocolSplit[0]; // http, socks4, or socks5
                        String remaining = protocolSplit[1]; // [username:password@]host:port
                        
                        // Check for authentication
                        if (remaining.contains("@")) {
                            // Format: username:password@host:port
                            String[] authSplit = remaining.split("@", 2);
                            String[] credentials = authSplit[0].split(":", 2);
                            username = credentials[0];
                            password = credentials[1];
                            remaining = authSplit[1]; // host:port
                        }
                        
                        // Extract host and port
                        String[] hostPort = remaining.split(":", 2);
                        host = hostPort[0];
                        port = Integer.parseInt(hostPort[1].trim());
                        
                        if (!host.isEmpty() && port > 0 && port <= 65535) {
                            ProxyEntry entry;
                            if (username != null && password != null) {
                                // Create authenticated proxy
                                entry = ProxyEntry.createWithAuth(host, port, protocol, username, password);
                            } else {
                                // Create non-authenticated proxy
                                entry = ProxyEntry.createWithProtocol(host, port, protocol);
                            }
                            
                            proxyListLock.writeLock().lock();
                            try {
                                proxyList.add(entry);
                            } finally {
                                proxyListLock.writeLock().unlock();
                            }
                            
                            logMessage("Loaded proxy: " + protocol + "://" + 
                                      (username != null ? "[authenticated]@" : "") + 
                                      host + ":" + port);
                        }
                    } else {
                        // Legacy format: host:port (assumes socks5)
                        String[] parts = proxy.split(":");
                        if (parts.length >= 2) {
                            String host = parts[0].trim();
                            int port = Integer.parseInt(parts[1].trim());
                            
                            if (!host.isEmpty() && port > 0 && port <= 65535) {
                                proxyListLock.writeLock().lock();
                                try {
                                    proxyList.add(ProxyEntry.createWithProtocol(host, port, "socks5"));
                                } finally {
                                    proxyListLock.writeLock().unlock();
                                }
                                
                                logMessage("Loaded legacy proxy: socks5://" + host + ":" + port);
                            }
                        }
                    }
                } catch (Exception e) {
                    logMessage("Skipped invalid proxy entry: " + proxy + " (" + e.getMessage() + ")");
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
        
        String idleTimeoutSetting = api.persistence().preferences().getString(IDLE_TIMEOUT_KEY);
        if (idleTimeoutSetting != null) {
            try {
                idleTimeoutSec = Integer.parseInt(idleTimeoutSetting);
            } catch (NumberFormatException e) {
                // default
            }
        }
        
        String maxConnectionsPerProxySetting = api.persistence().preferences().getString(MAX_CONNECTIONS_PER_PROXY_KEY);
        if (maxConnectionsPerProxySetting != null) {
            try {
                maxConnectionsPerProxy = Integer.parseInt(maxConnectionsPerProxySetting);
            } catch (NumberFormatException e) {
                // default
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
        
        String proxySelectionModeSetting = api.persistence().preferences().getString(PROXY_SELECTION_MODE_KEY);
        if (proxySelectionModeSetting != null) {
            useRandomProxySelection = Boolean.parseBoolean(proxySelectionModeSetting);
        }
    }
    
    /**
     * Load the bypass domains from persistence and update the UI
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
     * Update the bypass domains in the proxy service
     */
    private void updateBypassDomains(String domainsText) {
        if (socksProxyService != null) {
            socksProxyService.setBypassCollaborator(bypassCollaborator);
            
            String[] domains = domainsText.trim().split("\n");
            for (String domain : domains) {
                domain = domain.trim();
                if (!domain.isEmpty()) {
                    socksProxyService.addBypassDomain(domain);
                }
            }
        }

        api.persistence().preferences().setString(BYPASS_DOMAINS_KEY, domainsText);
    }
    
    /**
     * Save proxies and settings
     */
    private void saveProxies() {
        api.persistence().preferences().setString(PROXY_LIST_KEY, proxyListToString());
        api.persistence().preferences().setString(PORT_KEY, String.valueOf(configuredLocalPort));
    }
    
    /**
     * Convert the proxy list to a string for storage
     */
    private String proxyListToString() {
        StringBuilder sb = new StringBuilder();
        proxyListLock.readLock().lock();
        try {
            for (ProxyEntry entry : proxyList) {
                // proto and auth
                sb.append(entry.getProtocol()).append("://");
                
                // auth
                if (entry.isAuthenticated()) {
                    sb.append(entry.getUsername()).append(":")
                      .append(entry.getPassword()).append("@");
                }
                
                // host:port
                sb.append(entry.getHost()).append(":")
                  .append(entry.getPort()).append("\n");
            }
        } finally {
            proxyListLock.readLock().unlock();
        }
        
        return sb.toString();
    }
    
    private void saveSettings() {
        api.persistence().preferences().setString(PROXY_LIST_KEY, proxyListToString());
        api.persistence().preferences().setString(PORT_KEY, String.valueOf(configuredLocalPort));
        api.persistence().preferences().setString(BUFFER_SIZE_KEY, String.valueOf(bufferSize));
        api.persistence().preferences().setString(IDLE_TIMEOUT_KEY, String.valueOf(idleTimeoutSec));
        api.persistence().preferences().setString(MAX_CONNECTIONS_PER_PROXY_KEY, String.valueOf(maxConnectionsPerProxy));
        api.persistence().preferences().setString(LOGGING_ENABLED_KEY, String.valueOf(loggingEnabled));
        api.persistence().preferences().setString(BYPASS_COLLABORATOR_KEY, String.valueOf(bypassCollaborator));
        api.persistence().preferences().setString(PROXY_SELECTION_MODE_KEY, String.valueOf(useRandomProxySelection));
    }
    
    /**
     * UI components
     */
    private JComponent createUserInterface() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        JPanel controlPanel = new JPanel(new GridBagLayout());
        
        JPanel proxyPanel = new JPanel(new BorderLayout());
        proxyPanel.setBorder(BorderFactory.createTitledBorder("SOCKS Proxies"));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        controlPanel.add(new JLabel("Local port:"), gbc);
        
        JCheckBox randomPortCheckbox = new JCheckBox("Random Port", true);
        JSpinner portSpinner = new JSpinner(new SpinnerNumberModel(
                configuredLocalPort > 0 ? configuredLocalPort : 13920, 
                1024, 65535, 1));
        portSpinner.setEnabled(!randomPortCheckbox.isSelected());
        
        randomPortCheckbox.addActionListener(_ -> {
            boolean random = randomPortCheckbox.isSelected();
            portSpinner.setEnabled(!random);
            if (random) {
                configuredLocalPort = 0;
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
        
        JPanel portPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        portPanel.add(randomPortCheckbox);
        portPanel.add(portSpinner);
        
        gbc.gridx = 1;
        gbc.gridy = 0;
        controlPanel.add(portPanel, gbc);
        
        if (configuredLocalPort > 0) {
            randomPortCheckbox.setSelected(false);
            portSpinner.setEnabled(true);
        } else {
            randomPortCheckbox.setSelected(true);
            portSpinner.setEnabled(false);
        }
        
        statusLabel = new JLabel("Status: Stopped");
        gbc.gridx = 2;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        controlPanel.add(statusLabel, gbc);
        
        statsLabel = new JLabel("No active connections");
        gbc.gridx = 2;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        controlPanel.add(statsLabel, gbc);
        
        enableButton = new JButton("Enable Proxy Rotate");
        enableButton.addActionListener(_ -> enableProxyRotate());
        
        disableButton = new JButton("Disable Proxy Rotate");
        disableButton.addActionListener(_ -> disableProxyRotate());
        disableButton.setEnabled(false);
        
        JPanel controlButtonPanel = new JPanel(new GridLayout(1, 2, 10, 0));
        controlButtonPanel.add(enableButton);
        controlButtonPanel.add(disableButton);
        
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        controlPanel.add(controlButtonPanel, gbc);
        
        proxyTableModel = new ProxyTableModel();
        JTable proxyTable = new JTable(proxyTableModel);
        proxyTable.setFillsViewportHeight(true);
        proxyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        setupTableRenderer(proxyTable);
        
        JScrollPane scrollPane = new JScrollPane(proxyTable);
        scrollPane.setPreferredSize(new Dimension(600, 200));
        
        JTabbedPane proxyAddTabs = new JTabbedPane();
        
        JPanel singleAddPanel = new JPanel(new BorderLayout());
        
        JPanel unifiedInputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel unifiedLabel = new JLabel("Proxy URL:");
        JTextField unifiedField = new JTextField(25);
        unifiedField.setToolTipText("Format: socks5://host:port or socks4://host:port");
        
        unifiedField.setText("socks5://host:port");
        unifiedField.setForeground(Color.GRAY);
        unifiedField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (unifiedField.getText().equals("socks5://host:port")) {
                    unifiedField.setText("");
                    unifiedField.setForeground(Color.WHITE);
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
            
            new Thread(() -> {
                validateProxy(proxy, 3);
                updateProxyTable();
            }).start();
            
            unifiedField.setText("");
            unifiedField.setText("socks5://host:port");
            unifiedField.setForeground(Color.GRAY);
        });
        
        singleAddPanel.add(unifiedInputPanel, BorderLayout.CENTER);
        
        JPanel bulkPanel = new JPanel(new BorderLayout(5, 5));
        JTextArea bulkTextArea = new JTextArea(5, 30);
        bulkTextArea.setToolTipText("Enter one proxy per line in format socks5://host:port or socks4://host:port");
        
        bulkTextArea.setText("# Enter one proxy per line\n# Examples:\n# socks5://192.168.1.1:1080\n# socks4://user:pass@host:1080");
        bulkTextArea.setForeground(Color.GRAY);
        bulkTextArea.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (bulkTextArea.getText().startsWith("# Enter")) {
                    bulkTextArea.setText("");
                    bulkTextArea.setForeground(Color.WHITE);
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
        
        proxyAddTabs.addTab("Single Proxy", singleAddPanel);
        proxyAddTabs.addTab("Bulk Add", bulkPanel);
        
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
        
        JPanel proxyTablePanel = new JPanel(new BorderLayout());
        proxyTablePanel.add(scrollPane, BorderLayout.CENTER);
        proxyTablePanel.add(buttonPanel, BorderLayout.SOUTH);
        
        JSplitPane proxySplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, 
                                                 proxyTablePanel, proxyAddPanel);
        proxySplitPane.setResizeWeight(0.7); 
        
        proxyPanel.add(proxySplitPane, BorderLayout.CENTER);
        
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Log"));
        
        logTextArea = new JTextArea();
        logTextArea.setEditable(false);
        logTextArea.setLineWrap(true);
        logTextArea.setWrapStyleWord(true);
        
        JScrollPane logScrollPane = new JScrollPane(logTextArea);
        logScrollPane.setPreferredSize(new Dimension(600, 150));
        
        logPanel.add(logScrollPane, BorderLayout.CENTER);
        
        JPanel settingsPanel = createSettingsPanel();
        
        JTabbedPane tabbedPane = new JTabbedPane();
        
        JPanel mainTab = new JPanel(new BorderLayout());
        mainTab.add(controlPanel, BorderLayout.NORTH);
        mainTab.add(proxyPanel, BorderLayout.CENTER);
        mainTab.add(logPanel, BorderLayout.SOUTH);
        
        tabbedPane.addTab("Main", mainTab);
        tabbedPane.addTab("Settings", settingsPanel);
        
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        
        statsUpdateTimer = new javax.swing.Timer(1000, _ -> {
            if (socksProxyService != null && socksProxyService.isRunning()) {
                statsLabel.setText(socksProxyService.getConnectionPoolStats());
            } else {
                statsLabel.setText("No active connections");
            }
        });
        statsUpdateTimer.start();
        
        // Batch UI updates every 500ms for better performance
        uiUpdateTimer = new javax.swing.Timer(500, _ -> {
            if (uiUpdatePending) {
                proxyTableModel.fireTableDataChanged();
                updateServerButtons();
                uiUpdatePending = false;
            }
        });
        uiUpdateTimer.start();
        
        updateProxyTable();
        
        return mainPanel;
    }
    
    /**
     * Update Burp Suite's SOCKS proxy settings to use our local proxy service
     * just a hack :P
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
     * Reset/disable Burp Suite's SOCKS proxy settings to ensure clean state
     */
    private void resetBurpSocksSettings() {
        try {
            // Disable SOCKS proxy and reset to default values
            String disableProxyJson = "{\"user_options\":{\"connections\":{\"socks_proxy\":{\"use_proxy\":false}}}}";
            String resetHostJson = "{\"user_options\":{\"connections\":{\"socks_proxy\":{\"host\":\"\"}}}}";
            String resetPortJson = "{\"user_options\":{\"connections\":{\"socks_proxy\":{\"port\":0}}}}";
            String resetDnsJson = "{\"user_options\":{\"connections\":{\"socks_proxy\":{\"dns_over_socks\":false}}}}";
            
            // Import settings into Burp
            api.burpSuite().importUserOptionsFromJson(disableProxyJson);
            api.burpSuite().importUserOptionsFromJson(resetHostJson);
            api.burpSuite().importUserOptionsFromJson(resetPortJson);
            api.burpSuite().importUserOptionsFromJson(resetDnsJson);
            
            logMessage("Burp SOCKS proxy settings reset to default (disabled)");
        } catch (Exception e) {
            logMessage("Error resetting Burp SOCKS settings: " + e.getMessage());
        }
    }
    
    /**
     * Helper function to find an available port to use
     */
    private int findAvailablePort() {
        Random random = new Random();
        for (int i = 0; i < 20; i++) {
            int port = 10000 + random.nextInt(55000);
            try (ServerSocket socket = new ServerSocket(port)) {
                return socket.getLocalPort();
            } catch (IOException e) {
                // Port is in use, try another one
            }
        }
        // If we can't find a random port, try the default as a fallback
        return 13560;
    }

    /**
     * Enables the Burp Proxy Rotate extension
     */
    private void enableProxyRotate() {
        if (socksProxyService != null && socksProxyService.isRunning()) {
            logMessage("Burp Proxy Rotate service is already running");
            return;
        }
        
        if (proxyList.isEmpty()) {
            JOptionPane.showMessageDialog(
                    null,
                    "Please add at least one proxy before enabling the extension.",
                    "No Proxies Available",
                    JOptionPane.WARNING_MESSAGE
            );
            logMessage("Cannot start Burp Proxy Rotate extension: No proxies available");
            return;
        }

        // First validate all proxies, then start the service (extension)
        validateAllProxies(() -> {
            // Check if we have at least one active proxy after validation
            boolean hasActiveProxy = false;
            proxyListLock.readLock().lock();
            try {
                for (ProxyEntry proxy : proxyList) {
                    if (proxy.isActive()) {
                        hasActiveProxy = true;
                        break;
                    }
                }
            } finally {
                proxyListLock.readLock().unlock();
            }
            
            if (!hasActiveProxy) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(
                            null,
                            "No active proxies available. Please add valid proxies before enabling the service.",
                            "No Active Proxies",
                            JOptionPane.WARNING_MESSAGE
                    );
                    logMessage("Cannot start Burp Proxy Rotate service: No active proxies available");
                });
                return;
            }
            
            startProxyRotateService();
        });
    }
    
    /**
     * Starts the proxy rotate service after validation
     */
    private void startProxyRotateService() {
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
        
        socksProxyService.setSettings(
                bufferSize,
                idleTimeoutSec,
                maxConnectionsPerProxy
        );
        
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
        
        socksProxyService.setUseRandomProxySelection(useRandomProxySelection);
        
        // Start the internal proxy service
        socksProxyService.start(finalPortToUse, 
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
     * Disable the extension
     */
    private void disableProxyRotate() {
        try {
            logMessage("Stopping Burp Proxy Rotate service...");
            
            if (socksProxyService != null && socksProxyService.isRunning()) {
                socksProxyService.stop();
                logMessage("SOCKS Rotate service stopped");
            } else {
                logMessage("Burp Proxy Rotate service was not running");
            }
            
            // Always reset Burp's SOCKS proxy settings, regardless of service state
            resetBurpSocksSettings();
            
            // Update UI if available
            if (statusLabel != null) {
                statusLabel.setText("Status: Stopped");
            }
            if (enableButton != null) {
                enableButton.setEnabled(true);
            }
            if (disableButton != null) {
                disableButton.setEnabled(false);
            }
            
        } catch (Exception ex) {
            logMessage("Error stopping SOCKS Rotate service: " + ex.getMessage());
            
            // Still try to reset the SOCKS proxy settings even if there was an error
            try {
                resetBurpSocksSettings();
            } catch (Exception resetEx) {
                logMessage("Error resetting SOCKS proxy settings: " + resetEx.getMessage());
            }
            
            if (enableButton != null && disableButton != null) {
                JOptionPane.showMessageDialog(null,
                        "An error occurred while stopping the service: " + ex.getMessage(),
                        "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    /**
     * Update the server control buttons based on service state
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
     * Shut down
     */
    private void shutdown() {
        logMessage("Extension unloading. Stopping proxy service...");
         
        if (socksProxyService != null) {
            disableProxyRotate();
        }
        
        // Reset Burp's SOCKS proxy settings to ensure clean state
        resetBurpSocksSettings();
        
        saveProxies();
        logMessage("Burp SOCKS Rotate extension shut down.");

        if (statsUpdateTimer != null && statsUpdateTimer.isRunning()) {
            statsUpdateTimer.stop();
        }
        
        if (uiUpdateTimer != null && uiUpdateTimer.isRunning()) {
            uiUpdateTimer.stop();
        }
    }
    
    /**
     * Add a proxy to the list
     */
    private void addProxy(ProxyEntry proxy) {
        boolean added = false;
        proxyListLock.writeLock().lock();
        try {
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
     * Remove a proxy from the list
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
     * Clear all proxies
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
     * Update the proxy table (batched for performance)
     */
    private void updateProxyTable() {
        if (proxyTableModel != null) {
            uiUpdatePending = true; // Will be processed by uiUpdateTimer
        }
    }
    
    /**
     * Log a message to both the UI and Burp's output
     */
    private void logMessage(String message) {
        if (api != null && api.logging() != null && loggingEnabled) {
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
     * Proxies Table
     */
    private class ProxyTableModel extends AbstractTableModel {
        private final String[] columnNames = {"Protocol", "Host", "Port", "Auth", "Status"};
        
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
                    case 3: return entry.isAuthenticated() ? "Yes" : "No";
                    case 4:
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
     * Table renderer
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
                
                if (entry != null && column == 3 && "Yes".equals(value)) {
                    Font boldFont = c.getFont().deriveFont(Font.BOLD);
                    c.setFont(boldFont);
                } else {
                    Font regularFont = c.getFont().deriveFont(Font.PLAIN);
                    c.setFont(regularFont);
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
     * Validate all proxies in the list
     */
    private void validateAllProxies() {
        validateAllProxies(null);
    }

    /**
     * Validate all proxies in the list with an optional callback when complete
     * @param callback Optional callback to execute after validation is complete
     */
    private void validateAllProxies(Runnable callback) {
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
            
            // If this was triggered from the validate button (not from enableProxyRotate)
            if (callback == null) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(null, 
                        "Validation complete. " + finalActiveCount + " of " + total + " proxies are active.",
                        "Validation Results", 
                        JOptionPane.INFORMATION_MESSAGE);
                });
            } else {
                // Execute the callback function
                callback.run();
            }
        }).start();
    }
    
    /**
     * Validate a single proxy
     */
    private boolean validateProxy(ProxyEntry proxy, int maxAttempts) {
        logMessage("Validating proxy: " + proxy.getProtocol() + "://" + 
                  (proxy.isAuthenticated() ? proxy.getUsername() + ":***@" : "") + 
                  proxy.getHost() + ":" + proxy.getPort());
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
                
                if (proxy.isHttp()) {
                    // HTTP proxy validation - send a simple CONNECT request to a test server
                    String testHost = "www.google.com";
                    int testPort = 443;
                    
                    StringBuilder request = new StringBuilder();
                    request.append("CONNECT ").append(testHost).append(":").append(testPort).append(" HTTP/1.1\r\n");
                    request.append("Host: ").append(testHost).append(":").append(testPort).append("\r\n");
                    
                    // Add authentication if needed
                    if (proxy.isAuthenticated()) {
                        String auth = proxy.getUsername() + ":" + proxy.getPassword();
                        String encodedAuth = java.util.Base64.getEncoder().encodeToString(auth.getBytes());
                        request.append("Proxy-Authorization: Basic ").append(encodedAuth).append("\r\n");
                    }
                    
                    request.append("Connection: keep-alive\r\n\r\n");
                    
                    // Send the request
                    out.write(request.toString().getBytes());
                    out.flush();
                    
                    // Read the response
                    byte[] buffer = new byte[1024];
                    int bytesRead = in.read(buffer);
                    if (bytesRead > 0) {
                        String response = new String(buffer, 0, bytesRead);
                        if (response.contains("200") || response.contains("HTTP/1.1 200")) {
                            // Success - 200 response
                            logMessage("HTTP proxy validated successfully: " + proxy.getHost() + ":" + proxy.getPort());
                            success = true;
                            finalErrorMessage = "";
                            break;
                        } else if (response.contains("407")) {
                            // Authentication required but not provided, or invalid
                            finalErrorMessage = "Authentication required or invalid";
                            logMessage("HTTP proxy requires authentication: " + proxy.getHost() + ":" + proxy.getPort());
                            if (!proxy.isAuthenticated()) {
                                break;
                            }
                        } else {
                            // Other error
                            finalErrorMessage = "HTTP proxy error: " + response.split("\r\n")[0];
                            logMessage("HTTP proxy validation failed: " + proxy.getHost() + ":" + proxy.getPort() + 
                                     " - " + finalErrorMessage);
                            break;
                        }
                    }
                } 
                // Check SOCKS proxy
                else {
                    // Send greeting based on protocol
                    int protocolVersion = proxy.getProtocolVersion();
                    
                    if (protocolVersion == 5) {
                        // SOCKS5 greeting (Auth or No Auth)
                        if (proxy.isAuthenticated()) {
                            // Auth methods: no auth (0x00) and username/password (0x02)
                            out.write(new byte[]{0x05, 0x02, 0x00, 0x02});
                        } else {
                            // No Auth only
                            out.write(new byte[]{0x05, 0x01, 0x00});
                        }
                        out.flush();
                        
                        byte[] response = new byte[2];
                        int bytesRead = in.read(response);
                        
                        if (bytesRead == 2 && response[0] == 0x05) {
                            // Successful handshake
                            if (response[1] == 0x00) {
                                // No auth required
                                logMessage("SOCKS5 proxy validated successfully (no auth): " + proxy.getHost() + ":" + proxy.getPort());
                                success = true;
                                finalErrorMessage = "";
                                break;
                            } else if (response[1] == 0x02 && proxy.isAuthenticated()) {
                                // Username/password auth required - send credentials
                                byte[] usernameBytes = proxy.getUsername().getBytes();
                                byte[] passwordBytes = proxy.getPassword().getBytes();
                                
                                // Auth request: version 1, username len, username, password len, password
                                byte[] authRequest = new byte[3 + usernameBytes.length + passwordBytes.length];
                                authRequest[0] = 0x01; // Auth version
                                authRequest[1] = (byte) usernameBytes.length;
                                System.arraycopy(usernameBytes, 0, authRequest, 2, usernameBytes.length);
                                authRequest[2 + usernameBytes.length] = (byte) passwordBytes.length;
                                System.arraycopy(passwordBytes, 0, authRequest, 3 + usernameBytes.length, passwordBytes.length);
                                
                                out.write(authRequest);
                                out.flush();
                                
                                // Read auth response
                                byte[] authResponse = new byte[2];
                                bytesRead = in.read(authResponse);
                                
                                if (bytesRead == 2 && authResponse[0] == 0x01 && authResponse[1] == 0x00) {
                                    // Auth successful
                                    logMessage("SOCKS5 proxy validated successfully (with auth): " + proxy.getHost() + ":" + proxy.getPort());
                                    success = true;
                                    finalErrorMessage = "";
                                    break;
                                } else {
                                    finalErrorMessage = "Authentication failed";
                                    logMessage("SOCKS5 authentication failed: " + proxy.getHost() + ":" + proxy.getPort());
                                    break;
                                }
                            } else if (response[1] == 0x02 && !proxy.isAuthenticated()) {
                                finalErrorMessage = "Proxy requires authentication";
                                logMessage("SOCKS5 proxy requires authentication: " + proxy.getHost() + ":" + proxy.getPort());
                                break;
                            } else {
                                finalErrorMessage = "Unsupported authentication method: " + response[1];
                                logMessage("SOCKS5 proxy returned unsupported auth method: " + response[1]);
                                break;
                            }
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
                        
                        // verify we get a SOCKS4 response
                        if (bytesRead == 8 && response[0] == 0x00) {
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
                }
            } catch (IOException e) {
                finalErrorMessage = e.getMessage();
                if (finalErrorMessage == null || finalErrorMessage.isEmpty()) {
                    finalErrorMessage = e.getClass().getSimpleName();
                }
                logMessage("Attempt " + attempt + "/" + maxAttempts + " failed: " + finalErrorMessage);
            } finally {
                if (socket != null) {
                    try { socket.close(); } catch (IOException e) { /* pass */ }
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
     * Parse a proxy URL string into a ProxyEntry object
     * Formats
     * - socks5://host:port
     * - socks4://host:port
     * - http://host:port
     * - socks5://username:password@host:port  
     * - http://username:password@host:port
     * - host:port (defaults to socks5) - might remove this
     * 
     * @param proxyUrl the proxy URL string
     * @return a ProxyEntry object or null if the format is invalid
     */
    private ProxyEntry parseProxyUrl(String proxyUrl) {
        if (proxyUrl == null || proxyUrl.trim().isEmpty()) {
            return null;
        }
        
        // Check if the URL has protocol specification
        if (proxyUrl.startsWith("socks") || proxyUrl.startsWith("http")) {
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(PROXY_URL_REGEX);
            java.util.regex.Matcher matcher = pattern.matcher(proxyUrl);
            
            if (matcher.matches()) {
                String protocol = matcher.group(1);
                String username = matcher.group(2); // May be null if no auth
                String password = matcher.group(3); // May be null if no auth
                String host = matcher.group(4);
                int port = Integer.parseInt(matcher.group(5));
                
                // Validate port range
                if (port > 0 && port <= 65535) {
                    if (username != null && password != null) {
                        return ProxyEntry.createWithAuth(host, port, protocol, username, password);
                    } else {
                        return ProxyEntry.createWithProtocol(host, port, protocol);
                    }
                }
            }
        } else {
            // original format host:port .. might remove this
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(PROXY_HOST_PORT_REGEX);
            java.util.regex.Matcher matcher = pattern.matcher(proxyUrl);
            
            if (matcher.matches()) {
                String host = matcher.group(1);
                int port = Integer.parseInt(matcher.group(2));
                
                // Validate port
                if (port > 0 && port <= 65535) {
                    return ProxyEntry.createWithProtocol(host, port, "socks5");
                }
            }
        }
        
        return null;
    }

    /**
     * Notify that a proxy has failed
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
     * Notify that a proxy has been reactivated (it's active again)
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
     * Settings panel
     */
    private JPanel createSettingsPanel() {
        JPanel settingsPanel = new JPanel(new BorderLayout());
        settingsPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        JPanel controlsPanel = new JPanel(new GridBagLayout());
        controlsPanel.setBorder(BorderFactory.createTitledBorder("Connection Settings"));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
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

        gbc.gridx = 0;
        gbc.gridy = 1;
        controlsPanel.add(new JLabel("Idle Timeout (sec):"), gbc);
        
        idleTimeoutSpinner = new JSpinner(new SpinnerNumberModel(idleTimeoutSec, 10, 600, 10));
        idleTimeoutSpinner.addChangeListener(_ -> {
            idleTimeoutSec = (Integer) idleTimeoutSpinner.getValue();
            saveSettings();
            logMessage("Idle timeout updated to " + idleTimeoutSec + " seconds");
        });
        
        gbc.gridx = 1;
        controlsPanel.add(idleTimeoutSpinner, gbc);
        
        gbc.gridx = 0;
        gbc.gridy = 2;
        controlsPanel.add(new JLabel("Max Connections Per Proxy:"), gbc);
        
        maxConnectionsPerProxySpinner = new JSpinner(new SpinnerNumberModel(maxConnectionsPerProxy, 1, 500, 10));
        maxConnectionsPerProxySpinner.addChangeListener(_ -> {
            maxConnectionsPerProxy = (Integer) maxConnectionsPerProxySpinner.getValue();
            saveSettings();
            logMessage("Max connections per proxy updated to " + maxConnectionsPerProxy);
        });
        
        gbc.gridx = 1;
        controlsPanel.add(maxConnectionsPerProxySpinner, gbc);
        
        gbc.gridx = 0;
        gbc.gridy = 3;
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
        
        gbc.gridx = 0;
        gbc.gridy = 4;
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
        
        gbc.gridx = 0;
        gbc.gridy = 5;
        controlsPanel.add(new JLabel("Proxy Selection Mode:"), gbc);
        
        proxySelectionModeComboBox = new JComboBox<>(new String[]{"Round-Robin", "Random"});
        proxySelectionModeComboBox.setSelectedItem(useRandomProxySelection ? "Random" : "Round-Robin");
        proxySelectionModeComboBox.addActionListener(_ -> {
            useRandomProxySelection = proxySelectionModeComboBox.getSelectedItem().equals("Random");
            saveSettings();
            logMessage("Proxy selection mode updated to " + (useRandomProxySelection ? "Random" : "Round-Robin"));
        });
        
        gbc.gridx = 1;
        controlsPanel.add(proxySelectionModeComboBox, gbc);
        
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
        
        loadBypassDomains();
        
        gbc.gridx = 0;
        gbc.gridy = 6;
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
     * Reset to default settings
     */
    private void resetDefaultSettings() {
        bufferSize = DEFAULT_BUFFER_SIZE;
        idleTimeoutSec = DEFAULT_IDLE_TIMEOUT;
        maxConnectionsPerProxy = DEFAULT_MAX_CONNECTIONS_PER_PROXY;
        loggingEnabled = DEFAULT_LOGGING_ENABLED;
        bypassCollaborator = DEFAULT_BYPASS_COLLABORATOR;
        useRandomProxySelection = DEFAULT_RANDOM_PROXY_SELECTION;
        
        bufferSizeSpinner.setValue(bufferSize);
        idleTimeoutSpinner.setValue(idleTimeoutSec);
        maxConnectionsPerProxySpinner.setValue(maxConnectionsPerProxy);
        enableLoggingCheckbox.setSelected(loggingEnabled);
        bypassCollaboratorCheckbox.setSelected(bypassCollaborator);
        proxySelectionModeComboBox.setSelectedItem(useRandomProxySelection ? "Random" : "Round-Robin");
        
        if (socksProxyService != null) {
            socksProxyService.resetToDefaults();
        }
        
        saveSettings();
        
        logMessage("All settings reset to defaults");
        
        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, 
            "Settings have been reset to default values:\n\n" +
            "• Buffer Size: " + bufferSize + " bytes\n" +
            "• Idle Timeout: " + idleTimeoutSec + " seconds\n" +
            "• Max Connections Per Proxy: " + maxConnectionsPerProxy + "\n" +
            "• Logging: " + (loggingEnabled ? "Enabled" : "Disabled") + "\n" +
            "• Bypass Collaborator: " + (bypassCollaborator ? "Enabled" : "Disabled") + "\n" +
            "• Proxy Selection: " + (useRandomProxySelection ? "Random" : "Round-Robin"),
            "Settings Reset", 
            JOptionPane.INFORMATION_MESSAGE));
    }
}