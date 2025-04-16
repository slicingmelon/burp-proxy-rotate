/**
 * Burp Upstream Proxy Rotate
 * 
 * This extension routes each HTTP request through a different SOCKS proxy from a provided list.
 */
package slicingmelon.burpproxyrotate;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.InterceptedRequest;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.net.InetSocketAddress;

public class BurpProxyRotate implements BurpExtension {
    
    private MontoyaApi api;
    private List<ProxyEntry> proxyList;
    private ProxyTableModel proxyTableModel;
    private JTextArea logTextArea;
    private final Random random = new Random();
    private final ReadWriteLock proxyListLock = new ReentrantReadWriteLock();
    private boolean extensionEnabled = false;
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Burp SOCKS Proxy Rotator");
        
        // Initialize proxy list
        proxyList = new ArrayList<>();
        
        // Load saved proxies
        loadSavedProxies();
        
        // Register as HTTP handler
        registerHttpHandler();
        
        // Register proxy handlers for earlier interception
        registerProxyHandlers();
        
        // Create and register the UI
        SwingUtilities.invokeLater(() -> {
            JComponent panel = createUserInterface();
            api.userInterface().registerSuiteTab("SOCKS Proxy Rotator", panel);
        });
        
        logMessage("SOCKS Proxy Rotator extension loaded successfully");
    }
    
    private void loadSavedProxies() {
        String savedProxies = api.persistence().extensionSettings().getString("proxyList");
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
        
        String enabledSetting = api.persistence().extensionSettings().getString("enabled");
        if (enabledSetting != null) {
            extensionEnabled = Boolean.parseBoolean(enabledSetting);
        }
    }
    
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
        
        api.persistence().extensionSettings().setString("proxyList", sb.toString());
        api.persistence().extensionSettings().setString("enabled", String.valueOf(extensionEnabled));
    }
    
    private void registerHttpHandler() {
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                if (!extensionEnabled || proxyList.isEmpty()) {
                    return RequestToBeSentAction.continueWith(request);
                }
                
                ProxyEntry proxy = getRandomProxy();
                if (proxy != null) {
                    logMessage("Routing request to: " + request.url() + " through SOCKS proxy: " + proxy.getHost() + ":" + proxy.getPort());
                    return RequestToBeSentAction.continueWith(
                            request.withSocksProxy(new InetSocketAddress(proxy.getHost(), proxy.getPort()))
                    );
                }
                
                return RequestToBeSentAction.continueWith(request);
            }
            
            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                return ResponseReceivedAction.continueWith(response);
            }
        });
    }
    
    private void registerProxyHandlers() {
        api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            @Override
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
                return ProxyRequestReceivedAction.continueWith(interceptedRequest);
            }
            
            @Override
            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
                if (!extensionEnabled || proxyList.isEmpty()) {
                    return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
                }
                
                ProxyEntry proxy = getRandomProxy();
                if (proxy != null) {
                    logMessage("Routing intercepted request to: " + interceptedRequest.url() + " through SOCKS proxy: " + proxy.getHost() + ":" + proxy.getPort());
                    HttpRequest newRequest = interceptedRequest
                            .withSocksProxy(new InetSocketAddress(proxy.getHost(), proxy.getPort()));
                    return ProxyRequestToBeSentAction.continueWith(newRequest);
                }
                
                return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
            }
        });
    }
    
    private ProxyEntry getRandomProxy() {
        proxyListLock.readLock().lock();
        try {
            if (proxyList.isEmpty()) {
                return null;
            }
            return proxyList.get(random.nextInt(proxyList.size()));
        } finally {
            proxyListLock.readLock().unlock();
        }
    }
    
    private JComponent createUserInterface() {
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Create enable/disable toggle
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JCheckBox enableCheckbox = new JCheckBox("Enable SOCKS Proxy Rotation", extensionEnabled);
        enableCheckbox.addActionListener(e -> {
            extensionEnabled = enableCheckbox.isSelected();
            saveProxies();
            logMessage("SOCKS Proxy Rotation " + (extensionEnabled ? "enabled" : "disabled"));
        });
        controlPanel.add(enableCheckbox);
        
        // Create proxy table
        proxyTableModel = new ProxyTableModel();
        JTable proxyTable = new JTable(proxyTableModel);
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
        JTextField portField = new JTextField(5);
        JButton addButton = new JButton("Add Proxy");
        
        gbc.gridx = 0;
        gbc.gridy = 0;
        inputPanel.add(hostLabel, gbc);
        
        gbc.gridx = 1;
        inputPanel.add(hostField, gbc);
        
        gbc.gridx = 2;
        inputPanel.add(portLabel, gbc);
        
        gbc.gridx = 3;
        inputPanel.add(portField, gbc);
        
        gbc.gridx = 4;
        inputPanel.add(addButton, gbc);
        
        addButton.addActionListener(e -> {
            String host = hostField.getText().trim();
            String portText = portField.getText().trim();
            
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
                
                addProxy(host, port);
                hostField.setText("");
                portField.setText("");
                
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(mainPanel, "Port must be a valid number", "Validation Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        
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
            
            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                
                String[] parts = line.split(":");
                if (parts.length != 2) {
                    continue;
                }
                
                try {
                    String host = parts[0].trim();
                    int port = Integer.parseInt(parts[1].trim());
                    
                    if (!host.isEmpty() && port > 0 && port <= 65535) {
                        addProxy(host, port);
                        added++;
                    }
                } catch (NumberFormatException ex) {
                    // Skip invalid entries
                }
            }
            
            if (added > 0) {
                bulkTextArea.setText("");
                logMessage("Added " + added + " proxies from bulk input");
            }
        });
        
        // Management buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton deleteButton = new JButton("Delete Selected");
        JButton clearButton = new JButton("Clear All");
        
        deleteButton.addActionListener(e -> {
            int selectedRow = proxyTable.getSelectedRow();
            if (selectedRow >= 0 && selectedRow < proxyList.size()) {
                removeProxy(selectedRow);
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
    
    private void addProxy(String host, int port) {
        proxyListLock.writeLock().lock();
        try {
            proxyList.add(new ProxyEntry(host, port));
        } finally {
            proxyListLock.writeLock().unlock();
        }
        
        updateProxyTable();
        saveProxies();
        logMessage("Added proxy: " + host + ":" + port);
    }
    
    private void removeProxy(int index) {
        if (index >= 0 && index < proxyList.size()) {
            ProxyEntry removed;
            
            proxyListLock.writeLock().lock();
            try {
                removed = proxyList.remove(index);
            } finally {
                proxyListLock.writeLock().unlock();
            }
            
            updateProxyTable();
            saveProxies();
            logMessage("Removed proxy: " + removed.getHost() + ":" + removed.getPort());
        }
    }
    
    private void clearAllProxies() {
        proxyListLock.writeLock().lock();
        try {
            proxyList.clear();
        } finally {
            proxyListLock.writeLock().unlock();
        }
        
        updateProxyTable();
        saveProxies();
        logMessage("Cleared all proxies");
    }
    
    private void updateProxyTable() {
        if (proxyTableModel != null) {
            proxyTableModel.fireTableDataChanged();
        }
    }
    
    private void logMessage(String message) {
        api.logging().logToOutput(message);
        
        if (logTextArea != null) {
            SwingUtilities.invokeLater(() -> {
                logTextArea.append(message + "\n");
                // Auto-scroll to bottom
                logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
            });
        }
    }
    
    private class ProxyTableModel extends AbstractTableModel {
        private final String[] columnNames = {"Host", "Port"};
        
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
            proxyListLock.readLock().lock();
            try {
                if (rowIndex >= 0 && rowIndex < proxyList.size()) {
                    ProxyEntry entry = proxyList.get(rowIndex);
                    
                    switch (columnIndex) {
                        case 0:
                            return entry.getHost();
                        case 1:
                            return entry.getPort();
                        default:
                            return null;
                    }
                }
                return null;
            } finally {
                proxyListLock.readLock().unlock();
            }
        }
    }
    
    private static class ProxyEntry {
        private final String host;
        private final int port;
        
        public ProxyEntry(String host, int port) {
            this.host = host;
            this.port = port;
        }
        
        public String getHost() {
            return host;
        }
        
        public int getPort() {
            return port;
        }
    }
}