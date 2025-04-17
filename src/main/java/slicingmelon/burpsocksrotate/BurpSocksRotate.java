/**
 * Burp Upstream Proxy Rotate
 * 
 * This extension routes each HTTP request through a different SOCKS proxy from a provided list.
 */
package slicingmelon.burpsocksrotate;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

public class BurpSocksRotate implements BurpExtension {
    
    private MontoyaApi api;
    private List<ProxyEntry> proxyList;
    private ProxyTableModel proxyTableModel;
    private JTextArea logTextArea;
    private final ReadWriteLock proxyListLock = new ReentrantReadWriteLock();
    private boolean extensionEnabled = false; // For context menu proxy selection feature
    
    // SOCKS proxy rotator service
    private SocksProxyService socksProxyService;
    private int configuredLocalPort = 1080; // Port configured in UI, passed to service on start
    
    // UI components related to server control
    private JButton startServerButton;
    private JButton stopServerButton;
    private JTextField portField;
    
    // Keys for persistence
    private static final String PROXY_LIST_KEY = "proxyList";
    private static final String ENABLED_KEY = "enabled"; // Persistence for context menu feature
    private static final String PORT_KEY = "localPort";
    
    // Performance settings (passed to SocksProxyService)
    private int bufferSize = 1048576; // 1MB
    private int connectionTimeout = 10000; // 10 seconds
    private int dataTimeout = 30000; // 30 seconds
    private boolean verboseLogging = false; // TODO: Add UI control for this
    private int maxConnections = 20; // TODO: Add UI control for this
    private int maxPooledConnectionsPerProxy = 5; // TODO: Add UI control for this

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Burp SOCKS Proxy Rotator");
        
        // Initialize proxy list
        proxyList = new ArrayList<>();
        
        // Load saved proxies and settings
        loadSavedProxies(); // Also loads configuredLocalPort
        
        // Initialize the SOCKS Proxy Service
        // Pass necessary dependencies: proxy list, lock, logger, and configuration
        socksProxyService = new SocksProxyService(
                proxyList,
                proxyListLock,
                api.logging(),
                bufferSize,
                connectionTimeout,
                dataTimeout,
                verboseLogging,
                maxConnections,
                maxPooledConnectionsPerProxy
        );

        // Create and register the UI
        SwingUtilities.invokeLater(() -> {
            JComponent panel = createUserInterface();
            api.userInterface().registerSuiteTab("SOCKS Proxy Rotator", panel);
            updateServerButtons(); // Initialize button state based on service state (likely stopped)
        });
        
        // Add a context menu item to manually set the SOCKS proxy
        registerContextMenu();
        
        // Add shutdown hook
        api.extension().registerUnloadingHandler(this::shutdown);
        
        logMessage("SOCKS Proxy Rotator extension loaded successfully");
    }
    
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
                                // Use the constructor directly now
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
        
        String enabledSetting = api.persistence().preferences().getString(ENABLED_KEY);
        if (enabledSetting != null) {
            extensionEnabled = Boolean.parseBoolean(enabledSetting);
        }
        
        String portSetting = api.persistence().preferences().getString(PORT_KEY);
        if (portSetting != null) {
            try {
                int port = Integer.parseInt(portSetting);
                if (port > 0 && port < 65536) {
                    configuredLocalPort = port; // Load the configured port
                }
            } catch (NumberFormatException e) {
                // Ignore, use default port
            }
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
        
        api.persistence().preferences().setString(PROXY_LIST_KEY, sb.toString());
        api.persistence().preferences().setString(ENABLED_KEY, String.valueOf(extensionEnabled));
        api.persistence().preferences().setString(PORT_KEY, String.valueOf(configuredLocalPort)); // Save the configured port
    }
    
    private JComponent createUserInterface() {
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Create control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        // Enable/disable checkbox (for context menu feature)
        JCheckBox enableCheckbox = new JCheckBox("Enable Proxy Marking", extensionEnabled);
        enableCheckbox.addActionListener(e -> {
            extensionEnabled = enableCheckbox.isSelected();
            saveProxies();
            logMessage("Proxy Marking " + (extensionEnabled ? "enabled" : "disabled"));
        });
        controlPanel.add(enableCheckbox);
        
        // Separator
        controlPanel.add(new JSeparator(JSeparator.VERTICAL));
        
        // Server controls panel
        JPanel serverControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        serverControls.add(new JLabel("Local Port:"));
        
        portField = new JTextField(String.valueOf(configuredLocalPort), 5); // Use configured port
        serverControls.add(portField);
        
        startServerButton = new JButton("Start Proxy Server");
        startServerButton.addActionListener(e -> startProxyServer());
        serverControls.add(startServerButton);
        
        stopServerButton = new JButton("Stop Proxy Server");
        stopServerButton.addActionListener(e -> stopProxyServer());
        stopServerButton.setEnabled(false); // Initial state
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
        JTextField addPortField = new JTextField(5); // Renamed to avoid clash with server portField
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
        inputPanel.add(addPortField, gbc); // Use renamed field
        
        gbc.gridx = 4;
        inputPanel.add(addButton, gbc);
        
        gbc.gridx = 5;
        inputPanel.add(validateAllButton, gbc);
        
        addButton.addActionListener(e -> {
            String host = hostField.getText().trim();
            String portText = addPortField.getText().trim(); // Use renamed field
            
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
                addProxy(proxy); // Calls method below
                
                // Validate the newly added proxy
                new Thread(() -> {
                    validateProxy(proxy, 3);
                    updateProxyTable();
                }).start();
                
                hostField.setText("");
                addPortField.setText(""); // Use renamed field
                
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
            
            String[] lines = bulk.split("\n"); // Use regex for newline
            int added = 0;
            List<ProxyEntry> proxiesToAdd = new ArrayList<>(); // Collect proxies first

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
                        // Check for duplicates before adding to list
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
                updateProxyTable(); // Update table after adding
                saveProxies(); // Save the updated list
                logMessage("Added " + added + " new proxies from bulk input.");
                 // Optionally trigger validation for added proxies
                 // new Thread(() -> validateAddedProxies(proxiesToAdd)).start();
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
            if (selectedRow >= 0) { // Table model index might differ if sorted/filtered
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
        // TODO: Add a "Settings" tab for bufferSize, timeouts, maxConnections, verboseLogging etc.
        
        mainPanel.add(controlPanel, BorderLayout.NORTH);
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        
        // Update table with existing proxies
        updateProxyTable();
        
        return mainPanel;
    }
    
    private void startProxyServer() {
        proxyListLock.readLock().lock();
        boolean hasActiveProxy;
        try {
             hasActiveProxy = proxyList.stream().anyMatch(ProxyEntry::isActive);
             if (proxyList.isEmpty() || !hasActiveProxy) {
                  JOptionPane.showMessageDialog(null,
                     proxyList.isEmpty() ? "Please add at least one proxy before starting the server." : "Please add or validate at least one proxy before starting the server.",
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
             configuredLocalPort = portToUse; // Update the configured port
             saveProxies(); // Save the potentially changed port
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(null, 
                "Invalid port number. Please enter a number between 1-65535.",
                "Invalid Port", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // Define callbacks for success and failure
        Runnable onSuccessCallback = () -> {
            // Run UI updates on the Event Dispatch Thread (EDT)
            SwingUtilities.invokeLater(() -> {
                updateServerButtons(); // Update button states
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
            // Run UI updates on the Event Dispatch Thread (EDT)
            SwingUtilities.invokeLater(() -> {
                logMessage("Proxy service failed to start: " + errorMessage);
                JOptionPane.showMessageDialog(null, 
                    "Failed to start proxy server: " + errorMessage,
                    "Server Error", 
                    JOptionPane.ERROR_MESSAGE);
                updateServerButtons(); // Ensure buttons reflect stopped state
            });
        };

        // Start the proxy service with callbacks
        try {
            logMessage("Attempting to start SOCKS proxy service on port " + portToUse + "...");
            socksProxyService.start(portToUse, onSuccessCallback, onFailureCallback);
            // Remove immediate UI updates and checks from here - they are now handled by callbacks
        } catch (Exception ex) {
            // Catch any immediate exceptions from the start() call itself (e.g., invalid arguments)
            logMessage("Unexpected error trying to initiate proxy service start: " + ex.getMessage());
            JOptionPane.showMessageDialog(null,
                "An unexpected error occurred trying to start the proxy service: " + ex.getMessage(),
                "Start Error",
                JOptionPane.ERROR_MESSAGE);
            updateServerButtons(); // Ensure buttons reflect stopped state on immediate error
        }
    }
    
    private void stopProxyServer() {
         logMessage("Stopping SOCKS Proxy Rotator server...");
         socksProxyService.stop();
         updateServerButtons(); // Update UI after stopping
         logMessage("SOCKS Proxy Rotator server stop requested."); // Service logs when fully stopped
    }
    
    private void updateServerButtons() {
        SwingUtilities.invokeLater(() -> {
            if (startServerButton != null && stopServerButton != null && portField != null) {
                boolean running = socksProxyService != null && socksProxyService.isRunning();
                startServerButton.setEnabled(!running);
                stopServerButton.setEnabled(running);
                portField.setEnabled(!running); // Disable port field when running
            }
        });
    }

    private void shutdown() {
         logMessage("Extension unloading. Stopping proxy service...");
         if (socksProxyService != null) {
            stopProxyServer(); // Use the existing stop method which calls service.stop()
         }
         saveProxies(); // Ensure settings are saved on unload
         logMessage("SOCKS Proxy Rotator extension shut down.");
    }
    
    private void addProxy(ProxyEntry proxy) {
         boolean added = false;
         proxyListLock.writeLock().lock();
         try {
             // Prevent duplicates
             boolean exists = proxyList.stream().anyMatch(p -> p.getHost().equalsIgnoreCase(proxy.getHost()) && p.getPort() == proxy.getPort());
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
             // Optionally re-initialize connection pool in service if server is running?
             // if (socksProxyService != null && socksProxyService.isRunning()) {
             //     socksProxyService.initializeConnectionPool(); // Needs public access or a dedicated method
             // }
         }
    }
    
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
            // Optionally update connection pool in service if server is running
            // if (socksProxyService != null && socksProxyService.isRunning()) {
            //     socksProxyService.removeProxyFromPool(removed); // Needs method in service
            // }
        }
    }
    
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
            // Optionally clear connection pool in service if server is running
            // if (socksProxyService != null && socksProxyService.isRunning()) {
            //     socksProxyService.initializeConnectionPool(); // Re-init empty pool
            // }
        }
    }
    
    private void updateProxyTable() {
        if (proxyTableModel != null) {
             SwingUtilities.invokeLater(() -> proxyTableModel.fireTableDataChanged());
        }
    }
    
    private void logMessage(String message) {
        // Log to Burp output
        if (api != null && api.logging() != null) {
             api.logging().logToOutput(message);
        } else {
             System.out.println("Log (API not ready): " + message); // Fallback during early init/late shutdown
        }
        
        // Log to UI text area
        if (logTextArea != null) {
            SwingUtilities.invokeLater(() -> {
                logTextArea.append(message + "\n");
                // Auto-scroll to bottom
                logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
            });
        }
    }
    
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
                    case 1: return entry.getPort(); // Keep as int for potential sorting
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
            if (columnIndex == 1) return Integer.class; // Port is integer
            return String.class;
        }
    }
    
    private void setupTableRenderer(JTable proxyTable) {
        proxyTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() { // Render based on Object for different types
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                
                 // Reset color first
                 c.setForeground(table.getForeground());
                 
                 // Use model index, as view index might change due to sorting
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
                 
                 // Center port number column if desired
                 if (column == 1) {
                    ((JLabel) c).setHorizontalAlignment(SwingConstants.CENTER);
                 } else {
                     ((JLabel) c).setHorizontalAlignment(SwingConstants.LEFT);
                 }

                return c;
            }
        });
        // Enable sorting
        proxyTable.setAutoCreateRowSorter(true);
    }
    
    private boolean validateProxy(ProxyEntry proxy, int maxAttempts) {
        logMessage("Validating proxy: " + proxy.getHost() + ":" + proxy.getPort() + " (attempts left: " + maxAttempts + ")");
        proxy.setErrorMessage("Validating..."); // Indicate validation in progress
         updateProxyTable(); // Show "Validating..." status

        boolean success = false;
        String finalErrorMessage = "Validation failed"; // Default error

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
             Socket socket = null;
            try {
                socket = new Socket();
                socket.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()), 5000); // 5 second connection timeout
                socket.setSoTimeout(5000); // 5 second read timeout

                OutputStream out = socket.getOutputStream();
                InputStream in = socket.getInputStream();
                
                // Send SOCKS5 greeting (No Auth)
                out.write(new byte[]{0x05, 0x01, 0x00});
                out.flush();
                
                // Read SOCKS5 response
                byte[] response = new byte[2];
                int bytesRead = in.read(response);
                
                if (bytesRead == 2 && response[0] == 0x05 && response[1] == 0x00) {
                    logMessage("Proxy validated successfully: " + proxy.getHost() + ":" + proxy.getPort());
                    success = true;
                    finalErrorMessage = ""; // Clear error on success
                    break; // Exit loop on success
                } else {
                    finalErrorMessage = "Invalid SOCKS response (Bytes: " + bytesRead + ", Resp: " + (bytesRead>0 ? response[0]:"N/A") + "," + (bytesRead>1 ? response[1]:"N/A") + ")";
                    logMessage("Attempt " + attempt + "/" + maxAttempts + " failed: " + finalErrorMessage);
                }
            } catch (IOException e) {
                 finalErrorMessage = e.getMessage();
                 if (finalErrorMessage == null || finalErrorMessage.isEmpty()) {
                     finalErrorMessage = e.getClass().getSimpleName(); // Use exception type if message is null
                 }
                 logMessage("Attempt " + attempt + "/" + maxAttempts + " failed: " + finalErrorMessage);
            } finally {
                if (socket != null) {
                    try { socket.close(); } catch (IOException e) { /* ignore */ }
                }
            }
            
            // Wait before retrying if not the last attempt and not successful
            if (!success && attempt < maxAttempts) {
                try {
                    Thread.sleep(1000); // 1 second delay
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    finalErrorMessage = "Validation interrupted";
                    logMessage("Validation interrupted for " + proxy.getHost() + ":" + proxy.getPort());
                    break; // Exit loop if interrupted
                }
            }
        }

        // Update final status outside the loop
        proxy.setActive(success);
        proxy.setErrorMessage(finalErrorMessage);
        updateProxyTable(); // Update UI with final status

        return success;
    }
    
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
             // Create a copy to avoid holding lock during long validation
             proxiesToValidate = new ArrayList<>(proxyList);
        } finally {
            proxyListLock.readLock().unlock();
        }

        new Thread(() -> {
            int total = proxiesToValidate.size();
            final AtomicInteger activeCount = new AtomicInteger(0);
            
            logMessage("Starting validation for " + total + " proxies...");

             // Use a thread pool for concurrent validation? (Careful with resource limits)
             // ExecutorService validationPool = Executors.newFixedThreadPool(10); // Example: 10 concurrent validations
             
             proxiesToValidate.forEach(proxy -> {
                 // validationPool.submit(() -> { ... }); // If using pool
                  if (validateProxy(proxy, 3)) { // Validate each proxy from the copied list
                      activeCount.incrementAndGet();
                  }
                 // updateProxyTable(); // updateProxyTable is called within validateProxy now
             });
             
             // validationPool.shutdown(); try { validationPool.awaitTermination(...); } catch(...) {} // If using pool

            logMessage("Validation complete.");
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(null, 
                    "Validation complete. " + activeCount.get() + " of " + total + " proxies are active.",
                    "Validation Results", 
                    JOptionPane.INFORMATION_MESSAGE);
                 updateProxyTable(); // Final table update just in case
            });
        }).start();
    }

    private void registerContextMenu() {
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                 // This context menu seems less relevant now as the primary function
                 // is the rotator service, not manually setting Burp's upstream proxy.
                 // Keeping it for now, but consider removing or repurposing if the
                 // "Enable Proxy Marking" feature is removed.

                 List<ProxyEntry> currentProxyList;
                 proxyListLock.readLock().lock();
                 try {
                     // Create a copy to avoid holding lock while menu is open
                     currentProxyList = new ArrayList<>(proxyList);
                 } finally {
                     proxyListLock.readLock().unlock();
                 }


                if (currentProxyList.isEmpty() || !extensionEnabled) {
                    return Collections.emptyList();
                }
                
                List<Component> menuItems = new ArrayList<>();
                JMenu proxyMenu = new JMenu("SOCKS Proxy Rotator");
                
                // Limit number of items shown in context menu?
                int count = 0;
                for (ProxyEntry proxy : currentProxyList) {
                    JMenuItem item = new JMenuItem("Manually Use: " + proxy.getHost() + ":" + proxy.getPort());
                     // Pass the proxy details directly to avoid issues with index changes
                     item.addActionListener(e -> showManualProxyInstructions(proxy.getHost(), proxy.getPort()));
                    proxyMenu.add(item);
                    count++;
                    if (count >= 20) { // Limit context menu size
                        proxyMenu.addSeparator();
                        JMenuItem more = new JMenuItem("...");
                        more.setEnabled(false);
                        proxyMenu.add(more);
                        break;
                    }
                }
                
                menuItems.add(proxyMenu);
                return menuItems;
            }
        });
    }
    
    // Renamed from selectCurrentProxy to avoid confusion with rotation
    private void showManualProxyInstructions(String host, int port) {
         logMessage("Showing manual instructions for proxy: " + host + ":" + port);
        JOptionPane.showMessageDialog(null,
                "To manually use this proxy (" + host + ":" + port + ")\n" +
                "instead of the rotator service:\n\n" +
                "1. Go to Settings > Network > Connections > SOCKS Proxy\n" +
                "2. Check 'Use SOCKS proxy'\n" +
                "3. Enter Proxy Host: " + host + "\n" +
                "4. Enter Proxy Port: " + port + "\n\n" +
                "(Remember to disable or reconfigure this if you want to use the rotator service again).",
                "Manual SOCKS Proxy Setup",
                JOptionPane.INFORMATION_MESSAGE);
    }
    
    // Removed ProxyEntry inner class - moved to ProxyEntry.java
    
    // Keep compatibility method for adding proxy by host/port
    private void addProxy(String host, int port) {
        addProxy(new ProxyEntry(host, port));
    }
}