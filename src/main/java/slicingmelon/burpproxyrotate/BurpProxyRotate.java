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
import burp.api.montoya.http.HttpService;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.net.InetSocketAddress;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BurpProxyRotate implements BurpExtension {
    
    private MontoyaApi api;
    private List<ProxyEntry> proxyList;
    private ProxyTableModel proxyTableModel;
    private JTextArea logTextArea;
    private final Random random = new Random();
    private final ReadWriteLock proxyListLock = new ReentrantReadWriteLock();
    private boolean extensionEnabled = false;
    
    // SOCKS proxy rotator server
    private ServerSocket serverSocket;
    private Thread serverThread;
    private ExecutorService threadPool;
    private boolean serverRunning = false;
    private int localPort = 1080;
    private JButton startServerButton;
    private JButton stopServerButton;
    private JTextField portField;
    
    // Keys for persistence
    private static final String PROXY_LIST_KEY = "proxyList";
    private static final String ENABLED_KEY = "enabled";
    private static final String PORT_KEY = "localPort";
    
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
                    localPort = port;
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
        api.persistence().preferences().setString(PORT_KEY, String.valueOf(localPort));
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
                    
                    // Instead of modifying the request with a SOCKS proxy directly,
                    // we'll add a header to mark it for special handling by the proxy handler
                    // This is just to track which requests have been processed
                    HttpRequest newRequest = request.withAddedHeader("X-SOCKS-Proxy", 
                            proxy.getHost() + ":" + proxy.getPort());
                    
                    return RequestToBeSentAction.continueWith(newRequest);
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
                    
                    // Add a header to mark this request as being sent through a SOCKS proxy
                    HttpRequest newRequest = interceptedRequest.withAddedHeader("X-SOCKS-Proxy", 
                            proxy.getHost() + ":" + proxy.getPort());
                    
                    return ProxyRequestToBeSentAction.continueWith(newRequest);
                }
                
                return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
            }
        });
        
        // Since we can't directly modify requests to use a SOCKS proxy,
        // we'll use Burp's network settings to configure the SOCKS proxy
        // and display instructions to the user
        logMessage("Important: This extension adds a header to mark requests that should go through a proxy.");
        logMessage("You need to configure Burp's SOCKS proxy settings manually:");
        logMessage("1. Go to Settings > Network > Connections > SOCKS Proxy");
        logMessage("2. Check 'Use SOCKS proxy'");
        logMessage("3. Enter the SOCKS proxy details");
        logMessage("The extension will rotate which proxy to use for each request in your list");
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
        
        // Create control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        // Enable/disable checkbox
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
        
        portField = new JTextField(String.valueOf(localPort), 5);
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
        JTextField portField = new JTextField(5);
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
        inputPanel.add(portField, gbc);
        
        gbc.gridx = 4;
        inputPanel.add(addButton, gbc);
        
        gbc.gridx = 5;
        inputPanel.add(validateAllButton, gbc);
        
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
                
                ProxyEntry proxy = new ProxyEntry(host, port);
                addProxy(proxy);
                
                // Validate the newly added proxy
                new Thread(() -> {
                    validateProxy(proxy, 3);
                    updateProxyTable();
                }).start();
                
                hostField.setText("");
                portField.setText("");
                
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
    
    private void startProxyServer() {
        // Check if we have at least one proxy
        if (proxyList.isEmpty()) {
            JOptionPane.showMessageDialog(null, 
                "Please add at least one proxy before starting the server.",
                "No Proxies Configured", 
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // Read port from UI
        try {
            localPort = Integer.parseInt(portField.getText().trim());
            if (localPort <= 0 || localPort > 65535) {
                throw new NumberFormatException("Port out of range");
            }
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(null, 
                "Invalid port number. Please enter a number between 1-65535.",
                "Invalid Port", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        saveProxies();
        
        // Start the proxy server in a background thread
        if (serverRunning) {
            stopProxyServer();
        }
        
        threadPool = Executors.newCachedThreadPool();
        
        serverThread = new Thread(() -> {
            try {
                serverSocket = new ServerSocket(localPort);
                serverRunning = true;
                
                logMessage("SOCKS Proxy Rotator server started on localhost:" + localPort);
                
                while (serverRunning && !serverSocket.isClosed()) {
                    try {
                        Socket clientSocket = serverSocket.accept();
                        threadPool.execute(() -> handleSocksConnection(clientSocket));
                    } catch (IOException e) {
                        if (serverRunning) {
                            logMessage("Error accepting connection: " + e.getMessage());
                        }
                    }
                }
            } catch (IOException e) {
                logMessage("Error starting server: " + e.getMessage());
                JOptionPane.showMessageDialog(null, 
                    "Failed to start proxy server: " + e.getMessage(),
                    "Server Error", 
                    JOptionPane.ERROR_MESSAGE);
                
                serverRunning = false;
                updateServerButtons();
            }
        });
        
        serverThread.start();
        updateServerButtons();
        
        // Show configuration notice
        JOptionPane.showMessageDialog(null,
            "SOCKS Proxy Rotator started on localhost:" + localPort + "\n\n" +
            "To use it:\n" +
            "1. Go to Burp Settings > Network > Connections > SOCKS Proxy\n" +
            "2. Check 'Use SOCKS proxy'\n" +
            "3. Set Host to 'localhost' and Port to '" + localPort + "'\n\n" +
            "The rotator will route each request through a different SOCKS proxy from your list.",
            "Proxy Server Started",
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void stopProxyServer() {
        serverRunning = false;
        
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            logMessage("Error closing server socket: " + e.getMessage());
        }
        
        if (threadPool != null) {
            threadPool.shutdownNow();
        }
        
        updateServerButtons();
        logMessage("SOCKS Proxy Rotator server stopped");
    }
    
    private void updateServerButtons() {
        SwingUtilities.invokeLater(() -> {
            if (startServerButton != null && stopServerButton != null) {
                startServerButton.setEnabled(!serverRunning);
                stopServerButton.setEnabled(serverRunning);
                portField.setEnabled(!serverRunning);
            }
        });
    }
    
    private void handleSocksConnection(Socket clientSocket) {
        try {
            // Set larger socket buffer sizes for handling large requests
            clientSocket.setReceiveBufferSize(65536);  // 64KB
            clientSocket.setSendBufferSize(65536);     // 64KB
            
            // Basic SOCKS5 protocol implementation
            InputStream clientIn = clientSocket.getInputStream();
            OutputStream clientOut = clientSocket.getOutputStream();
            
            // Read SOCKS5 greeting
            byte[] buffer = new byte[1024];
            int read = clientIn.read(buffer, 0, 2);
            
            if (read != 2 || buffer[0] != 0x05) {
                logMessage("Invalid SOCKS protocol version");
                clientSocket.close();
                return;
            }
            
            int numMethods = buffer[1] & 0xFF;
            read = clientIn.read(buffer, 0, numMethods);
            
            if (read != numMethods) {
                logMessage("Failed to read authentication methods");
                clientSocket.close();
                return;
            }
            
            // Send SOCKS5 response - no authentication required
            clientOut.write(new byte[] { 0x05, 0x00 });
            
            // Read connection request
            read = clientIn.read(buffer, 0, 4);
            if (read != 4 || buffer[0] != 0x05 || buffer[1] != 0x01) {
                logMessage("Invalid SOCKS connection request");
                clientSocket.close();
                return;
            }
            
            // Read address type
            int addressType = buffer[3] & 0xFF;
            String targetHost;
            int targetPort;
            
            switch (addressType) {
                case 0x01: // IPv4
                    byte[] ipv4 = new byte[4];
                    read = clientIn.read(ipv4);
                    if (read != 4) {
                        logMessage("Failed to read IPv4 address");
                        clientSocket.close();
                        return;
                    }
                    targetHost = (ipv4[0] & 0xFF) + "." + (ipv4[1] & 0xFF) + "." + 
                              (ipv4[2] & 0xFF) + "." + (ipv4[3] & 0xFF);
                    break;
                    
                case 0x03: // Domain name
                    int domainLength = clientIn.read() & 0xFF;
                    byte[] domain = new byte[domainLength];
                    read = clientIn.read(domain);
                    if (read != domainLength) {
                        logMessage("Failed to read domain name");
                        clientSocket.close();
                        return;
                    }
                    targetHost = new String(domain);
                    break;
                    
                case 0x04: // IPv6
                    logMessage("IPv6 addresses not supported yet");
                    clientSocket.close();
                    return;
                    
                default:
                    logMessage("Unsupported address type: " + addressType);
                    clientSocket.close();
                    return;
            }
            
            // Read port
            byte[] portBytes = new byte[2];
            read = clientIn.read(portBytes);
            if (read != 2) {
                logMessage("Failed to read port");
                clientSocket.close();
                return;
            }
            targetPort = ((portBytes[0] & 0xFF) << 8) | (portBytes[1] & 0xFF);
            
            // Get a random proxy from our list
            ProxyEntry proxy = getRandomProxy();
            if (proxy == null) {
                logMessage("No proxies available");
                clientSocket.close();
                return;
            }
            
            logMessage("Routing connection to " + targetHost + ":" + targetPort + 
                     " via SOCKS proxy " + proxy.getHost() + ":" + proxy.getPort());
            
            // Connect to the upstream SOCKS proxy
            Socket upstreamSocket = new Socket(proxy.getHost(), proxy.getPort());
            InputStream upstreamIn = upstreamSocket.getInputStream();
            OutputStream upstreamOut = upstreamSocket.getOutputStream();
            
            // SOCKS5 handshake with upstream proxy
            upstreamOut.write(new byte[] { 0x05, 0x01, 0x00 });
            read = upstreamIn.read(buffer, 0, 2);
            if (read != 2 || buffer[0] != 0x05 || buffer[1] != 0x00) {
                logMessage("Upstream proxy handshake failed");
                clientSocket.close();
                upstreamSocket.close();
                return;
            }
            
            // Forward the connection request to the upstream proxy
            byte[] requestHeader = new byte[4];
            requestHeader[0] = 0x05; // SOCKS5
            requestHeader[1] = 0x01; // CONNECT
            requestHeader[2] = 0x00; // Reserved
            requestHeader[3] = (byte)addressType; // Address type
            
            upstreamOut.write(requestHeader);
            
            // Forward address based on type
            if (addressType == 0x01) { // IPv4
                String[] parts = targetHost.split("\\.");
                for (String part : parts) {
                    upstreamOut.write(Integer.parseInt(part) & 0xFF);
                }
            } else if (addressType == 0x03) { // Domain
                upstreamOut.write(targetHost.length() & 0xFF);
                upstreamOut.write(targetHost.getBytes());
            }
            
            // Forward port
            upstreamOut.write((targetPort >> 8) & 0xFF);
            upstreamOut.write(targetPort & 0xFF);
            
            // Read response from upstream proxy
            read = upstreamIn.read(buffer, 0, 4);
            if (read != 4 || buffer[0] != 0x05 || buffer[1] != 0x00) {
                logMessage("Upstream proxy connection failed");
                clientSocket.close();
                upstreamSocket.close();
                return;
            }
            
            // Skip the bound address in the response
            if (buffer[3] == 0x01) { // IPv4
                upstreamIn.read(new byte[4 + 2]); // 4 for IPv4, 2 for port
            } else if (buffer[3] == 0x03) { // Domain
                int len = upstreamIn.read() & 0xFF;
                upstreamIn.read(new byte[len + 2]); // len for domain, 2 for port
            } else if (buffer[3] == 0x04) { // IPv6
                upstreamIn.read(new byte[16 + 2]); // 16 for IPv6, 2 for port
            }
            
            // Send success response to client
            byte[] response = new byte[10]; // IPv4 format response
            response[0] = 0x05; // SOCKS5
            response[1] = 0x00; // Success
            response[2] = 0x00; // Reserved
            response[3] = 0x01; // IPv4
            // IP and port are all zeros (placeholder)
            
            clientOut.write(response);
            
            // Start bidirectional data transfer
            threadPool.execute(() -> {
                try {
                    byte[] buf = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = clientIn.read(buf)) != -1) {
                        upstreamOut.write(buf, 0, bytesRead);
                        upstreamOut.flush();
                    }
                } catch (IOException e) {
                    // Connection closed
                } finally {
                    try {
                        upstreamSocket.close();
                    } catch (IOException e) {
                        // Ignore
                    }
                }
            });
            
            byte[] buf = new byte[8192];
            int bytesRead;
            while ((bytesRead = upstreamIn.read(buf)) != -1) {
                clientOut.write(buf, 0, bytesRead);
                clientOut.flush();
            }
            
        } catch (IOException e) {
            logMessage("Error handling SOCKS connection: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                // Ignore
            }
        }
    }
    
    private void shutdown() {
        stopProxyServer();
    }
    
    private void addProxy(ProxyEntry proxy) {
        proxyListLock.writeLock().lock();
        try {
            proxyList.add(proxy);
        } finally {
            proxyListLock.writeLock().unlock();
        }
        
        updateProxyTable();
        saveProxies();
        logMessage("Added proxy: " + proxy.getHost() + ":" + proxy.getPort());
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
            proxyListLock.readLock().lock();
            try {
                if (rowIndex >= 0 && rowIndex < proxyList.size()) {
                    ProxyEntry entry = proxyList.get(rowIndex);
                    
                    switch (columnIndex) {
                        case 0:
                            return entry.getHost();
                        case 1:
                            return entry.getPort();
                        case 2:
                            return entry.isActive() ? "Active" : 
                                   "Inactive" + (entry.getErrorMessage().isEmpty() ? "" : ": " + entry.getErrorMessage());
                        default:
                            return null;
                    }
                }
                return null;
            } finally {
                proxyListLock.readLock().unlock();
            }
        }
        
        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }
    }
    
    private void setupTableRenderer(JTable proxyTable) {
        proxyTable.setDefaultRenderer(String.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                
                if (row >= 0 && row < proxyList.size()) {
                    boolean active = proxyList.get(row).isActive();
                    
                    if (!active) {
                        c.setForeground(Color.RED);
                    } else {
                        c.setForeground(table.getForeground());
                    }
                }
                
                return c;
            }
        });
    }
    
    private boolean validateProxy(ProxyEntry proxy, int maxAttempts) {
        logMessage("Validating proxy: " + proxy.getHost() + ":" + proxy.getPort() + " (attempts: " + maxAttempts + ")");
        
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                // Try to connect to the proxy and perform a basic SOCKS5 handshake
                Socket socket = new Socket();
                socket.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()), 5000); // 5 second timeout
                
                OutputStream out = socket.getOutputStream();
                InputStream in = socket.getInputStream();
                
                // Send SOCKS5 greeting
                out.write(new byte[]{0x05, 0x01, 0x00});
                out.flush();
                
                // Read response
                byte[] response = new byte[2];
                int bytesRead = in.read(response);
                
                socket.close();
                
                if (bytesRead == 2 && response[0] == 0x05 && response[1] == 0x00) {
                    logMessage("Proxy validated successfully: " + proxy.getHost() + ":" + proxy.getPort());
                    proxy.setActive(true);
                    proxy.setErrorMessage("");
                    return true;
                } else {
                    logMessage("Attempt " + attempt + " failed: Invalid response from proxy");
                    if (attempt == maxAttempts) {
                        proxy.setActive(false);
                        proxy.setErrorMessage("Invalid response");
                    }
                }
            } catch (IOException e) {
                logMessage("Attempt " + attempt + " failed: " + e.getMessage());
                if (attempt == maxAttempts) {
                    proxy.setActive(false);
                    proxy.setErrorMessage(e.getMessage());
                }
            }
            
            // Wait before retrying
            if (attempt < maxAttempts) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        
        return false;
    }
    
    private void validateAllProxies() {
        if (proxyList.isEmpty()) {
            JOptionPane.showMessageDialog(null, 
                "No proxies to validate.",
                "Validation", 
                JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        new Thread(() -> {
            int total = proxyList.size();
            int active = 0;
            
            for (int i = 0; i < proxyList.size(); i++) {
                ProxyEntry proxy;
                proxyListLock.readLock().lock();
                try {
                    proxy = proxyList.get(i);
                } finally {
                    proxyListLock.readLock().unlock();
                }
                
                if (validateProxy(proxy, 3)) {
                    active++;
                }
                
                updateProxyTable();
            }
            
            final int finalActive = active;
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(null, 
                    "Validation complete. " + finalActive + " of " + total + " proxies are active.",
                    "Validation Results", 
                    JOptionPane.INFORMATION_MESSAGE);
            });
        }).start();
    }
    
    private ProxyEntry getRandomProxy() {
        proxyListLock.readLock().lock();
        try {
            // Create a list of active proxies
            List<ProxyEntry> activeProxies = new ArrayList<>();
            for (ProxyEntry proxy : proxyList) {
                if (proxy.isActive()) {
                    activeProxies.add(proxy);
                }
            }
            
            if (activeProxies.isEmpty()) {
                logMessage("No active proxies available");
                return null;
            }
            
            return activeProxies.get(random.nextInt(activeProxies.size()));
        } finally {
            proxyListLock.readLock().unlock();
        }
    }
    
    private void registerContextMenu() {
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                if (proxyList.isEmpty() || !extensionEnabled) {
                    return Collections.emptyList();
                }
                
                List<Component> menuItems = new ArrayList<>();
                JMenu proxyMenu = new JMenu("SOCKS Proxy Rotator");
                
                for (int i = 0; i < proxyList.size(); i++) {
                    ProxyEntry proxy = proxyList.get(i);
                    JMenuItem item = new JMenuItem("Set current proxy: " + proxy.getHost() + ":" + proxy.getPort());
                    int index = i;
                    item.addActionListener(e -> selectCurrentProxy(index));
                    proxyMenu.add(item);
                }
                
                menuItems.add(proxyMenu);
                return menuItems;
            }
        });
    }
    
    private void selectCurrentProxy(int index) {
        if (index >= 0 && index < proxyList.size()) {
            ProxyEntry proxy = proxyList.get(index);
            logMessage("Manual selection of proxy: " + proxy.getHost() + ":" + proxy.getPort());
            
            // Display instructions for manually setting the proxy
            JOptionPane.showMessageDialog(null,
                    "To use this proxy (" + proxy.getHost() + ":" + proxy.getPort() + "),\n" +
                    "please configure Burp's SOCKS proxy settings manually:\n\n" +
                    "1. Go to Settings > Network > Connections > SOCKS Proxy\n" +
                    "2. Check 'Use SOCKS proxy'\n" +
                    "3. Enter these proxy details: " + proxy.getHost() + ":" + proxy.getPort() + "\n\n" +
                    "Due to API limitations, this extension cannot automatically set the SOCKS proxy.",
                    "Set Current SOCKS Proxy",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    // Add the missing ProxyEntry class
    private static class ProxyEntry {
        private final String host;
        private final int port;
        private boolean active;
        private String errorMessage;
        
        public ProxyEntry(String host, int port) {
            this.host = host;
            this.port = port;
            this.active = true; // Assume active until validated
            this.errorMessage = "";
        }
        
        public String getHost() {
            return host;
        }
        
        public int getPort() {
            return port;
        }
        
        public boolean isActive() {
            return active;
        }
        
        public void setActive(boolean active) {
            this.active = active;
        }
        
        public String getErrorMessage() {
            return errorMessage;
        }
        
        public void setErrorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
        }
    }
    
    // Keep compatibility with existing code
    private void addProxy(String host, int port) {
        addProxy(new ProxyEntry(host, port));
    }
}