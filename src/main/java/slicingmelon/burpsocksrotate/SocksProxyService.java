package slicingmelon.burpsocksrotate;

import burp.api.montoya.logging.Logging;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Consumer;

/**
 * A service that randomly rotates SOCKS proxies for Burp Suite using Java NIO.
 * For each new connection, a different active SOCKS proxy is chosen.
 */
public class SocksProxyService {
    // Default settings
    private int bufferSize = 8092; // 8KB
    private int connectionTimeout = 20000; // 20 seconds
    private int socketTimeout = 120000; // 120 seconds
    private int maxRetryCount = 2; // Number of proxies to try before giving up
    private int maxConnectionsPerProxy = 50; // Maximum connections per proxy
    private int idleTimeoutSec = 60; // Idle timeout in seconds
    
    // Bypass configuration for Burp Collaborator domains
    private boolean bypassCollaborator = true;
    private final List<String> bypassDomains = new ArrayList<>();
    
    private final Logging logging;
    private final List<ProxyEntry> proxyList;
    private final ReadWriteLock proxyListLock;
    private final Random random = new Random();
    
    // Logging configuration
    private boolean loggingEnabled = true;
    
    // NIO components
    private Selector selector;
    private ServerSocketChannel serverChannel;
    private ExecutorService selectorThreadPool;
    private volatile boolean serverRunning = false;
    private int localPort;
    
    // Connection tracking
    private final AtomicInteger activeConnectionCount = new AtomicInteger(0);
    private final ConcurrentHashMap<String, AtomicInteger> connectionsPerProxy = new ConcurrentHashMap<>();
    
    // Connection state management
    private final Map<SocketChannel, ConnectionState> connectionStates = new ConcurrentHashMap<>();
    private final Map<SocketChannel, SocketChannel> proxyConnections = new ConcurrentHashMap<>();
    private final Map<SocketChannel, Long> lastActivityTime = new ConcurrentHashMap<>();
    
    private BurpSocksRotate extension;

    // Connection state enum
    private enum ConnectionStage {
        INITIAL, 
        SOCKS4_CONNECT, SOCKS4_CONNECTED,
        SOCKS5_AUTH, SOCKS5_AUTH_RESPONSE, SOCKS5_CONNECT, SOCKS5_CONNECTED,
        PROXY_CONNECT, PROXY_CONNECTED,
        ERROR
    }
    
    // Class to track state of a connection
    private class ConnectionState {
        private ConnectionStage stage = ConnectionStage.INITIAL;
        private ByteBuffer inputBuffer;
        private ByteBuffer outputBuffer;
        private String targetHost;
        private int targetPort;
        private byte addressType;
        private int socksVersion;
        private ProxyEntry selectedProxy;
        private String errorMessage;
        private long creationTime;
        
        public ConnectionState() {
            // Use direct buffers for better I/O performance
            this.inputBuffer = ByteBuffer.allocateDirect(bufferSize);
            this.outputBuffer = ByteBuffer.allocateDirect(bufferSize);
            this.creationTime = System.currentTimeMillis();
        }
    }

    // Track the last used proxy to enforce rotation
    private volatile int lastProxyIndex = -1;
    private final Object proxyRotationLock = new Object();

    /**
     * Creates a new SocksProxyService.
     */
    public SocksProxyService(List<ProxyEntry> proxyList, ReadWriteLock proxyListLock, Logging logging) {
        this.proxyList = proxyList;
        this.proxyListLock = proxyListLock;
        this.logging = logging;
        
        // Add default Burp Collaborator domains
        bypassDomains.add("burpcollaborator.net");
        bypassDomains.add("oastify.com");
    }

    /**
     * Sets the extension reference for callbacks to update the UI.
     */
    public void setExtension(BurpSocksRotate extension) {
        this.extension = extension;
    }
    
    /**
     * Sets the service settings.
     */
    public void setSettings(int bufferSize, int connectionTimeout, int socketTimeout, int maxRetryCount, int maxConnectionsPerProxy) {
        this.bufferSize = bufferSize;
        this.connectionTimeout = connectionTimeout;
        this.socketTimeout = socketTimeout;
        this.maxRetryCount = maxRetryCount;
        this.maxConnectionsPerProxy = maxConnectionsPerProxy;
        this.idleTimeoutSec = Math.max(30, socketTimeout / 2000); // Half of socket timeout, but minimum 30 seconds
        
        logInfo("Settings updated: bufferSize=" + bufferSize + ", connectionTimeout=" + connectionTimeout + 
                "ms, socketTimeout=" + socketTimeout + "ms, maxRetryCount=" + maxRetryCount + 
                ", maxConnectionsPerProxy=" + maxConnectionsPerProxy +
                ", idleTimeoutSec=" + idleTimeoutSec);
    }

    /**
     * Sets the service settings with explicit connection pool settings.
     */
    public void setSettings(int bufferSize, int connectionTimeout, int socketTimeout, 
                          int maxRetryCount, int maxConnectionsPerProxy, int idleTimeoutSec) {
        this.bufferSize = bufferSize;
        this.connectionTimeout = connectionTimeout;
        this.socketTimeout = socketTimeout;
        this.maxRetryCount = maxRetryCount;
        this.maxConnectionsPerProxy = maxConnectionsPerProxy;
        this.idleTimeoutSec = idleTimeoutSec;
        
        logInfo("Settings updated: bufferSize=" + bufferSize + ", connectionTimeout=" + connectionTimeout + 
                "ms, socketTimeout=" + socketTimeout + "ms, maxRetryCount=" + maxRetryCount + 
                ", maxConnectionsPerProxy=" + maxConnectionsPerProxy +
                ", idleTimeoutSec=" + idleTimeoutSec);
    }

    /**
     * Checks if the service is running.
     */
    public boolean isRunning() {
        return serverRunning;
    }
    
    /**
     * Gets the local port the service is running on.
     */
    public int getLocalPort() {
        return localPort;
    }

    /**
     * Gets the number of active connections.
     */
    public int getActiveConnectionCount() {
        return activeConnectionCount.get();
    }

    /**
     * Starts the SOCKS proxy rotation service using NIO.
     */
    public void start(int port, Runnable onSuccess, Consumer<String> onFailure) {
        if (serverRunning) {
            logInfo("Service is already running.");
            return;
        }

        this.localPort = port;
        
        try {
            // Performance tuning: use enhanced selector provider
            selector = SelectorProvider.provider().openSelector();
            
            // Create a new non-blocking server socket channel with optimized config
            serverChannel = ServerSocketChannel.open();
            serverChannel.configureBlocking(false);
            
            // Set socket options
            serverChannel.socket().setReuseAddress(true);
            
            // Increase accept backlog to handle connection surges
            // This helps during high-volume connection establishment
            serverChannel.socket().bind(new InetSocketAddress(localPort), 1000);
            
            // Register the server channel for accept operations
            serverChannel.register(selector, SelectionKey.OP_ACCEPT);
            
            // Create a dedicated thread pool for the selector loop
            selectorThreadPool = Executors.newSingleThreadExecutor(new ThreadFactory() {
                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "SocksProxy-Selector");
                    t.setDaemon(true);
                    
                    // Set higher priority for the selector thread
                    t.setPriority(Thread.NORM_PRIORITY + 1);
                    return t;
                }
            });
            
            // Create a scheduled thread for idle connection cleanup
            final java.util.concurrent.ScheduledExecutorService cleanupScheduler = 
                Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
                    @Override
                    public Thread newThread(Runnable r) {
                        Thread t = new Thread(r, "SocksProxy-Cleanup");
                        t.setDaemon(true);
                        
                        // Lower priority for cleanup thread
                        t.setPriority(Thread.MIN_PRIORITY);
                        return t;
                    }
                });
            
            serverRunning = true;
            
            // Start the main selector loop
            selectorThreadPool.submit(() -> {
                try {
                    runSelectorLoop();
                } catch (Exception e) {
                    logError("Error in selector loop: " + e.getMessage());
                    serverRunning = false;
                    onFailure.accept("Selector error: " + e.getMessage());
                }
            });
            
            // Start cleanup thread - run every 30 seconds (reduced frequency)
            cleanupScheduler.scheduleAtFixedRate(() -> {
                try {
                    if (serverRunning) {
                        cleanupIdleConnections();
                    } else {
                        cleanupScheduler.shutdown();
                    }
                } catch (Exception e) {
                    logError("Error in cleanup thread: " + e.getMessage());
                }
            }, 30, 30, TimeUnit.SECONDS);
            
            logInfo("Burp SOCKS Rotate server started on localhost:" + localPort + " (NIO mode)");
            onSuccess.run();
            
        } catch (IOException e) {
            logError("Error starting service: " + e.getMessage());
            serverRunning = false;
            onFailure.accept(e.getMessage());
        }
    }
    
    /**
     * The main selector loop that handles all NIO events.
     */
    private void runSelectorLoop() throws IOException {
        int idleCount = 0;
        
        while (serverRunning) {
            try {
                // Wait for events with a timeout (100ms when active, up to 500ms when idle)
                // Using longer timeouts reduces CPU usage significantly
                int selectTimeout = Math.min(100 + (idleCount * 50), 500);
                int readyChannels = selector.select(selectTimeout);
                
                // Check if the server was stopped
                if (!serverRunning) {
                    break;
                }
                
                if (readyChannels == 0) {
                    // No channels ready - count idle cycles
                    idleCount++;
                    
                    // If we've been idle for a while, add a small sleep to reduce CPU usage
                    if (idleCount > 10) {
                        try {
                            Thread.sleep(5);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                    
                    // Check if selector needs to be recreated (JDK bug workaround)
                    if (idleCount % 100 == 0) {
                        if (selector.keys().isEmpty()) {
                            idleCount = 0;
                        }
                    }
                    
                    continue;
                }
                
                // Reset idle count when we have activity
                idleCount = 0;
                
                // Process the ready keys
                Iterator<SelectionKey> keyIterator = selector.selectedKeys().iterator();
                
                while (keyIterator.hasNext()) {
                    SelectionKey key = keyIterator.next();
                    keyIterator.remove();
                    
                    try {
                        if (!key.isValid()) {
                            continue;
                        }
                        
                        // Handle the event based on its type
                        if (key.isAcceptable()) {
                            handleAccept(key);
                        } else if (key.isConnectable()) {
                            handleConnect(key);
                        } else if (key.isReadable()) {
                            handleRead(key);
                        } else if (key.isWritable()) {
                            handleWrite(key);
                        }
                    } catch (IOException e) {
                        logError("I/O error on key operation: " + e.getMessage());
                        cancelAndCloseKey(key);
                    } catch (Exception e) {
                        logError("Unexpected error processing key: " + e.getMessage());
                        cancelAndCloseKey(key);
                    }
                }
            } catch (IOException e) {
                if (serverRunning) {
                    logError("Selector operation error: " + e.getMessage());
                    
                    // Handle the JDK epoll bug by recreating the selector
                    try {
                        Selector newSelector = Selector.open();
                        for (SelectionKey key : selector.keys()) {
                            if (key.isValid() && key.channel().isOpen()) {
                                int ops = key.interestOps();
                                Object att = key.attachment();
                                key.cancel();
                                key.channel().register(newSelector, ops, att);
                            }
                        }
                        selector.close();
                        selector = newSelector;
                        idleCount = 0;
                        logInfo("Recreated selector due to possible JDK bug");
                    } catch (IOException ex) {
                        logError("Failed to recreate selector: " + ex.getMessage());
                        throw e; // Rethrow if we can't recover
                    }
                }
            }
        }
    }

    /**
     * Stops the SOCKS proxy rotation service.
     */
    public void stop() {
        if (!serverRunning) {
            logInfo("Service is not running.");
            return;
        }

        logInfo("Burp SOCKS Rotate server stopping...");
        serverRunning = false;
        
        try {
            // Reset the proxy rotation index
            lastProxyIndex = -1;
            
            // Close the selector to interrupt the selector thread
            if (selector != null) {
                selector.wakeup();
                selector.close();
            }
            
            // Close the server channel
            if (serverChannel != null) {
                serverChannel.close();
            }
            
            // Shutdown the thread pool
            if (selectorThreadPool != null) {
                selectorThreadPool.shutdown();
                selectorThreadPool.awaitTermination(5, TimeUnit.SECONDS);
                if (!selectorThreadPool.isTerminated()) {
                    selectorThreadPool.shutdownNow();
                }
            }
            
            // Close all active connections
            synchronized (connectionStates) {
                for (SocketChannel channel : new ArrayList<>(connectionStates.keySet())) {
                    try {
                        channel.close();
                    } catch (IOException e) {
                        // Ignore
                    }
                }
                connectionStates.clear();
            }
            
            // Clear all associated maps
            synchronized (proxyConnections) {
                proxyConnections.clear();
            }
            synchronized (lastActivityTime) {
                lastActivityTime.clear();
            }
            
            // Reset connection count
            activeConnectionCount.set(0);
            connectionsPerProxy.clear();
            
        } catch (Exception e) {
            logError("Error during shutdown: " + e.getMessage());
        } finally {
            selector = null;
            serverChannel = null;
            selectorThreadPool = null;
        }
        
        logInfo("Burp SOCKS Rotate server stopped.");
    }

    /**
     * Handles an accept event on the server socket.
     */
    private void handleAccept(SelectionKey key) throws IOException {
        ServerSocketChannel serverChannel = (ServerSocketChannel) key.channel();
        SocketChannel clientChannel = serverChannel.accept();
        clientChannel.configureBlocking(false);
        
        // Set socket options
        Socket socket = clientChannel.socket();
        socket.setTcpNoDelay(true);
        socket.setKeepAlive(true);
        
        // Register for read events
        clientChannel.register(selector, SelectionKey.OP_READ);
        
        // Create and store connection state
        ConnectionState state = new ConnectionState();
        connectionStates.put(clientChannel, state);
        lastActivityTime.put(clientChannel, System.currentTimeMillis());
        
        // Increment connection counter
        activeConnectionCount.incrementAndGet();
        
        logInfo("New client connection accepted");
    }
    
    /**
     * Handles a connect event on a client socket.
     */
    private void handleConnect(SelectionKey key) throws IOException {
        SocketChannel proxyChannel = (SocketChannel) key.channel();
        
        try {
            if (proxyChannel.finishConnect()) {
                // Get the corresponding client channel
                SocketChannel clientChannel = null;
                for (Map.Entry<SocketChannel, SocketChannel> entry : proxyConnections.entrySet()) {
                    if (entry.getValue() == proxyChannel) {
                        clientChannel = entry.getKey();
                        break;
                    }
                }
                
                if (clientChannel == null) {
                    logError("Could not find client for proxy connect completion");
                    proxyChannel.close();
                    return;
                }
                
                ConnectionState state = connectionStates.get(clientChannel);
                if (state == null) {
                    logError("No state found for client in connect completion");
                    proxyChannel.close();
                    return;
                }
                
                // Update connection activity time
                lastActivityTime.put(proxyChannel, System.currentTimeMillis());
                lastActivityTime.put(clientChannel, System.currentTimeMillis());
                
                // Check if this is a direct connection (bypassing proxy for Collaborator)
                if (state.selectedProxy != null && "direct".equals(state.selectedProxy.getProtocol())) {
                    logInfo("Direct connection established to " + state.targetHost + ":" + state.targetPort);
                    
                    try {
                        // Configure socket for optimal SSL/TLS handling
                        Socket socket = proxyChannel.socket();
                        
                        // Increase buffer sizes substantially for SSL/TLS data
                        int largeBuffer = Math.max(bufferSize * 4, 262144); // At least 256KB
                        socket.setReceiveBufferSize(largeBuffer);
                        socket.setSendBufferSize(largeBuffer);
                        
                        // Performance tuning
                        socket.setTcpNoDelay(true);
                        socket.setKeepAlive(true);
                        socket.setSoTimeout(0);
                        socket.setPerformancePreferences(0, 1, 0);
                        
                        // Create larger buffers for this connection
                        state.inputBuffer = ByteBuffer.allocateDirect(262144);
                        state.outputBuffer = ByteBuffer.allocateDirect(262144);
                    } catch (Exception e) {
                        // Just log but continue - socket options are optimizations, not critical
                        logError("Error optimizing direct connection socket: " + e.getMessage());
                    }
                    
                    // Send success response based on SOCKS version
                    if (state.socksVersion == 5) {
                        sendSocks5SuccessResponse(clientChannel);
                    } else {
                        sendSocks4SuccessResponse(clientChannel);
                    }
                    
                    // Update state to connected
                    state.stage = ConnectionStage.PROXY_CONNECTED;
                    
                    // Register for reading
                    proxyChannel.register(selector, SelectionKey.OP_READ);
                    
                    return;
                }
                
                // Regular proxy connection logic continues here
                // Register for reading from the proxy
                proxyChannel.register(selector, SelectionKey.OP_READ);
                
                // Setup the SOCKS handshake with the proxy
                if (state.selectedProxy.getProtocolVersion() == 5) {
                    // SOCKS5 proxy handshake
                    ByteBuffer handshake;
                    
                    if (state.selectedProxy.isAuthenticated()) {
                        // We support both no-auth (0x00) and username/password (0x02)
                        handshake = ByteBuffer.allocate(4);
                        handshake.put((byte) 0x05); // SOCKS version
                        handshake.put((byte) 0x02); // 2 auth methods
                        handshake.put((byte) 0x00); // No auth
                        handshake.put((byte) 0x02); // Username/password auth
                    } else {
                        // Only support no-auth
                        handshake = ByteBuffer.allocate(3);
                        handshake.put((byte) 0x05); // SOCKS version
                        handshake.put((byte) 0x01); // 1 auth method
                        handshake.put((byte) 0x00); // No auth
                    }
                    
                    handshake.flip();
                    proxyChannel.write(handshake);
                    state.stage = ConnectionStage.SOCKS5_AUTH;
                } else {
                    // SOCKS4 proxy handshake directly sending the connect
                    ByteBuffer request = createSocks4ConnectRequest(state.targetHost, state.targetPort);
                    proxyChannel.write(request);
                    state.stage = ConnectionStage.SOCKS4_CONNECT;
                }
                
                logInfo("Proxy connection established to " + 
                       state.selectedProxy.getProtocol() + "://" + 
                       state.selectedProxy.getHost() + ":" + 
                       state.selectedProxy.getPort());
            }
        } catch (IOException e) {
            logError("Connection failed: " + e.getMessage());
            
            // Find the associated client channel and inform about the error
            for (Map.Entry<SocketChannel, SocketChannel> entry : proxyConnections.entrySet()) {
                if (entry.getValue() == proxyChannel) {
                    SocketChannel clientChannel = entry.getKey();
                    ConnectionState state = connectionStates.get(clientChannel);
                    
                    if (state != null) {
                        ProxyEntry proxy = state.selectedProxy;
                        
                        // Check if this was a direct connection attempt
                        if (proxy != null && "direct".equals(proxy.getProtocol())) {
                            logError("Direct connection to " + state.targetHost + " failed, falling back to proxy");
                            
                            // Remove the direct proxy connection
                            proxyConnections.remove(clientChannel);
                            
                            // Try connecting through a regular proxy as fallback
                            try {
                                connectThroughProxy(clientChannel, state);
                                // If we get here, the proxy connection is being established
                                return;
                            } catch (IOException ex) {
                                logError("Fallback to proxy also failed: " + ex.getMessage());
                                // Fall through to send error response and close
                            }
                        } else if (proxy != null) {
                            // Regular proxy failure
                            // Notify extension about proxy failure
                            if (extension != null) {
                                extension.notifyProxyFailure(proxy.getHost(), proxy.getPort(), e.getMessage());
                            }
                        }
                        
                        // Send error response based on SOCKS version
                        if (state.socksVersion == 5) {
                            sendSocks5ErrorResponse(clientChannel, (byte) 1); // General failure
                        } else {
                            sendSocks4ErrorResponse(clientChannel, (byte) 91); // Rejected
                        }
                    }
                    
                    // Close the client connection
                    cancelAndCloseChannel(clientChannel);
                    break;
                }
            }
            
            // Close the proxy channel
            cancelAndCloseChannel(proxyChannel);
        }
    }
    
    /**
     * Connects to the target through a proxy (used as fallback when direct connection fails)
     */
    private void connectThroughProxy(SocketChannel clientChannel, ConnectionState state) throws IOException {
        // Choose a proxy using the rotation mechanism
        ProxyEntry proxy = selectRandomActiveProxy();
        
        if (proxy == null) {
            logError("No active proxies available for fallback");
            throw new IOException("No active proxies available");
        }
        
        String proxyKey = proxy.getHost() + ":" + proxy.getPort();
        
        // Log the fallback
        logInfo("Fallback: Using proxy " + proxy.getProtocol() + "://" + proxyKey + 
                " for target: " + state.targetHost + ":" + state.targetPort);
        
        // Increment connection counter
        connectionsPerProxy.computeIfAbsent(proxyKey, _ -> new AtomicInteger(0)).incrementAndGet();
        
        // Save the selected proxy
        state.selectedProxy = proxy;
        
        // Create and configure the proxy socket channel
        SocketChannel proxyChannel = SocketChannel.open();
        proxyChannel.configureBlocking(false);
        Socket proxySocket = proxyChannel.socket();
        
        // Set socket options
        proxySocket.setTcpNoDelay(true);
        
        // Associate the channels
        proxyConnections.put(clientChannel, proxyChannel);
        
        // Connect to the proxy
        boolean connected = proxyChannel.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()));
        
        // Register for connect completion
        proxyChannel.register(selector, SelectionKey.OP_CONNECT);
        
        if (connected) {
            // Connection completed immediately, simulate a connect event
            SelectionKey key = proxyChannel.keyFor(selector);
            handleConnect(key);
        }
    }
    
    /**
     * Handles a read event on a socket.
     */
    private void handleRead(SelectionKey key) throws IOException {
        SocketChannel channel = (SocketChannel) key.channel();
        lastActivityTime.put(channel, System.currentTimeMillis());
        
        // Determine if this is a client or proxy channel
        if (connectionStates.containsKey(channel)) {
            // This is a client channel
            handleClientRead(key, channel);
        } else {
            // This is a proxy channel
            handleProxyRead(key, channel);
        }
    }
    
    /**
     * Handles a read event from a client.
     */
    private void handleClientRead(SelectionKey key, SocketChannel clientChannel) throws IOException {
        ConnectionState state = connectionStates.get(clientChannel);
        
        if (state == null) {
            logError("No state found for client read");
            cancelAndCloseKey(key);
            return;
        }
        
        ByteBuffer buffer = state.inputBuffer;
        buffer.clear();
        
        int bytesRead;
        try {
            bytesRead = clientChannel.read(buffer);
        } catch (IOException e) {
            logError("Error reading from client: " + e.getMessage());
            closeConnection(clientChannel);
            return;
        }
        
        if (bytesRead == -1) {
            // Connection closed by client
            logInfo("Client closed connection");
            closeConnection(clientChannel);
            return;
        } else if (bytesRead == 0) {
            // No data read
            return;
        }
        
        // Process the data based on the current connection stage
        buffer.flip();
        
        switch (state.stage) {
            case INITIAL:
                processInitialClientData(clientChannel, state, buffer);
                break;
                
            case SOCKS5_CONNECT:
                processSocks5ConnectRequest(clientChannel, state, buffer);
                break;
                
            case PROXY_CONNECTED:
                // Forward data to the proxy
                SocketChannel proxyChannel = proxyConnections.get(clientChannel);
                if (proxyChannel != null && proxyChannel.isConnected()) {
                    // Check if this is a direct connection to a Collaborator domain
                    if (state.selectedProxy != null && "direct".equals(state.selectedProxy.getProtocol())) {
                        // For direct connections (especially HTTPS), we need to ensure efficient data handling
                        try {
                            // For TLS traffic, make sure we're writing all data in a single call if possible
                            int totalBytesToWrite = buffer.remaining();
                            if (totalBytesToWrite > 0) {
                                logInfo("Forwarding " + totalBytesToWrite + " bytes from client to direct connection");
                                
                                // Attempt to write all data at once for efficiency
                                int written = proxyChannel.write(buffer);
                                
                                // If we couldn't write everything at once, keep trying
                                if (buffer.hasRemaining()) {
                                    logInfo("Couldn't write all data at once, remaining: " + buffer.remaining());
                                    
                                    // Register for write interest to send remaining data
                                    SelectionKey proxyKey = proxyChannel.keyFor(selector);
                                    if (proxyKey != null && proxyKey.isValid()) {
                                        // Create a new buffer with remaining data
                                        ByteBuffer remainingData = ByteBuffer.allocateDirect(buffer.remaining());
                                        remainingData.put(buffer);
                                        remainingData.flip();
                                        
                                        // Store the remaining data with the connection state
                                        state.outputBuffer = remainingData;
                                        
                                        // Enable write interest
                                        proxyKey.interestOps(proxyKey.interestOps() | SelectionKey.OP_WRITE);
                                    }
                                }
                            }
                        } catch (IOException e) {
                            logError("Error forwarding data to direct connection: " + e.getMessage());
                            closeConnection(clientChannel);
                        }
                    } else {
                        // Regular proxy forwarding
                        ByteBuffer forwardBuffer = ByteBuffer.allocate(buffer.remaining());
                        forwardBuffer.put(buffer);
                        forwardBuffer.flip();
                        
                        while (forwardBuffer.hasRemaining()) {
                            proxyChannel.write(forwardBuffer);
                        }
                    }
                }
                break;
                
            default:
                logError("Unexpected client data in state: " + state.stage);
                cancelAndCloseChannel(clientChannel);
                break;
        }
    }
    
    /**
     * Handles a read event from a proxy.
     */
    private void handleProxyRead(SelectionKey key, SocketChannel proxyChannel) throws IOException {
        // Find the associated client channel
        SocketChannel clientChannel = null;
        for (Map.Entry<SocketChannel, SocketChannel> entry : proxyConnections.entrySet()) {
            if (entry.getValue() == proxyChannel) {
                clientChannel = entry.getKey();
                break;
            }
        }
        
        if (clientChannel == null) {
            logError("No client found for proxy read");
            cancelAndCloseKey(key);
            return;
        }
        
        ConnectionState state = connectionStates.get(clientChannel);
        if (state == null) {
            logError("No state found for proxy read");
            cancelAndCloseKey(key);
            return;
        }
        
        // Use a shared buffer for better performance and less garbage collection
        ByteBuffer buffer = state.inputBuffer;
        buffer.clear();
        
        int bytesRead;
        try {
            bytesRead = proxyChannel.read(buffer);
        } catch (IOException e) {
            logError("Error reading from proxy/direct: " + e.getMessage());
            closeConnection(clientChannel);
            return;
        }
        
        if (bytesRead == -1) {
            // Connection closed by proxy
            logInfo("Proxy/direct connection closed");
            closeConnection(clientChannel);
            return;
        } else if (bytesRead == 0) {
            // No data read
            return;
        }
        
        buffer.flip();
        
        // Process based on the current connection stage
        switch (state.stage) {
            case SOCKS5_AUTH:
                processSocks5AuthResponse(clientChannel, proxyChannel, state, buffer, false);
                break;
                
            case SOCKS5_AUTH_RESPONSE:
                processSocks5AuthResponse(clientChannel, proxyChannel, state, buffer, true);
                break;
                
            case SOCKS5_CONNECT:
                processSocks5ConnectResponse(clientChannel, proxyChannel, state, buffer);
                break;
                
            case SOCKS4_CONNECT:
                processSocks4ConnectResponse(clientChannel, proxyChannel, state, buffer);
                break;
                
            case PROXY_CONNECTED:
                // Forward data to client
                forwardDataToClient(clientChannel, state, buffer);
                break;
                
            default:
                logError("Unexpected proxy data in state: " + state.stage);
                closeConnection(clientChannel);
                break;
        }
    }
    
    /**
     * Forward data from a proxy/direct connection to a client
     */
    private void forwardDataToClient(SocketChannel clientChannel, ConnectionState state, 
                                    ByteBuffer buffer) throws IOException {
        // Check if this is a direct connection to a Collaborator domain
        if (state.selectedProxy != null && "direct".equals(state.selectedProxy.getProtocol())) {
            // For HTTPS or other SSL/TLS traffic, handle larger chunks efficiently
            try {
                int totalBytesToWrite = buffer.remaining();
                if (totalBytesToWrite > 0) {
                    logInfo("Forwarding " + totalBytesToWrite + " bytes from direct connection to client");
                    
                    // Attempt to write all data at once
                    int written = clientChannel.write(buffer);
                    
                    // If we couldn't write everything at once, keep trying
                    if (buffer.hasRemaining()) {
                        logInfo("Couldn't write all data at once to client, remaining: " + buffer.remaining());
                        
                        // Register for write interest to send remaining data
                        SelectionKey clientKey = clientChannel.keyFor(selector);
                        if (clientKey != null && clientKey.isValid()) {
                            // Create a new buffer with remaining data
                            ByteBuffer remainingData = ByteBuffer.allocateDirect(buffer.remaining());
                            remainingData.put(buffer);
                            remainingData.flip();
                            
                            // Store the remaining data with the connection state
                            state.outputBuffer = remainingData;
                            
                            // Enable write interest
                            clientKey.interestOps(clientKey.interestOps() | SelectionKey.OP_WRITE);
                        }
                    }
                }
            } catch (IOException e) {
                logError("Error forwarding data from direct connection: " + e.getMessage());
                closeConnection(clientChannel);
            }
        } else {
            // Regular proxy forwarding without creating additional buffers
            try {
                clientChannel.write(buffer);
            } catch (IOException e) {
                logError("Error writing to client: " + e.getMessage());
                closeConnection(clientChannel);
            }
        }
    }
    
    /**
     * Handles a write event on a socket.
     */
    private void handleWrite(SelectionKey key) throws IOException {
        SocketChannel channel = (SocketChannel) key.channel();
        lastActivityTime.put(channel, System.currentTimeMillis());
        
        // Determine if this is a client or proxy channel
        ConnectionState state = null;
        ByteBuffer pendingData = null;
        
        if (connectionStates.containsKey(channel)) {
            // This is a client channel
            state = connectionStates.get(channel);
            if (state != null) {
                pendingData = state.outputBuffer;
            }
        } else {
            // This is a proxy channel - find the associated client
            SocketChannel clientChannel = null;
            for (Map.Entry<SocketChannel, SocketChannel> entry : proxyConnections.entrySet()) {
                if (entry.getValue() == channel) {
                    clientChannel = entry.getKey();
                    break;
                }
            }
            
            if (clientChannel != null) {
                state = connectionStates.get(clientChannel);
                if (state != null) {
                    pendingData = state.outputBuffer;
                }
            }
        }
        
        // If we have pending data, write it
        if (state != null && pendingData != null && pendingData.hasRemaining()) {
            try {
                int written = channel.write(pendingData);
                logInfo("Wrote " + written + " bytes to channel, remaining: " + pendingData.remaining());
                
                // If we've written all data, clear write interest
                if (!pendingData.hasRemaining()) {
                    // Clear the buffer
                    state.outputBuffer = ByteBuffer.allocateDirect(state.outputBuffer.capacity());
                    
                    // Remove write interest, keep read interest
                    key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                }
            } catch (IOException e) {
                logError("Error writing to channel: " + e.getMessage());
                
                // Clear write interest
                key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                
                // If this is a proxy channel, close the associated client connection
                if (!connectionStates.containsKey(channel)) {
                    for (Map.Entry<SocketChannel, SocketChannel> entry : proxyConnections.entrySet()) {
                        if (entry.getValue() == channel) {
                            closeConnection(entry.getKey());
                            break;
                        }
                    }
                } else {
                    // Close this connection
                    closeConnection(channel);
                }
            }
        } else {
            // No pending data, clear write interest
            key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
        }
    }
    
    /**
     * Process the initial data from a client to determine SOCKS protocol version.
     */
    private void processInitialClientData(SocketChannel clientChannel, ConnectionState state, ByteBuffer buffer) throws IOException {
        if (buffer.remaining() == 0) {
            return;
        }
        
        // Check the first byte to determine SOCKS version
        byte version = buffer.get();
        
        if (version == 5) {
            // SOCKS5 - handle the greeting
            state.socksVersion = 5;
            
            if (buffer.remaining() < 1) {
                return; // Need more data
            }
            
            int numMethods = buffer.get() & 0xFF;
            
            if (buffer.remaining() < numMethods) {
                return; // Need more data
            }
            
            // Skip the auth methods - we only support no auth (0)
            for (int i = 0; i < numMethods; i++) {
                buffer.get();
            }
            
            // Send authentication method response (0 = no auth)
            ByteBuffer response = ByteBuffer.allocate(2);
            response.put((byte) 5);  // SOCKS version
            response.put((byte) 0);  // No auth method
            response.flip();
            
            clientChannel.write(response);
            
            // Update state to wait for connect request
            state.stage = ConnectionStage.SOCKS5_CONNECT;
            
        } else if (version == 4) {
            // SOCKS4 - handle the connect request directly
            state.socksVersion = 4;
            
            if (buffer.remaining() < 1) {
                return; // Need more data
            }
            
            byte command = buffer.get();
            
            if (command != 1) {
                // Only support CONNECT command
                sendSocks4ErrorResponse(clientChannel, (byte) 91);
                closeConnection(clientChannel);
                return;
            }
            
            if (buffer.remaining() < 6) {
                return; // Need more data
            }
            
            // Read port (2 bytes, big endian)
            int targetPort = ((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF);
            
            // Read IPv4 address (4 bytes)
            byte[] ipv4 = new byte[4];
            buffer.get(ipv4);
            
            String targetHost;
            
            if (ipv4[0] == 0 && ipv4[1] == 0 && ipv4[2] == 0 && ipv4[3] != 0) {
                // SOCKS4A - domain name follows
                // Skip the user ID
                while (buffer.hasRemaining() && buffer.get() != 0) {
                    // Skip to null terminator
                }
                
                // Read domain name
                StringBuilder domain = new StringBuilder();
                while (buffer.hasRemaining()) {
                    byte b = buffer.get();
                    if (b == 0) break;
                    domain.append((char) b);
                }
                
                targetHost = domain.toString();
            } else {
                // Regular SOCKS4 - IPv4 address
                targetHost = (ipv4[0] & 0xFF) + "." + (ipv4[1] & 0xFF) + "." + 
                            (ipv4[2] & 0xFF) + "." + (ipv4[3] & 0xFF);
                
                // Skip the user ID
                while (buffer.hasRemaining() && buffer.get() != 0) {
                    // Skip to null terminator
                }
            }
            
            // Save target information
            state.targetHost = targetHost;
            state.targetPort = targetPort;
            state.addressType = 1; // IPv4 type
            
            // Connect to the target through a random proxy
            connectToTarget(clientChannel, state);
        } else {
            // Unsupported SOCKS version
            logError("Unsupported SOCKS version: " + version);
            closeConnection(clientChannel);
        }
    }
    
    /**
     * Process a SOCKS5 CONNECT request.
     */
    private void processSocks5ConnectRequest(SocketChannel clientChannel, ConnectionState state, ByteBuffer buffer) throws IOException {
        if (buffer.remaining() < 4) {
            return; // Need more data
        }
        
        // Read the SOCKS5 command request
        byte version = buffer.get();
        if (version != 5) {
            logError("Invalid SOCKS5 request version");
            closeConnection(clientChannel);
            return;
        }
        
        byte command = buffer.get();
        if (command != 1) {
            // Only support CONNECT command
            sendSocks5ErrorResponse(clientChannel, (byte) 7); // Command not supported
            closeConnection(clientChannel);
            return;
        }
        
        // Skip reserved byte
        buffer.get();
        
        // Read address type
        byte addressType = buffer.get();
        state.addressType = addressType;
        
        String targetHost;
        int targetPort;
        
        switch (addressType) {
            case 1: // IPv4
                if (buffer.remaining() < 6) {
                    return; // Need more data
                }
                
                byte[] ipv4 = new byte[4];
                buffer.get(ipv4);
                targetHost = (ipv4[0] & 0xFF) + "." + (ipv4[1] & 0xFF) + "." + 
                            (ipv4[2] & 0xFF) + "." + (ipv4[3] & 0xFF);
                break;
                
            case 3: // Domain name
                if (buffer.remaining() < 1) {
                    return; // Need more data
                }
                
                int domainLength = buffer.get() & 0xFF;
                
                if (buffer.remaining() < domainLength + 2) {
                    return; // Need more data
                }
                
                byte[] domain = new byte[domainLength];
                buffer.get(domain);
                targetHost = new String(domain);
                break;
                
            case 4: // IPv6
                if (buffer.remaining() < 18) {
                    return; // Need more data
                }
                
                byte[] ipv6 = new byte[16];
                buffer.get(ipv6);
                
                // Format IPv6 address
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 16; i += 2) {
                    if (i > 0) sb.append(":");
                    sb.append(String.format("%02x%02x", ipv6[i], ipv6[i+1]));
                }
                targetHost = sb.toString();
                break;
                
            default:
                sendSocks5ErrorResponse(clientChannel, (byte) 8); // Address type not supported
                closeConnection(clientChannel);
                return;
        }
        
        // Read port (2 bytes, big endian)
        targetPort = ((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF);
        
        // Save target information
        state.targetHost = targetHost;
        state.targetPort = targetPort;
        
        // Connect to the target through a random proxy
        connectToTarget(clientChannel, state);
    }

    /**
     * Checks if a domain should bypass proxying.
     */
    private boolean shouldBypassProxy(String domain) {
        if (!bypassCollaborator || domain == null) {
            return false;
        }
        
        // Always log bypassing attempts for debugging
        logInfo("Checking if domain should bypass proxy: " + domain);
        
        // Check if domain matches or is a subdomain of any bypass domain
        for (String bypassDomain : bypassDomains) {
            if (domain.equals(bypassDomain) || domain.endsWith("." + bypassDomain)) {
                logInfo("Bypassing proxy for domain: " + domain);
                return true;
            }
        }
        
        return false;
    }

    /**
     * Connect to the target through a selected proxy with guaranteed rotation.
     */
    private void connectToTarget(SocketChannel clientChannel, ConnectionState state) throws IOException {
        // Check if the target domain should bypass the proxy
        if (bypassCollaborator && shouldBypassProxy(state.targetHost)) {
            // Connect directly to the target
            try {
                logInfo("Setting up direct connection to " + state.targetHost + ":" + state.targetPort);
                
                // Create a fake proxy entry for tracking with special flag
                ProxyEntry directProxy = ProxyEntry.createDirect(state.targetHost, state.targetPort);
                state.selectedProxy = directProxy;
                
                // Create and configure direct socket channel
                SocketChannel directChannel = SocketChannel.open();
                directChannel.configureBlocking(false);
                Socket directSocket = directChannel.socket();
                
                // Enhanced socket configuration for SSL/TLS
                directSocket.setTcpNoDelay(true);
                directSocket.setKeepAlive(true);
                directSocket.setSoTimeout(0); // No timeout for HTTPS handshakes
                
                // Increase buffer sizes substantially for SSL/TLS data
                int largeBuffer = Math.max(bufferSize * 4, 262144); // At least 256KB
                directSocket.setReceiveBufferSize(largeBuffer);
                directSocket.setSendBufferSize(largeBuffer);
                
                // Disable Nagle's algorithm for better SSL performance
                directSocket.setTcpNoDelay(true);
                
                // Set performance preferences
                directSocket.setPerformancePreferences(0, 1, 0); // Prioritize latency over bandwidth
                
                // Associate the channels
                proxyConnections.put(clientChannel, directChannel);
                
                // Connect directly to the target
                logInfo("Initiating direct connection to " + state.targetHost + ":" + state.targetPort);
                
                boolean connected = directChannel.connect(new InetSocketAddress(state.targetHost, state.targetPort));
                
                // If connected immediately, we need to handle the response appropriately
                if (connected) {
                    // Send success response based on SOCKS version
                    if (state.socksVersion == 5) {
                        sendSocks5SuccessResponse(clientChannel);
                    } else {
                        sendSocks4SuccessResponse(clientChannel);
                    }
                    
                    // Update state to connected
                    state.stage = ConnectionStage.PROXY_CONNECTED;
                    
                    // For direct connections, especially HTTPS, allocate larger buffers
                    state.inputBuffer = ByteBuffer.allocateDirect(262144); // 256KB
                    state.outputBuffer = ByteBuffer.allocateDirect(262144);
                    
                    // Register for reading
                    directChannel.register(selector, SelectionKey.OP_READ);
                    
                    logInfo("Direct connection established immediately to " + state.targetHost + ":" + state.targetPort);
                } else {
                    // Register for connect completion
                    directChannel.register(selector, SelectionKey.OP_CONNECT);
                    logInfo("Direct connection pending to " + state.targetHost + ":" + state.targetPort);
                }
                
                return;
            } catch (IOException e) {
                logError("Error connecting directly to " + state.targetHost + ": " + e.getMessage());
                // Fall through to use proxy if direct connection fails
            }
        }
        
        // Original proxy connection logic
        // Choose a proxy using the rotation mechanism
        ProxyEntry proxy = selectRandomActiveProxy();
        
        if (proxy == null) {
            logError("No active proxies available");
            if (state.socksVersion == 5) {
                sendSocks5ErrorResponse(clientChannel, (byte) 1);
            } else {
                sendSocks4ErrorResponse(clientChannel, (byte) 91);
            }
            closeConnection(clientChannel);
            return;
        }
        
        String proxyKey = proxy.getHost() + ":" + proxy.getPort();
        
        // Always log the proxy being used for this connection
        logInfo("Using proxy: " + proxy.getProtocol() + "://" + proxyKey + 
                " for target: " + state.targetHost + ":" + state.targetPort);
        
        // Increment connection counter
        connectionsPerProxy.computeIfAbsent(proxyKey, _ -> new AtomicInteger(0)).incrementAndGet();
        
        // Save the selected proxy
        state.selectedProxy = proxy;
        
        try {
            // Create and configure the proxy socket channel
            SocketChannel proxyChannel = SocketChannel.open();
            proxyChannel.configureBlocking(false);
            Socket proxySocket = proxyChannel.socket();
            
            // Set socket options
            proxySocket.setTcpNoDelay(true);
            
            // Associate the channels
            proxyConnections.put(clientChannel, proxyChannel);
            
            // Connect to the proxy
            boolean connected = proxyChannel.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()));
            
            // Register for connect completion
            proxyChannel.register(selector, SelectionKey.OP_CONNECT);
            
            if (connected) {
                // Connection completed immediately, simulate a connect event
                SelectionKey key = proxyChannel.keyFor(selector);
                handleConnect(key);
            }
            
        } catch (IOException e) {
            logError("Error connecting to proxy " + proxyKey + ": " + e.getMessage());
            
            // Clean up on error
            AtomicInteger count = connectionsPerProxy.get(proxyKey);
            if (count != null) {
                count.decrementAndGet();
            }
            
            // Send error response
            if (state.socksVersion == 5) {
                sendSocks5ErrorResponse(clientChannel, (byte) 1);
            } else {
                sendSocks4ErrorResponse(clientChannel, (byte) 91);
            }
            
            closeConnection(clientChannel);
        }
    }
    
    /**
     * Process a SOCKS5 authentication response from the proxy.
     */
    private void processSocks5AuthResponse(SocketChannel clientChannel, SocketChannel proxyChannel, 
                                        ConnectionState state, ByteBuffer buffer, boolean isAuthResponse) throws IOException {
        if (isAuthResponse) {
            // This is a response to username/password authentication
            if (buffer.remaining() < 2) {
                return; // Need more data
            }
            
            byte authVersion = buffer.get();
            byte authStatus = buffer.get();
            
            if (authVersion != 1) {
                logError("Invalid SOCKS5 auth version: " + authVersion);
                sendSocks5ErrorResponse(clientChannel, (byte) 1);
                closeConnection(clientChannel);
                return;
            }
            
            if (authStatus != 0) {
                // Authentication failed
                logError("SOCKS5 authentication failed with status: " + authStatus);
                sendSocks5ErrorResponse(clientChannel, (byte) 1); // General failure
                closeConnection(clientChannel);
                return;
            }
            
            // Authentication succeeded, send connection request
            logInfo("SOCKS5 authentication successful");
            sendSocks5ConnectRequest(proxyChannel, state);
        } else {
            // Normal auth method selection
            if (buffer.remaining() < 2) {
                return; // Need more data
            }
            
            byte version = buffer.get();
            byte method = buffer.get();
            
            if (version != 5) {
                logError("Invalid SOCKS5 version in auth response: " + version);
                sendSocks5ErrorResponse(clientChannel, (byte) 1);
                closeConnection(clientChannel);
                return;
            }
            
            // Handle authentication based on the selected method
            if (method == 0) {
                // No authentication required
                logInfo("SOCKS5 proxy accepted no-auth method");
                sendSocks5ConnectRequest(proxyChannel, state);
            } else if (method == 2 && state.selectedProxy.isAuthenticated()) {
                // Username/password authentication required
                logInfo("SOCKS5 proxy requested username/password authentication");
                
                // Send username/password authentication
                byte[] usernameBytes = state.selectedProxy.getUsername().getBytes();
                byte[] passwordBytes = state.selectedProxy.getPassword().getBytes();
                
                // Auth request: version 1, username len, username, password len, password
                ByteBuffer authRequest = ByteBuffer.allocate(3 + usernameBytes.length + passwordBytes.length);
                authRequest.put((byte) 1); // Auth subversion
                authRequest.put((byte) usernameBytes.length);
                authRequest.put(usernameBytes);
                authRequest.put((byte) passwordBytes.length);
                authRequest.put(passwordBytes);
                authRequest.flip();
                
                proxyChannel.write(authRequest);
                
                // Update state to wait for auth response
                state.stage = ConnectionStage.SOCKS5_AUTH_RESPONSE;
            } else {
                // Authentication method not supported
                logError("SOCKS5 proxy authentication method not supported or credentials missing: " + method);
                sendSocks5ErrorResponse(clientChannel, (byte) 1);
                closeConnection(clientChannel);
            }
        }
    }
    
    /**
     * Process a SOCKS5 connect response from the proxy.
     */
    private void processSocks5ConnectResponse(SocketChannel clientChannel, SocketChannel proxyChannel, 
                                           ConnectionState state, ByteBuffer buffer) throws IOException {
        if (buffer.remaining() < 4) {
            return; // Need more data
        }
        
        byte version = buffer.get();
        byte status = buffer.get();
        
        // Skip reserved byte
        buffer.get();
        
        // Read bound address type
        byte boundType = buffer.get();
        
        // Skip address and port based on type
        int skipBytes = 0;
        switch (boundType) {
            case 1: // IPv4
                skipBytes = 4 + 2; // IPv4 + port
                break;
            case 3: // Domain
                if (buffer.remaining() < 1) {
                    return; // Need more data
                }
                skipBytes = (buffer.get() & 0xFF) + 2; // Domain length + port
                break;
            case 4: // IPv6
                skipBytes = 16 + 2; // IPv6 + port
                break;
            default:
                logError("Invalid address type in SOCKS5 response: " + boundType);
                closeConnection(clientChannel);
                return;
        }
        
        // Skip the remaining data if we have enough
        if (buffer.remaining() < skipBytes) {
            return; // Need more data
        }
        for (int i = 0; i < skipBytes; i++) {
            buffer.get();
        }
        
        if (version != 5) {
            logError("Invalid SOCKS5 response version: " + version);
            closeConnection(clientChannel);
            return;
        }
        
        if (status != 0) {
            // Connection failed
            logError("SOCKS5 connection failed with status: " + status);
            sendSocks5ErrorResponse(clientChannel, status);
            closeConnection(clientChannel);
            return;
        }
        
        // Connection successful
        sendSocks5SuccessResponse(clientChannel);
        
        // Update state to connected
        state.stage = ConnectionStage.PROXY_CONNECTED;
        
        // If there's any remaining data, forward it to the client
        if (buffer.hasRemaining()) {
            clientChannel.write(buffer);
        }
    }
    
    /**
     * Process a SOCKS4 connect response from the proxy.
     */
    private void processSocks4ConnectResponse(SocketChannel clientChannel, SocketChannel proxyChannel, 
                                           ConnectionState state, ByteBuffer buffer) throws IOException {
        if (buffer.remaining() < 8) {
            return; // Need more data
        }
        
        byte nullByte = buffer.get();
        byte status = buffer.get();
        
        // Skip the rest of the response (port and IP)
        for (int i = 0; i < 6; i++) {
            buffer.get();
        }
        
        if (nullByte != 0) {
            logError("Invalid SOCKS4 response format");
            closeConnection(clientChannel);
            return;
        }
        
        if (status != 90) {
            // Connection failed
            logError("SOCKS4 connection failed with status: " + status);
            sendSocks4ErrorResponse(clientChannel, status);
            closeConnection(clientChannel);
            return;
        }
        
        // Connection successful
        sendSocks4SuccessResponse(clientChannel);
        
        // Update state to connected
        state.stage = ConnectionStage.PROXY_CONNECTED;
        
        // If there's any remaining data, forward it to the client
        if (buffer.hasRemaining()) {
            clientChannel.write(buffer);
        }
    }
    
    /**
     * Create a SOCKS4 connection request.
     */
    private ByteBuffer createSocks4ConnectRequest(String targetHost, int targetPort) {
        ByteBuffer request;
        
        // Check if targetHost is an IP address
        String[] ipParts = targetHost.split("\\.");
        if (ipParts.length == 4) {
            // Regular SOCKS4
            request = ByteBuffer.allocate(9);
            request.put((byte) 4); // SOCKS version
            request.put((byte) 1); // CONNECT command
            request.put((byte) ((targetPort >> 8) & 0xFF)); // Port high byte
            request.put((byte) (targetPort & 0xFF)); // Port low byte
            
            // IP address
            for (String part : ipParts) {
                request.put((byte) (Integer.parseInt(part) & 0xFF));
            }
            
            // Null-terminated user ID
            request.put((byte) 0);
        } else {
            // SOCKS4A with domain name
            byte[] domain = targetHost.getBytes();
            request = ByteBuffer.allocate(10 + domain.length);
            request.put((byte) 4); // SOCKS version
            request.put((byte) 1); // CONNECT command
            request.put((byte) ((targetPort >> 8) & 0xFF)); // Port high byte
            request.put((byte) (targetPort & 0xFF)); // Port low byte
            request.put((byte) 0); // 0.0.0.x for SOCKS4A
            request.put((byte) 0);
            request.put((byte) 0);
            request.put((byte) 1); // Non-zero value
            request.put((byte) 0); // Null-terminated user ID
            
            // Domain name
            request.put(domain);
            request.put((byte) 0); // Null-terminate domain
        }
        
        request.flip();
        return request;
    }
    
    /**
     * Send a SOCKS5 error response to the client.
     */
    private void sendSocks5ErrorResponse(SocketChannel channel, byte errorCode) {
        try {
            ByteBuffer response = ByteBuffer.allocate(10);
            response.put((byte) 5);  // SOCKS version
            response.put(errorCode); // Error code
            response.put((byte) 0);  // Reserved
            response.put((byte) 1);  // Address type (IPv4)
            
            // IP address (0.0.0.0)
            response.put((byte) 0);
            response.put((byte) 0);
            response.put((byte) 0);
            response.put((byte) 0);
            
            // Port (0)
            response.put((byte) 0);
            response.put((byte) 0);
            
            response.flip();
            channel.write(response);
        } catch (IOException e) {
            logError("Error sending SOCKS5 error response: " + e.getMessage());
        }
    }
    
    /**
     * Send a SOCKS5 success response to the client.
     */
    private void sendSocks5SuccessResponse(SocketChannel channel) {
        try {
            ByteBuffer response = ByteBuffer.allocate(10);
            response.put((byte) 5);  // SOCKS version
            response.put((byte) 0);  // Success
            response.put((byte) 0);  // Reserved
            response.put((byte) 1);  // Address type (IPv4)
            
            // IP address (0.0.0.0)
            response.put((byte) 0);
            response.put((byte) 0);
            response.put((byte) 0);
            response.put((byte) 0);
            
            // Port (0)
            response.put((byte) 0);
            response.put((byte) 0);
            
            response.flip();
            channel.write(response);
        } catch (IOException e) {
            logError("Error sending SOCKS5 success response: " + e.getMessage());
        }
    }
    
    /**
     * Send a SOCKS4 error response to the client.
     */
    private void sendSocks4ErrorResponse(SocketChannel channel, byte errorCode) {
        try {
            ByteBuffer response = ByteBuffer.allocate(8);
            response.put((byte) 0);  // Null byte
            response.put(errorCode); // Error code
            
            // Port (0)
            response.put((byte) 0);
            response.put((byte) 0);
            
            // IP (0.0.0.0)
            response.put((byte) 0);
            response.put((byte) 0);
            response.put((byte) 0);
            response.put((byte) 0);
            
            response.flip();
            channel.write(response);
        } catch (IOException e) {
            logError("Error sending SOCKS4 error response: " + e.getMessage());
        }
    }
    
    /**
     * Send a SOCKS4 success response to the client.
     */
    private void sendSocks4SuccessResponse(SocketChannel channel) {
        try {
            ByteBuffer response = ByteBuffer.allocate(8);
            response.put((byte) 0);  // Null byte
            response.put((byte) 90); // Success
            
            // Port (0)
            response.put((byte) 0);
            response.put((byte) 0);
            
            // IP (0.0.0.0)
            response.put((byte) 0);
            response.put((byte) 0);
            response.put((byte) 0);
            response.put((byte) 0);
            
            response.flip();
            channel.write(response);
        } catch (IOException e) {
            logError("Error sending SOCKS4 success response: " + e.getMessage());
        }
    }

    /**
     * Closes a connection and cleans up resources.
     */
    private void closeConnection(SocketChannel clientChannel) {
        // Get the proxy channel if it exists
        SocketChannel proxyChannel = proxyConnections.remove(clientChannel);
        
        // Get the state
        ConnectionState state = connectionStates.remove(clientChannel);
        
        // Close the client channel
        cancelAndCloseChannel(clientChannel);
        
        // Close the proxy channel if it exists
        if (proxyChannel != null) {
            cancelAndCloseChannel(proxyChannel);
            
            // Update proxy connections counter
            if (state != null && state.selectedProxy != null) {
                String proxyKey = state.selectedProxy.getHost() + ":" + state.selectedProxy.getPort();
                AtomicInteger count = connectionsPerProxy.get(proxyKey);
                if (count != null) {
                    count.decrementAndGet();
                }
            }
        }
        
        // Remove from activity tracking
        lastActivityTime.remove(clientChannel);
        if (proxyChannel != null) {
            lastActivityTime.remove(proxyChannel);
        }
        
        // Update connection counter
        activeConnectionCount.decrementAndGet();
    }
    
    /**
     * Cancels a selection key and closes the channel.
     */
    private void cancelAndCloseKey(SelectionKey key) {
        if (key.channel() instanceof SocketChannel) {
            SocketChannel channel = (SocketChannel) key.channel();
            cancelAndCloseChannel(channel);
        }
        
        key.cancel();
    }
    
    /**
     * Cancels a channel's selection key and closes the channel.
     */
    private void cancelAndCloseChannel(SocketChannel channel) {
        try {
            // Cancel the selection key
            SelectionKey key = channel.keyFor(selector);
            if (key != null) {
                key.cancel();
            }
            
            // Close the channel
            if (channel.isOpen()) {
                channel.socket().setSoLinger(true, 0); // Force immediate close
                channel.close();
            }
        } catch (IOException e) {
            logError("Error closing channel: " + e.getMessage());
        }
    }
    
    /**
     * Cleans up idle connections and enforces connection rotation.
     */
    private void cleanupIdleConnections() {
        long currentTime = System.currentTimeMillis();
        long idleThreshold = idleTimeoutSec * 1000;
        int closedCount = 0;
        
        // More aggressive idle connection timeouts to force new proxy selections
        // We want to close connections even if they're still somewhat active
        // This helps ensure different proxies are used for different requests
        long moderatelyIdleThreshold = 10000; // 10 seconds - close moderately idle connections
        
        // Check client connections
        for (SocketChannel clientChannel : new ArrayList<>(lastActivityTime.keySet())) {
            Long lastActivity = lastActivityTime.get(clientChannel);
            
            if (lastActivity != null) {
                long idleTime = currentTime - lastActivity;
                
                // Close completely idle connections
                if (idleTime > idleThreshold) {
                    logInfo("Closing idle connection");
                    closeConnection(clientChannel);
                    closedCount++;
                }
                // Also close moderately idle connections to force rotation
                else if (idleTime > moderatelyIdleThreshold) {
                    ConnectionState state = connectionStates.get(clientChannel);
                    // Only close connections that are in connected state and have transferred data
                    if (state != null && state.stage == ConnectionStage.PROXY_CONNECTED) {
                        logInfo("Closing moderately idle connection to force rotation");
                        closeConnection(clientChannel);
                        closedCount++;
                    }
                }
            }
        }
        
        if (closedCount > 0) {
            logInfo("Closed " + closedCount + " connections to enforce proxy rotation");
        }
    }
    
    /**
     * Selects a different proxy for each request to ensure proper rotation.
     * Each call should return a different proxy than the previous call.
     */
    private ProxyEntry selectRandomActiveProxy() {
        // Fast path for empty proxy list
        if (proxyList.isEmpty()) {
            return null;
        }
        
        List<ProxyEntry> activeProxies = new ArrayList<>();
        
        // Get all active proxies
        proxyListLock.readLock().lock();
        try {
            // Collect ALL active proxies to ensure proper rotation
            for (ProxyEntry proxy : proxyList) {
                if (proxy.isActive()) {
                    activeProxies.add(proxy);
                }
            }
        } finally {
            proxyListLock.readLock().unlock();
        }
        
        if (activeProxies.isEmpty()) {
            return null;
        }
        
        // Ensure we get a different proxy than last time by incrementing the index
        synchronized (proxyRotationLock) {
            // Get the next proxy in sequence to ensure rotation
            lastProxyIndex = (lastProxyIndex + 1) % activeProxies.size();
            ProxyEntry selectedProxy = activeProxies.get(lastProxyIndex);
            
            // Log the selection to verify rotation
            logInfo("Rotating proxy: " + selectedProxy.getProtocol() + "://" + 
                  selectedProxy.getHost() + ":" + selectedProxy.getPort() + 
                  " (proxy " + (lastProxyIndex + 1) + " of " + activeProxies.size() + ")");
                  
            return selectedProxy;
        }
    }
    
    /**
     * Sets whether logging is enabled.
     */
    public void setLoggingEnabled(boolean enabled) {
        this.loggingEnabled = enabled;
        logInfo("Logging " + (enabled ? "enabled" : "disabled"));
    }

    /**
     * Logs an info message.
     */
    private void logInfo(String message) {
        if (loggingEnabled) {
            logging.logToOutput("[SocksProxy-NIO] " + message);
        }
    }

    /**
     * Logs an error message.
     */
    private void logError(String message) {
        if (loggingEnabled) {
            logging.logToError("[SocksProxy-NIO] ERROR: " + message);
        }
    }

    /**
     * Gets connection stats for each proxy.
     */
    public String getConnectionPoolStats() {
        if (!serverRunning) {
            return "Service not running";
        }
        
        StringBuilder stats = new StringBuilder();
        stats.append("Active connections: ").append(activeConnectionCount.get());
        
        if (!connectionsPerProxy.isEmpty()) {
            int activeProxyCount = 0;
            int maxConnectionsOnSingleProxy = 0;
            String busiestProxy = "";
            
            for (String proxyKey : connectionsPerProxy.keySet()) {
                int count = connectionsPerProxy.get(proxyKey).get();
                if (count > 0) {
                    activeProxyCount++;
                    if (count > maxConnectionsOnSingleProxy) {
                        maxConnectionsOnSingleProxy = count;
                        busiestProxy = proxyKey;
                    }
                }
            }
            
            // Add summary 
            stats.append(" | Using ")
                 .append(activeProxyCount)
                 .append(" proxies");
            
            if (maxConnectionsOnSingleProxy > 2) {
                stats.append(", busiest: ")
                     .append(busiestProxy)
                     .append("(")
                     .append(maxConnectionsOnSingleProxy)
                     .append(")");
            }
        }
        
        return stats.toString();
    }

    /**
     * Enables or disables bypassing proxies for Burp Collaborator domains.
     */
    public void setBypassCollaborator(boolean bypass) {
        this.bypassCollaborator = bypass;
        logInfo("Bypass for Collaborator domains " + (bypass ? "enabled" : "disabled"));
    }
    
    /**
     * Adds a custom domain to bypass proxy.
     */
    public void addBypassDomain(String domain) {
        if (!bypassDomains.contains(domain)) {
            bypassDomains.add(domain);
            logInfo("Added bypass domain: " + domain);
        }
    }
    
    /**
     * Removes a bypass domain.
     */
    public void removeBypassDomain(String domain) {
        if (bypassDomains.remove(domain)) {
            logInfo("Removed bypass domain: " + domain);
        }
    }
    
    /**
     * Clears all bypass domains.
     */
    public void clearBypassDomains() {
        bypassDomains.clear();
        logInfo("All bypass domains have been cleared");
    }

    /**
     * Send a SOCKS5 connect request to the proxy
     */
    private void sendSocks5ConnectRequest(SocketChannel proxyChannel, ConnectionState state) throws IOException {
        ByteBuffer request;
        
        if (state.addressType == 1) { // IPv4
            // Parse IPv4 address
            String[] octets = state.targetHost.split("\\.");
            if (octets.length != 4) {
                // Invalid IPv4 address
                return;
            }
            
            request = ByteBuffer.allocate(10);
            request.put((byte) 5); // SOCKS version
            request.put((byte) 1); // CONNECT command
            request.put((byte) 0); // Reserved
            request.put((byte) 1); // IPv4 address type
            
            for (String octet : octets) {
                request.put((byte) (Integer.parseInt(octet) & 0xFF));
            }
            
        } else if (state.addressType == 4) { // IPv6
            // Not fully implemented in this example
            request = ByteBuffer.allocate(22);
            request.put((byte) 5);
            request.put((byte) 1);
            request.put((byte) 0);
            request.put((byte) 4);
            
            // This is a simplified implementation
            // Add proper IPv6 parsing for production
            for (int i = 0; i < 16; i++) {
                request.put((byte) 0);
            }
            
        } else { // Domain name
            byte[] domain = state.targetHost.getBytes();
            request = ByteBuffer.allocate(7 + domain.length);
            request.put((byte) 5);
            request.put((byte) 1);
            request.put((byte) 0);
            request.put((byte) 3);
            request.put((byte) domain.length);
            request.put(domain);
        }
        
        // Set port (big endian)
        request.put((byte) ((state.targetPort >> 8) & 0xFF));
        request.put((byte) (state.targetPort & 0xFF));
        
        request.flip();
        proxyChannel.write(request);
        
        // Update state
        state.stage = ConnectionStage.SOCKS5_CONNECT;
    }
} 