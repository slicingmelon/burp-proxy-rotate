/**
 * Burp Proxy Rotate
 * Author: slicingmelon 
 * https://github.com/slicingmelon
 * https://x.com/pedro_infosec
 * 
 * This burp extension routes each HTTP request through a different proxy from a provided list.
 */
package slicingmelon.burpproxyrotate;

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
import java.nio.BufferOverflowException;

/**
 * The core service that randomly rotates each HTTP request through a different proxy from a provided list.
 */
public class ProxyRotateService {
    // Default settings
    private static final int DEFAULT_BUFFER_SIZE = 8092; // 8KB
    private static final int DEFAULT_IDLE_TIMEOUT = 60; // Idle timeout in seconds
    private static final int DEFAULT_MAX_CONNECTIONS_PER_PROXY = 50;
    private static final boolean DEFAULT_LOGGING_ENABLED = true;
    private static final boolean DEFAULT_BYPASS_COLLABORATOR = true;
    private static final boolean DEFAULT_RANDOM_PROXY_SELECTION = true;
    
    // Instance settings
    private int bufferSize = DEFAULT_BUFFER_SIZE;
    private int idleTimeoutSec = DEFAULT_IDLE_TIMEOUT;
    private int maxConnectionsPerProxy = DEFAULT_MAX_CONNECTIONS_PER_PROXY;
    
    // Bypass configuration for Burp Collaborator domains
    private boolean bypassCollaborator = DEFAULT_BYPASS_COLLABORATOR;
    private final List<String> bypassDomains = new ArrayList<>();
    
    // Proxy selection mode
    private boolean useRandomProxySelection = DEFAULT_RANDOM_PROXY_SELECTION;

    private final Logging logging;
    private final List<ProxyEntry> proxyList;
    private final ReadWriteLock proxyListLock;
    private final Random random = new Random();
    
    // Logging configuration
    private boolean loggingEnabled = DEFAULT_LOGGING_ENABLED;
    
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
    
    private BurpProxyRotate extension;

    // Connection state
    private enum ConnectionStage {
        INITIAL, 
        SOCKS4_CONNECT, SOCKS4_CONNECTED,
        SOCKS5_AUTH, SOCKS5_AUTH_RESPONSE, SOCKS5_CONNECT, SOCKS5_CONNECTED,
        HTTP_CONNECT,
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
        //private String errorMessage;
        //private long creationTime;
        
        public ConnectionState() {
            // Use direct buffers for better I/O performance
            this.inputBuffer = ByteBuffer.allocateDirect(bufferSize);
            this.outputBuffer = ByteBuffer.allocateDirect(bufferSize);
            //this.creationTime = System.currentTimeMillis();
        }
        
        /**
         * Helper function to ensure buffers are large enough, especially for HTTP(S) connections
         */
        public void ensureBufferCapacity(int desiredCapacity) {
            // Check if input buffer needs resizing
            if (inputBuffer.capacity() < desiredCapacity) {
                ByteBuffer newBuffer = ByteBuffer.allocateDirect(desiredCapacity);
                if (inputBuffer.position() > 0) {
                    inputBuffer.flip();
                    newBuffer.put(inputBuffer);
                }
                inputBuffer = newBuffer;
                logInfo("Increased input buffer capacity to " + desiredCapacity);
            }
            
            // Check if output buffer needs resizing
            if (outputBuffer.capacity() < desiredCapacity) {
                ByteBuffer newBuffer = ByteBuffer.allocateDirect(desiredCapacity);
                if (outputBuffer.position() > 0) {
                    outputBuffer.flip();
                    newBuffer.put(outputBuffer);
                }
                outputBuffer = newBuffer;
                logInfo("Increased output buffer capacity to " + desiredCapacity);
            }
        }
        
        /**
         * Adjusts buffer sizes based on the selected proxy type
         */
        public void adjustBuffersForProxyType() {
            if (selectedProxy != null && selectedProxy.isHttp()) {
                // HTTP proxies need much larger buffers?
                ensureBufferCapacity(262144); // 256 KB
            } else if (selectedProxy != null && "direct".equals(selectedProxy.getProtocol())) {
                // Direct connections for HTTPS need larger buffers too
                ensureBufferCapacity(131072); // 128 KB
            }
        }
    }

    // Track the last used proxy to enforce rotation
    private volatile int lastProxyIndex = -1;
    private volatile ProxyEntry lastUsedProxy = null;
    private final Object proxyRotationLock = new Object();

    /**
     * Creates a new ProxyRotateService
     */
    public ProxyRotateService(List<ProxyEntry> proxyList, ReadWriteLock proxyListLock, Logging logging) {
        this.proxyList = proxyList;
        this.proxyListLock = proxyListLock;
        this.logging = logging;
        
        // Add default Burp Collaborator domains
        bypassDomains.add("burpcollaborator.net");
        bypassDomains.add("oastify.com");
    }

    /**
     * ref for callbacks to update the UI
     */
    public void setExtension(BurpProxyRotate extension) {
        this.extension = extension;
    }
    
    /**
     * Proxy Service settings
     */
    public void setSettings(int bufferSize, int idleTimeoutSec, int maxConnectionsPerProxy) {
        boolean changed = false;
        
        if (this.bufferSize != bufferSize) {
            this.bufferSize = bufferSize;
            changed = true;
        }
        
        if (this.idleTimeoutSec != idleTimeoutSec) {
            this.idleTimeoutSec = idleTimeoutSec;
            changed = true;
        }
        
        if (this.maxConnectionsPerProxy != maxConnectionsPerProxy) {
            this.maxConnectionsPerProxy = maxConnectionsPerProxy;
            changed = true;
        }
        
        if (changed) {
            logInfo("Settings updated: bufferSize=" + bufferSize + 
                    ", idleTimeoutSec=" + idleTimeoutSec + 
                    ", maxConnectionsPerProxy=" + maxConnectionsPerProxy);
        }
    }

    /**
     * Reset default settings
     */
    public void resetToDefaults() {
        setSettings(DEFAULT_BUFFER_SIZE, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_CONNECTIONS_PER_PROXY);
        setLoggingEnabled(DEFAULT_LOGGING_ENABLED);
        setBypassCollaborator(DEFAULT_BYPASS_COLLABORATOR);
        setUseRandomProxySelection(DEFAULT_RANDOM_PROXY_SELECTION);
        logInfo("All settings reset to defaults");
    }

    /**
     * Check if the service is running
     */
    public boolean isRunning() {
        return serverRunning;
    }
    
    /**
     * Returns local port (of the proxy service)
     */
    public int getLocalPort() {
        return localPort;
    }

    /**
     * Number of active connections
     */
    public int getActiveConnectionCount() {
        return activeConnectionCount.get();
    }

    /**
     * Start Proxy Rotate Service
     */
    public void start(int port, Runnable onSuccess, Consumer<String> onFailure) {
        if (serverRunning) {
            logInfo("Service is already running.");
            return;
        }

        this.localPort = port;
        
        try {
            selector = SelectorProvider.provider().openSelector();
            
            // Create a new non-blocking server socket channel
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
            
            // Start cleanup thread - run every 30 seconds (will add UI setting)
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
            
            logInfo("Burp Proxy Rotate service started on localhost:" + localPort + " (NIO mode)");
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
                    
                    if (key == null) {
                        logError("Null SelectionKey encountered, skipping");
                        continue;
                    }
                    
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
                        String errorMsg = "Exception " + e.getClass().getName() + " while processing key";
                        if (e.getMessage() != null) {
                            errorMsg += ": " + e.getMessage();
                        }
                        if (e.getCause() != null) {
                            errorMsg += " - caused by: " + e.getCause().toString();
                        }
                        
                        try {
                            if (key.channel() != null) {
                                errorMsg += " - on channel: " + key.channel().toString();
                                
                                if (key.channel() instanceof SocketChannel) {
                                    SocketChannel channel = (SocketChannel) key.channel();
                                    if (channel.isConnected() && channel.socket() != null) {
                                        errorMsg += " (" + channel.socket().getInetAddress() + ":" + channel.socket().getPort() + ")";
                                    }
                                }
                            }
                            errorMsg += " - interestOps: " + key.interestOps();
                        } catch (Exception ex) {
                            // pass
                        }
                        
                        logError(errorMsg);
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
                            if (key != null && key.isValid() && key.channel() != null && key.channel().isOpen()) {
                                try {
                                    int ops = key.interestOps();
                                    Object att = key.attachment();
                                    key.cancel();
                                    key.channel().register(newSelector, ops, att);
                                } catch (Exception ex) {
                                    logError("Error while migrating key to new selector: " + ex.toString());
                                }
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
            } catch (Exception e) {
                // Catch any other unexpected exceptions in the main loop
                String errorMsg = "Unexpected exception in selector loop: " + e.getClass().getName();
                if (e.getMessage() != null) {
                    errorMsg += " - " + e.getMessage();
                }
                logError(errorMsg);
                
                // If we're not running anymore, just break out of the loop
                if (!serverRunning) {
                    break;
                }
                
                // Add a small delay before continuing to avoid busy-looping on errors
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    /**
     * Stops the Proxy Rotate service
     */
    public void stop() {
        if (!serverRunning) {
            logInfo("Burp Proxy Rotate service is not running.");
            return;
        }

        logInfo("Burp Proxy Rotate service stopping...");
        serverRunning = false;
        
        try {
            // Reset the proxy rotation index
            lastProxyIndex = -1;
            lastUsedProxy = null;
            
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
                        // pass
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
     * Handles an accept event on the server socket
     */
    private void handleAccept(SelectionKey key) throws IOException {
        ServerSocketChannel serverChannel = (ServerSocketChannel) key.channel();
        SocketChannel clientChannel = serverChannel.accept();
        clientChannel.configureBlocking(false);
        
        Socket socket = clientChannel.socket();
        socket.setTcpNoDelay(true);
        socket.setKeepAlive(true);
        
        clientChannel.register(selector, SelectionKey.OP_READ);
        
        // Create and store connection state
        ConnectionState state = new ConnectionState();
        connectionStates.put(clientChannel, state);
        lastActivityTime.put(clientChannel, System.currentTimeMillis());
        
        activeConnectionCount.incrementAndGet();
        
        logInfo("New client connection accepted");
    }
    
    /**
     * Handles a connect event on a client socket
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
                
                lastActivityTime.put(proxyChannel, System.currentTimeMillis());
                lastActivityTime.put(clientChannel, System.currentTimeMillis());
                
                // Check if this is a direct connection (bypassing proxy for collaborator)
                if (state.selectedProxy != null && "direct".equals(state.selectedProxy.getProtocol())) {
                    logInfo("Direct connection established to " + state.targetHost + ":" + state.targetPort);
                    
                    try {
                        // Configure socket for optimal SSL/TLS handling
                        Socket socket = proxyChannel.socket();
                        
                        // Increase buffer sizes for SSL/TLS data
                        int largeBuffer = Math.max(bufferSize * 4, 262144); // at least 256KB
                        socket.setReceiveBufferSize(largeBuffer);
                        socket.setSendBufferSize(largeBuffer);
                        
                        socket.setTcpNoDelay(true);
                        socket.setKeepAlive(true);
                        socket.setSoTimeout(0);
                        socket.setPerformancePreferences(0, 1, 0);
                        
                        // Create larger buffers for this connection
                        state.inputBuffer = ByteBuffer.allocateDirect(262144);
                        state.outputBuffer = ByteBuffer.allocateDirect(262144);
                    } catch (Exception e) {
                        logError("Error optimizing direct connection socket: " + e.getMessage());
                    }
                    
                    // Send success response based on SOCKS version
                    if (state.socksVersion == 5) {
                        Socks5.sendSocks5SuccessResponse(clientChannel);
                    } else {
                        Socks4.sendSocks4SuccessResponse(clientChannel);
                    }
                    
                    // Update state
                    state.stage = ConnectionStage.PROXY_CONNECTED;
                    
                    // Register for reading
                    proxyChannel.register(selector, SelectionKey.OP_READ);
                    
                    logInfo("Direct connection established immediately to " + state.targetHost + ":" + state.targetPort);
                    return;
                } else {
                    // Check if this is an HTTP proxy connection
                    if (state.selectedProxy != null && state.selectedProxy.isHttp()) {
                        // Send HTTP CONNECT request
                        logInfo("HTTP proxy connection established to " + state.selectedProxy.getHost() + ":" + state.selectedProxy.getPort());
                        HttpProxy.sendHttpConnectRequest(proxyChannel, state.targetHost, state.targetPort, state.selectedProxy);
                        
                        // Register for reading the HTTP response
                        proxyChannel.register(selector, SelectionKey.OP_READ);
                        
                        // Update state
                        state.stage = ConnectionStage.HTTP_CONNECT;
                        return;
                    }
                    
                    // Regular proxy connection logic continues for SOCKS proxies
                    proxyChannel.register(selector, SelectionKey.OP_READ);
                    
                    // Setup the SOCKS handshake with the proxy
                    if (state.selectedProxy.getProtocolVersion() == 5) {
                        // SOCKS5 proxy handshake
                        ByteBuffer handshake;
                        
                        if (state.selectedProxy.isAuthenticated()) {
                            // support both no-auth (0x00) and username/password (0x02)
                            handshake = ByteBuffer.allocate(4);
                            handshake.put((byte) 0x05); // SOCKS version
                            handshake.put((byte) 0x02); // 2 auth methods
                            handshake.put((byte) 0x00); // No auth
                            handshake.put((byte) 0x02); // Username/password auth
                        } else {
                            // only support no-auth
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
                        ByteBuffer request = Socks4.createSocks4ConnectRequest(state.targetHost, state.targetPort);
                        proxyChannel.write(request);
                        state.stage = ConnectionStage.SOCKS4_CONNECT;
                    }
                    
                    logInfo("Proxy connection established to " + 
                           state.selectedProxy.getProtocol() + "://" + 
                           state.selectedProxy.getHost() + ":" + 
                           state.selectedProxy.getPort());
                }
            }
        } catch (IOException e) {
            logError("Connection failed: " + e.getMessage());
            
            for (Map.Entry<SocketChannel, SocketChannel> entry : proxyConnections.entrySet()) {
                if (entry.getValue() == proxyChannel) {
                    SocketChannel clientChannel = entry.getKey();
                    ConnectionState state = connectionStates.get(clientChannel);
                    
                    if (state != null) {
                        ProxyEntry proxy = state.selectedProxy;
                        
                        if (proxy != null && "direct".equals(proxy.getProtocol())) {
                            logError("Direct connection to " + state.targetHost + " failed, falling back to proxy");
                            
                            proxyConnections.remove(clientChannel);
                            
                            try {
                                connectThroughProxy(clientChannel, state);
                                return;
                            } catch (IOException ex) {
                                logError("Fallback to proxy also failed: " + ex.getMessage());
                            }
                        } else if (proxy != null) {
                            // Regular proxy failure
                            if (extension != null) {
                                extension.notifyProxyFailure(proxy.getHost(), proxy.getPort(), e.getMessage());
                            }
                        }
                        
                        if (state.socksVersion == 5) {
                            Socks5.sendSocks5ErrorResponse(clientChannel, (byte) 1); // General failure
                        } else {
                            Socks4.sendSocks4ErrorResponse(clientChannel, (byte) 91); // Rejected
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
        
        logInfo("Fallback: Using proxy " + proxy.getProtocol() + "://" + proxyKey + 
                " for target: " + state.targetHost + ":" + state.targetPort);
        
        connectionsPerProxy.computeIfAbsent(proxyKey, _ -> new AtomicInteger(0)).incrementAndGet();
        
        state.selectedProxy = proxy;
        
        SocketChannel proxyChannel = SocketChannel.open();
        proxyChannel.configureBlocking(false);
        Socket proxySocket = proxyChannel.socket();
        
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
     * Handles a read event on a socket
     */
    private void handleRead(SelectionKey key) throws IOException {
        if (key == null || !key.isValid()) {
            throw new IOException("Invalid key in handleRead");
        }
        
        SocketChannel channel = (SocketChannel) key.channel();
        if (channel == null || !channel.isOpen()) {
            throw new IOException("Channel is null or closed in handleRead");
        }
        
        lastActivityTime.put(channel, System.currentTimeMillis());
        
        // Determine if this is a client or proxy channel
        if (connectionStates.containsKey(channel)) {
            handleClientRead(key, channel);
        } else {
            handleProxyRead(key, channel);
        }
    }
    
    /**
     * Handles a read event from a client
     */
    private void handleClientRead(SelectionKey key, SocketChannel clientChannel) throws IOException {
        ConnectionState state = connectionStates.get(clientChannel);
        
        if (state == null) {
            logError("No state found for client read");
            cancelAndCloseKey(key);
            return;
        }
        
        // Check if we need to resize the buffer
        if (state.inputBuffer.capacity() < bufferSize) {
            // Allocate a larger buffer
            ByteBuffer newBuffer = ByteBuffer.allocateDirect(bufferSize);
            state.inputBuffer = newBuffer;
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
            return;
        }
        
        // Process the data based on the current connection stage
        buffer.flip();
        
        try {
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
                        if (state.selectedProxy != null && "direct".equals(state.selectedProxy.getProtocol())) {
                            try {
                                // For TLS traffic, make sure we're writing all data in a single call if possible
                                int totalBytesToWrite = buffer.remaining();
                                if (totalBytesToWrite > 0) {
                                    logInfo("Forwarding " + totalBytesToWrite + " bytes from client to direct connection");
                                    
                                    // Attempt to write all data at once for efficiency
                                    proxyChannel.write(buffer);
                                    
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
        } catch (BufferOverflowException e) {
            logError("Buffer overflow in handleClientRead: " + e.toString() + " - buffer capacity: " + 
                    buffer.capacity() + ", position: " + buffer.position() + ", limit: " + buffer.limit());
            
            int newSize = buffer.capacity() * 2;
            logInfo("Increasing buffer size to " + newSize + " bytes");
            ByteBuffer newBuffer = ByteBuffer.allocateDirect(newSize);
            buffer.flip();
            newBuffer.put(buffer);
            state.inputBuffer = newBuffer;
            
            closeConnection(clientChannel);
        }
    }
    
    /**
     * Handles a read event from a proxy
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
        
        // Check if we need to resize the buffer
        if (state.inputBuffer.capacity() < bufferSize) {
            ByteBuffer newBuffer = ByteBuffer.allocateDirect(bufferSize);
            state.inputBuffer = newBuffer;
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
            logInfo("Proxy/direct connection closed");
            closeConnection(clientChannel);
            return;
        } else if (bytesRead == 0) {
            return;
        }
        
        buffer.flip();
        
        try {
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
                    
                case HTTP_CONNECT:
                    processHttpConnectResponse(clientChannel, proxyChannel, state, buffer);
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
        } catch (BufferOverflowException e) {
            logError("Buffer overflow in handleProxyRead: " + e.toString() + " - buffer capacity: " + 
                    buffer.capacity() + ", position: " + buffer.position() + ", limit: " + buffer.limit() + 
                    ", bytes read: " + bytesRead);
            
            // If this is HTTP proxy, we need larger buffers
            if (state.selectedProxy != null && state.selectedProxy.isHttp()) {
                // Try to handle the error by allocating a larger buffer for HTTP
                int newSize = Math.max(buffer.capacity() * 2, 1048576); // At least 1MB for HTTP
                logInfo("Increasing buffer size for HTTP proxy to " + newSize + " bytes");
                
                ByteBuffer newBuffer = ByteBuffer.allocateDirect(newSize);
                buffer.flip(); // Prepare for reading
                newBuffer.put(buffer); // Copy existing data
                state.inputBuffer = newBuffer;
            }
            
            // Close the connection
            closeConnection(clientChannel);
        }
    }
    
    /**
     * Forward data from a proxy/direct connection to a client
     */
    private void forwardDataToClient(SocketChannel clientChannel, ConnectionState state, 
                                    ByteBuffer buffer) throws IOException {
        if (state.selectedProxy != null && "direct".equals(state.selectedProxy.getProtocol())) {
            // HTTPS or other SSL/TLS traffic
            try {
                int totalBytesToWrite = buffer.remaining();
                if (totalBytesToWrite > 0) {
                    logInfo("Forwarding " + totalBytesToWrite + " bytes from direct connection to client");
                    
                    // Attempt to write all data at once
                   clientChannel.write(buffer);
                    
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
     * Handles a write event on a socket
     */
    private void handleWrite(SelectionKey key) throws IOException {
        if (key == null || !key.isValid()) {
            throw new IOException("Invalid key in handleWrite");
        }
        
        SocketChannel channel = (SocketChannel) key.channel();
        if (channel == null || !channel.isOpen()) {
            throw new IOException("Channel is null or closed in handleWrite");
        }
        
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
                    
                    key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                }
            } catch (IOException e) {
                logError("Error writing to channel: " + e.getMessage());
                
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
     * Process the initial data from a client to determine SOCKS protocol version
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
            
            // Put the version byte back for processing
            buffer.position(buffer.position() - 1);
            
            Socks5.Socks5GreetingResult greetingResult = Socks5.processSocks5Greeting(buffer);
            
            if (!greetingResult.success) {
                if ("Need more data".equals(greetingResult.errorMessage)) {
                    return;
                }
                logError(greetingResult.errorMessage);
                closeConnection(clientChannel);
                return;
            }
            
            // Send authentication method response (0 = no auth)
            Socks5.sendSocks5GreetingResponse(clientChannel);
            
            // Update state to wait for connect request
            state.stage = ConnectionStage.SOCKS5_CONNECT;
            
        } else if (version == 4) {
            // SOCKS4 - handle the connect request directly
            state.socksVersion = 4;
            
            Socks4.Socks4ConnectResult result = Socks4.processSocks4ConnectRequest(buffer);
            
            if (!result.success) {
                if ("Need more data".equals(result.errorMessage)) {
                    return; // Need more data
                }
                
                logError(result.errorMessage);
                Socks4.sendSocks4ErrorResponse(clientChannel, (byte) 91);
                closeConnection(clientChannel);
                return;
            }
            
            // Save target information
            state.targetHost = result.targetHost;
            state.targetPort = result.targetPort;
            state.addressType = 1; // IPv4 type
            
            // Connect to the target through a random proxy
            connectToTarget(clientChannel, state);
        } else {
            logError("Unsupported SOCKS version: " + version);
            closeConnection(clientChannel);
        }
    }
    
    /**
     * Process a SOCKS5 CONNECT request
     */
    private void processSocks5ConnectRequest(SocketChannel clientChannel, ConnectionState state, ByteBuffer buffer) throws IOException {
        Socks5.Socks5ConnectResult result = Socks5.processSocks5ConnectRequest(buffer);
        
        if (!result.success) {
            if ("Need more data".equals(result.errorMessage)) {
                return; // Need more data
            }
            
            logError(result.errorMessage);
            Socks5.sendSocks5ErrorResponse(clientChannel, result.errorCode);
            closeConnection(clientChannel);
            return;
        }
        
        // Save target information
        state.targetHost = result.targetHost;
        state.targetPort = result.targetPort;
        state.addressType = result.addressType;
        
        // Connect to the target through a random proxy
        connectToTarget(clientChannel, state);
    }

    /**
     * Checks if a domain should bypass proxying
     */
    private boolean shouldBypassProxy(String domain) {
        if (!bypassCollaborator || domain == null) {
            return false;
        }
        
        logInfo("Checking if domain should bypass proxy: " + domain);
        
        for (String bypassDomain : bypassDomains) {
            if (domain.equals(bypassDomain) || domain.endsWith("." + bypassDomain)) {
                logInfo("Bypassing proxy for domain: " + domain);
                return true;
            }
        }
        
        return false;
    }

    /**
     * Connect to the target through a selected proxy with rotation
     */
    private void connectToTarget(SocketChannel clientChannel, ConnectionState state) throws IOException {
        if (bypassCollaborator && shouldBypassProxy(state.targetHost)) {
            try {
                logInfo("Setting up direct connection to " + state.targetHost + ":" + state.targetPort);
                
                // Create a fake proxy entry for tracking with special flag
                ProxyEntry directProxy = ProxyEntry.createDirect(state.targetHost, state.targetPort);
                state.selectedProxy = directProxy;
                
                // Adjust buffer sizes for direct connection
                state.adjustBuffersForProxyType();
                
                // Create a direct socket channel
                SocketChannel directChannel = SocketChannel.open();
                directChannel.configureBlocking(false);
                Socket directSocket = directChannel.socket();
                
                // Enhanced socket configuration for SSL/TLS
                directSocket.setTcpNoDelay(true);
                directSocket.setKeepAlive(true);
                directSocket.setSoTimeout(0);
                
                // Increase buffer sizes SSL/TLS data
                int largeBuffer = Math.max(bufferSize * 4, 262144); // At least 256KB
                directSocket.setReceiveBufferSize(largeBuffer);
                directSocket.setSendBufferSize(largeBuffer);
                
                // Disable Nagle's algorithm for better SSL performance
                directSocket.setTcpNoDelay(true);
                
                // Prioritize latency over bandwidth ? (will check more)
                directSocket.setPerformancePreferences(0, 1, 0); 
                
                // Associate the channels
                proxyConnections.put(clientChannel, directChannel);
                
                logInfo("Initiating direct connection to " + state.targetHost + ":" + state.targetPort);
                
                boolean connected = directChannel.connect(new InetSocketAddress(state.targetHost, state.targetPort));
                
                if (connected) {
                    if (state.socksVersion == 5) {
                        Socks5.sendSocks5SuccessResponse(clientChannel);
                    } else {
                        Socks4.sendSocks4SuccessResponse(clientChannel);
                    }
                    
                    // Update state to connected
                    state.stage = ConnectionStage.PROXY_CONNECTED;
                    
                    // Register for reading
                    directChannel.register(selector, SelectionKey.OP_READ);
                    
                    logInfo("Direct connection established immediately to " + state.targetHost + ":" + state.targetPort);
                    return;
                } else {
                    // Register for connect completion
                    directChannel.register(selector, SelectionKey.OP_CONNECT);
                    logInfo("Direct connection pending to " + state.targetHost + ":" + state.targetPort);
                }
                
                return;
            } catch (IOException e) {
                logError("Error connecting directly to " + state.targetHost + ": " + e.getMessage());
            }
        }
        
        // Original proxy connection logic
        // Choose a proxy using the rotation mechanism
        ProxyEntry proxy = selectRandomActiveProxy();
        
        if (proxy == null) {
            logError("No active proxies available");
            if (state.socksVersion == 5) {
                Socks5.sendSocks5ErrorResponse(clientChannel, (byte) 1);
            } else {
                Socks4.sendSocks4ErrorResponse(clientChannel, (byte) 91);
            }
            closeConnection(clientChannel);
            return;
        }
        
        String proxyKey = proxy.getHost() + ":" + proxy.getPort();
        String proxyProtocol = proxy.getProtocol();
        
        logInfo("Using proxy: " + proxyProtocol + "://" + proxyKey + 
                " for target: " + state.targetHost + ":" + state.targetPort);
        
        connectionsPerProxy.computeIfAbsent(proxyKey, _ -> new AtomicInteger(0)).incrementAndGet();
        
        state.selectedProxy = proxy;
        
        state.adjustBuffersForProxyType();
        
        try {
            SocketChannel proxyChannel = SocketChannel.open();
            proxyChannel.configureBlocking(false);
            Socket proxySocket = proxyChannel.socket();
            
            proxySocket.setTcpNoDelay(true);
            
            if (proxy.isHttp()) {
                int largeBuffer = 262144; // 256KB
                proxySocket.setReceiveBufferSize(largeBuffer);
                proxySocket.setSendBufferSize(largeBuffer);
            }
            
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
                Socks5.sendSocks5ErrorResponse(clientChannel, (byte) 1);
            } else {
                Socks4.sendSocks4ErrorResponse(clientChannel, (byte) 91);
            }
            
            closeConnection(clientChannel);
        }
    }
    
    /**
     * Process a SOCKS5 authentication response from the proxy
     */
    private void processSocks5AuthResponse(SocketChannel clientChannel, SocketChannel proxyChannel, 
                                        ConnectionState state, ByteBuffer buffer, boolean isAuthResponse) throws IOException {
        Socks5.Socks5AuthResult authResult = Socks5.processSocks5AuthResponse(buffer, isAuthResponse);
        
        switch (authResult.status) {
            case NEED_MORE_DATA:
                return; // Need more data
                
            case INVALID_VERSION:
            case AUTH_FAILED:
            case UNSUPPORTED_METHOD:
                logError(authResult.errorMessage);
                Socks5.sendSocks5ErrorResponse(clientChannel, (byte) 1);
                closeConnection(clientChannel);
                return;
                
            case AUTH_SUCCESS:
                logInfo("SOCKS5 authentication successful");
                Socks5.sendSocks5ConnectRequest(proxyChannel, state.targetHost, state.targetPort, state.addressType);
                state.stage = ConnectionStage.SOCKS5_CONNECT;
                break;
                
            case NO_AUTH:
                logInfo("SOCKS5 proxy accepted no-auth method");
                Socks5.sendSocks5ConnectRequest(proxyChannel, state.targetHost, state.targetPort, state.addressType);
                state.stage = ConnectionStage.SOCKS5_CONNECT;
                break;
                
            case USERNAME_PASSWORD:
                if (state.selectedProxy.isAuthenticated()) {
                    logInfo("SOCKS5 proxy requested username/password authentication");
                    Socks5.sendSocks5Auth(proxyChannel, state.selectedProxy.getUsername(), state.selectedProxy.getPassword());
                    state.stage = ConnectionStage.SOCKS5_AUTH_RESPONSE;
                } else {
                    logError("SOCKS5 proxy requires authentication but no credentials provided");
                    Socks5.sendSocks5ErrorResponse(clientChannel, (byte) 1);
                    closeConnection(clientChannel);
                }
                break;
        }
    }
    
    /**
     * Process a SOCKS5 connect response from the proxy
     */
    private void processSocks5ConnectResponse(SocketChannel clientChannel, SocketChannel proxyChannel, 
                                           ConnectionState state, ByteBuffer buffer) throws IOException {
        Socks5.Socks5ConnectResponse response = Socks5.processSocks5ConnectResponse(buffer);
        
        if (!response.success) {
            if ("Need more data".equals(response.errorMessage)) {
                return; // Need more data
            }
            
            logError(response.errorMessage);
            if (response.errorCode != 0) {
                Socks5.sendSocks5ErrorResponse(clientChannel, response.errorCode);
            }
            closeConnection(clientChannel);
            return;
        }
        
        // Connection successful
        Socks5.sendSocks5SuccessResponse(clientChannel);
        
        // Update state to connected
        state.stage = ConnectionStage.PROXY_CONNECTED;
        
        // If there's any remaining data, forward it to the client
        if (response.remainingData != null && response.remainingData.hasRemaining()) {
            clientChannel.write(response.remainingData);
        }
    }
    
    /**
     * Process a SOCKS4 connect response from the proxy
     */
    private void processSocks4ConnectResponse(SocketChannel clientChannel, SocketChannel proxyChannel, 
                                           ConnectionState state, ByteBuffer buffer) throws IOException {
        Socks4.Socks4ConnectResponse response = Socks4.processSocks4ConnectResponse(buffer);
        
        if (!response.success) {
            if ("Need more data".equals(response.errorMessage)) {
                return; // Need more data
            }
            
            logError(response.errorMessage);
            Socks4.sendSocks4ErrorResponse(clientChannel, response.statusCode);
            closeConnection(clientChannel);
            return;
        }
        
        // Connection successful
        Socks4.sendSocks4SuccessResponse(clientChannel);
        
        state.stage = ConnectionStage.PROXY_CONNECTED;
        
        // Forward remaining data to the client
        if (response.remainingData != null && response.remainingData.hasRemaining()) {
            clientChannel.write(response.remainingData);
        }
    }
    

    

    

    

    


    /**
     * Closes a connection and cleans up resources
     */
    private void closeConnection(SocketChannel clientChannel) {
        if (clientChannel == null) {
            return;
        }
        
        try {
            // Get the proxy channel if it exists
            SocketChannel proxyChannel = proxyConnections.remove(clientChannel);
            
            // Get the state
            ConnectionState state = connectionStates.remove(clientChannel);
            
            // Close the client channel
            cancelAndCloseChannel(clientChannel);
            
            // Close the proxy channel if it exists
            if (proxyChannel != null) {
                cancelAndCloseChannel(proxyChannel);
                
                // Update counters
                if (state != null && state.selectedProxy != null) {
                    String proxyKey = state.selectedProxy.getHost() + ":" + state.selectedProxy.getPort();
                    AtomicInteger count = connectionsPerProxy.get(proxyKey);
                    if (count != null) {
                        count.decrementAndGet();
                    }
                }
            }
            
            lastActivityTime.remove(clientChannel);
            if (proxyChannel != null) {
                lastActivityTime.remove(proxyChannel);
            }
            
            activeConnectionCount.decrementAndGet();
        } catch (Exception e) {
            logError("Error in closeConnection: " + e.toString());
            
            try {
                activeConnectionCount.updateAndGet(current -> Math.max(0, current - 1));
            } catch (Exception ex) {
                // pass
            }
        }
    }
    
    /**
     * Cancel a selection key and closes the channel
     */
    private void cancelAndCloseKey(SelectionKey key) {
        if (key == null) {
            return;
        }
        
        try {
            // Get the channel before canceling the key
            //Object attachment = key.attachment();
            java.nio.channels.Channel channel = key.channel();
            
            // Cancel the key first
            key.cancel();
            
            // Close the channel if available
            if (channel != null) {
                if (channel instanceof SocketChannel) {
                    cancelAndCloseChannel((SocketChannel) channel);
                } else {
                    try {
                        channel.close();
                    } catch (IOException e) {
                        // pass
                    }
                }
            }
        } catch (Exception e) {
            logError("Error in cancelAndCloseKey: " + e.toString());
        }
    }
    
    /**
     * Cancel a channel's selection key and closes the channel
     */
    private void cancelAndCloseChannel(SocketChannel channel) {
        if (channel == null) {
            return;
        }
        
        try {
            // Cancel the selection key
            SelectionKey key = channel.keyFor(selector);
            if (key != null) {
                key.cancel();
            }
            
            // Close the channel
            if (channel.isOpen()) {
                try {
                    Socket socket = channel.socket();
                    if (socket != null) {
                        try {
                            socket.setSoLinger(true, 0);
                        } catch (Exception e) {
                            // pass
                        }
                    }
                } catch (Exception e) {
                    // pass
                }
                
                try {
                    channel.close();
                } catch (IOException e) {
                    // pass
                }
            }
        } catch (Exception e) {
            logError("Error closing channel: " + e.toString());
        } finally {
            try {
                lastActivityTime.remove(channel);
                
                if (connectionStates.containsKey(channel)) {
                    connectionStates.remove(channel);
                }
                
                // Remove from proxy connections (in both directions)
                SocketChannel pairedChannel = proxyConnections.remove(channel);
                if (pairedChannel != null) {
                    // Also try to close the paired channel
                    try {
                        if (pairedChannel.isOpen()) {
                            pairedChannel.close();
                        }
                    } catch (Exception e) {
                        // pass
                    }
                    lastActivityTime.remove(pairedChannel);
                }
                
                // Check if this is a proxy channel and remove from the reverse mapping
                for (Map.Entry<SocketChannel, SocketChannel> entry : new ArrayList<>(proxyConnections.entrySet())) {
                    if (entry.getValue() == channel) {
                        proxyConnections.remove(entry.getKey());
                        break;
                    }
                }
            } catch (Exception e) {
                // pass
            }
        }
    }
    
    /**
     * Clean up idle connections and enforce connection rotation
     */
    private void cleanupIdleConnections() {
        long currentTime = System.currentTimeMillis();
        long idleThreshold = idleTimeoutSec * 1000;
        int closedCount = 0;
        
        // More aggressive idle connection timeouts to force new proxy selections
        // We want to close connections even if they're still somewhat active
        // This helps ensure different proxies are used for different requests
        long moderatelyIdleThreshold = 10000; // 10 seconds - close moderately idle connections (will add UI settings)
        
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
     * Selects a proxy from the list based on the selected mode (round-robin or random)
     * Round-robin ensures each request uses a different proxy in sequence
     * Random mode picks a completely random proxy for each request
     */
    private ProxyEntry selectRandomActiveProxy() {
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
        
        // Choose a proxy based on the selection mode
        ProxyEntry selectedProxy;
        
        if (useRandomProxySelection) {
            // Random mode - pick any proxy at random
            int randomIndex = random.nextInt(activeProxies.size());
            selectedProxy = activeProxies.get(randomIndex);
            
            logInfo("Randomly selected proxy: " + selectedProxy.getProtocol() + "://" + 
                selectedProxy.getHost() + ":" + selectedProxy.getPort() + 
                " (proxy " + (randomIndex + 1) + " of " + activeProxies.size() + ")");
        } else {
            // Round-robin mode - get the next proxy in sequence
            synchronized (proxyRotationLock) {
                if (lastUsedProxy == null) {
                    // First time, start with the first proxy
                    selectedProxy = activeProxies.get(0);
                    lastProxyIndex = 0;
                } else {
                    // Find the last used proxy in the current active list
                    int lastUsedIndex = -1;
                    for (int i = 0; i < activeProxies.size(); i++) {
                        ProxyEntry proxy = activeProxies.get(i);
                        if (proxy.getHost().equals(lastUsedProxy.getHost()) && 
                            proxy.getPort() == lastUsedProxy.getPort() &&
                            proxy.getProtocol().equals(lastUsedProxy.getProtocol())) {
                            lastUsedIndex = i;
                            break;
                        }
                    }
                    
                    if (lastUsedIndex == -1) {
                        // Last used proxy is no longer active, start from beginning
                        selectedProxy = activeProxies.get(0);
                        lastProxyIndex = 0;
                    } else {
                        // Select the next proxy in the list
                        lastProxyIndex = (lastUsedIndex + 1) % activeProxies.size();
                        selectedProxy = activeProxies.get(lastProxyIndex);
                    }
                }
                
                lastUsedProxy = selectedProxy;
                
                logInfo("Rotating proxy: " + selectedProxy.getProtocol() + "://" + 
                    selectedProxy.getHost() + ":" + selectedProxy.getPort() + 
                    " (proxy " + (lastProxyIndex + 1) + " of " + activeProxies.size() + ")");
            }
        }
        
        return selectedProxy;
    }
    
    /**
     * Enable logging
     */
    public void setLoggingEnabled(boolean enabled) {
        if (this.loggingEnabled != enabled) {
            this.loggingEnabled = enabled;
            logInfo("Logging " + (enabled ? "enabled" : "disabled"));
        }
    }

    /**
     * Log info messages
     */
    private void logInfo(String message) {
        if (loggingEnabled) {
            logging.logToOutput("[BurpProxyRotate] " + message);
        }
    }

    /**
     * Log error messages
     */
    private void logError(String message) {
        if (loggingEnabled) {
            logging.logToError("[BurpProxyRotate] ERROR: " + message);
        }
    }

    /**
     * Get connection stats for each proxy
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
     * Enable or disable bypassing proxies for Burp Collaborator domains
     */
    public void setBypassCollaborator(boolean bypass) {
        if (this.bypassCollaborator != bypass) {
            this.bypassCollaborator = bypass;
            logInfo("Bypass for Collaborator domains " + (bypass ? "enabled" : "disabled"));
        }
    }
    
    /**
     * Helper function to add a custom domain to bypass proxy
     */
    public void addBypassDomain(String domain) {
        if (!bypassDomains.contains(domain)) {
            bypassDomains.add(domain);
            logInfo("Added bypass domain: " + domain);
        }
    }
    
    /**
     * Helper function to remove a bypass domain
     */
    public void removeBypassDomain(String domain) {
        if (bypassDomains.remove(domain)) {
            logInfo("Removed bypass domain: " + domain);
        }
    }
    
    /**
     * Clears all bypass domains
     */
    public void clearBypassDomains() {
        bypassDomains.clear();
        logInfo("All bypass domains have been cleared");
    }




    
    /**
     * Process an HTTP CONNECT response from the proxy
     */
    private void processHttpConnectResponse(SocketChannel clientChannel, SocketChannel proxyChannel, 
                                          ConnectionState state, ByteBuffer buffer) throws IOException {
        // Make sure we have enough buffer capacity for large HTTP responses
        if (buffer.capacity() < 16384) { // Ensure at least 16KB
            ByteBuffer newBuffer = ByteBuffer.allocateDirect(16384);
            buffer.flip();
            newBuffer.put(buffer);
            buffer = newBuffer;
            state.inputBuffer = buffer;
            buffer.flip();
        }
        
        HttpProxy.HttpConnectResponse response = HttpProxy.processHttpConnectResponse(buffer);
        
        logInfo(response.message);
        
        if (!response.success) {
            if (response.message.contains("Incomplete") || response.message.contains("waiting for more data")) {
                // Need to buffer data and wait for more
                if (response.bodyData != null) {
                    state.outputBuffer = response.bodyData;
                }
                return;
            }
            
            // Connection failed
            logError(response.message);
            
            if (state.socksVersion == 5) {
                Socks5.sendSocks5ErrorResponse(clientChannel, (byte) 1); // General failure
            } else {
                Socks4.sendSocks4ErrorResponse(clientChannel, (byte) 91); // Rejected
            }
            
            closeConnection(clientChannel);
            return;
        }
        
        // Successfully connected
        logInfo("HTTP CONNECT successful");
        
        // Send success response
        if (state.socksVersion == 5) {
            Socks5.sendSocks5SuccessResponse(clientChannel);
        } else {
            Socks4.sendSocks4SuccessResponse(clientChannel);
        }
        
        state.stage = ConnectionStage.PROXY_CONNECTED;
        
        // If there's body data after the headers, forward it to the client
        if (response.bodyData != null && response.bodyData.hasRemaining()) {
            clientChannel.write(response.bodyData);
        }
    }

    /**
     * Set whether to use random proxy selection instead of round-robin
     */
    public void setUseRandomProxySelection(boolean useRandom) {
        if (this.useRandomProxySelection != useRandom) {
            this.useRandomProxySelection = useRandom;
            logInfo("Proxy selection mode set to: " + (useRandom ? "Random" : "Round-Robin"));
        }
    }
} 