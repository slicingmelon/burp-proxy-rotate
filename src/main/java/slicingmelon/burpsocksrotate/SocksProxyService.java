package slicingmelon.burpsocksrotate;

import burp.api.montoya.logging.Logging;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Consumer;

/**
 * A service that randomly rotates SOCKS proxies for Burp Suite.
 * For each new connection, a different active SOCKS proxy is chosen.
 */
public class SocksProxyService {
    // Default settings
    private int bufferSize = 16384; // 16KB
    private int connectionTimeout = 30000; // 30 seconds
    private int socketTimeout = 60000; // 60 seconds
    private int maxRetryCount = 2; // Number of proxies to try before giving up
    private int maxThreads = 20; // Maximum number of threads
    private int maxConnectionsPerProxy = 10; // Maximum connections per proxy
    private int idleTimeoutSec = 60; // Idle timeout in seconds
    
    // Dependencies
    private final Logging logging;
    private final List<ProxyEntry> proxyList;
    private final ReadWriteLock proxyListLock;
    private final Random random = new Random();
    
    // Server state
    private ServerSocket serverSocket;
    private Thread serverThread;
    private ExecutorService threadPool;
    private volatile boolean serverRunning = false;
    private int localPort;
    
    // Connection tracking
    private final Set<Socket> activeClientSockets = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Set<Thread> activeRelayThreads = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final AtomicInteger activeConnectionCount = new AtomicInteger(0);
    
    // Connection pool and socket factory
    private ProxyConnectionPool connectionPool;
    private ProxySocketFactory socketFactory;
    
    // Reference to main extension for UI callbacks
    private BurpSocksRotate extension;

    /**
     * Creates a new SocksProxyService.
     */
    public SocksProxyService(List<ProxyEntry> proxyList, ReadWriteLock proxyListLock, Logging logging) {
        this.proxyList = proxyList;
        this.proxyListLock = proxyListLock;
        this.logging = logging;
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
    public void setSettings(int bufferSize, int connectionTimeout, int socketTimeout, int maxRetryCount, int maxThreads) {
        this.bufferSize = bufferSize;
        this.connectionTimeout = connectionTimeout;
        this.socketTimeout = socketTimeout;
        this.maxRetryCount = maxRetryCount;
        this.maxThreads = maxThreads;
        
        // Derive connection pool settings
        this.maxConnectionsPerProxy = Math.max(5, maxThreads / 2);
        this.idleTimeoutSec = Math.max(30, socketTimeout / 2000); // Half of socket timeout, but minimum 30 seconds
        
        logInfo("Settings updated: bufferSize=" + bufferSize + ", connectionTimeout=" + connectionTimeout + 
                "ms, socketTimeout=" + socketTimeout + "ms, maxRetryCount=" + maxRetryCount + 
                ", maxThreads=" + maxThreads + ", maxConnectionsPerProxy=" + maxConnectionsPerProxy +
                ", idleTimeoutSec=" + idleTimeoutSec);
    }

    /**
     * Sets the service settings with explicit connection pool settings.
     */
    public void setSettings(int bufferSize, int connectionTimeout, int socketTimeout, 
                          int maxRetryCount, int maxThreads, int maxConnectionsPerProxy, int idleTimeoutSec) {
        this.bufferSize = bufferSize;
        this.connectionTimeout = connectionTimeout;
        this.socketTimeout = socketTimeout;
        this.maxRetryCount = maxRetryCount;
        this.maxThreads = maxThreads;
        this.maxConnectionsPerProxy = maxConnectionsPerProxy;
        this.idleTimeoutSec = idleTimeoutSec;
        
        logInfo("Settings updated: bufferSize=" + bufferSize + ", connectionTimeout=" + connectionTimeout + 
                "ms, socketTimeout=" + socketTimeout + "ms, maxRetryCount=" + maxRetryCount + 
                ", maxThreads=" + maxThreads + ", maxConnectionsPerProxy=" + maxConnectionsPerProxy +
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
     * Starts the SOCKS proxy rotation service.
     */
    public void start(int port, Runnable onSuccess, Consumer<String> onFailure) {
        if (serverRunning) {
            logInfo("Server is already running.");
            return;
        }

        this.localPort = port;
        
        // Create the connection pool
        connectionPool = new ProxyConnectionPool(
            maxConnectionsPerProxy,
            connectionTimeout,
            socketTimeout,
            idleTimeoutSec,
            bufferSize,
            logging
        );
        
        // Create socket factory
        socketFactory = new ProxySocketFactory(logging, connectionTimeout);
        
        // Create a thread pool with a reasonable number of threads
        threadPool = Executors.newFixedThreadPool(maxThreads);

        serverThread = new Thread(() -> {
            try {
                serverSocket = new ServerSocket(localPort);
                serverRunning = true;
                logInfo("SOCKS Proxy Rotator server started on localhost:" + localPort);
                
                // Signal success
                onSuccess.run();

                while (serverRunning && !serverSocket.isClosed()) {
                    try {
                        Socket clientSocket = serverSocket.accept();
                        clientSocket.setSoTimeout(socketTimeout);
                        
                        // Track this client socket
                        activeClientSockets.add(clientSocket);
                        activeConnectionCount.incrementAndGet();
                        
                        threadPool.execute(() -> {
                            try {
                                handleConnection(clientSocket);
                            } finally {
                                // Cleanup after connection handling is done
                                closeSocketQuietly(clientSocket);
                                activeClientSockets.remove(clientSocket);
                                activeConnectionCount.decrementAndGet();
                            }
                        });
                    } catch (IOException e) {
                        if (serverRunning) {
                            logError("Error accepting connection: " + e.getMessage());
                        }
                    }
                }
            } catch (IOException e) {
                logError("Error starting server: " + e.getMessage());
                serverRunning = false;
                onFailure.accept(e.getMessage());
            } finally {
                serverRunning = false;
                logInfo("Server thread finished.");
            }
        });

        serverThread.start();
    }

    /**
     * Stops the SOCKS proxy rotation service.
     */
    public void stop() {
        if (!serverRunning) {
            logInfo("Server is not running.");
            return;
        }

        logInfo("Stopping SOCKS Proxy Rotator server...");
        serverRunning = false;
        
        // First, close the server socket to prevent new connections
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
                logInfo("Server socket closed.");
            }
        } catch (IOException e) {
            logError("Error closing server socket: " + e.getMessage());
        }
        
        // Shutdown the thread pool and wait a bit for tasks to complete
        if (threadPool != null) {
            threadPool.shutdown();
            try {
                // Wait for tasks to complete, but don't wait forever
                if (!threadPool.awaitTermination(5, TimeUnit.SECONDS)) {
                    logInfo("Forcing thread pool shutdown...");
                    threadPool.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                threadPool.shutdownNow();
            }
            logInfo("Thread pool shut down.");
        }

        // Interrupt all relay threads
        for (Thread thread : new ArrayList<>(activeRelayThreads)) {
            try {
                thread.interrupt();
            } catch (Exception e) {
                // Ignore - just trying to clean up
            }
        }
        activeRelayThreads.clear();

        // Close all active client sockets
        int closedClientSockets = 0;
        for (Socket socket : new ArrayList<>(activeClientSockets)) {
            try {
                socket.close();
                closedClientSockets++;
            } catch (IOException e) {
                // Ignore - just trying to clean up
            }
        }
        activeClientSockets.clear();
        
        // Shutdown the connection pool
        if (connectionPool != null) {
            connectionPool.shutdown();
            connectionPool = null;
        }
        
        // Reset active connection count
        activeConnectionCount.set(0);
        
        logInfo("Closed " + closedClientSockets + " client socket(s).");
        
        // Clean up final resources
        if (serverThread != null && serverThread.isAlive()) {
            try {
                serverThread.join(2000);
                if (serverThread.isAlive()) {
                    serverThread.interrupt();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        serverSocket = null;
        threadPool = null;
        serverThread = null;
        socketFactory = null;

        logInfo("SOCKS Proxy Rotator server stopped.");
    }

    /**
     * Handles an incoming connection.
     */
    private void handleConnection(Socket clientSocket) {
        try {
            InputStream clientIn = clientSocket.getInputStream();
            OutputStream clientOut = clientSocket.getOutputStream();
            
            // Read first byte to determine SOCKS version
            int version = clientIn.read();
            
            if (version == 5) {
                // SOCKS5 Protocol
                handleSocks5Connection(clientSocket, clientIn, clientOut);
            } else if (version == 4) {
                // SOCKS4 Protocol
                handleSocks4Connection(clientSocket, clientIn, clientOut, version);
            } else {
                logError("Unsupported SOCKS version: " + version);
            }
        } catch (IOException e) {
            logError("Error handling connection: " + e.getMessage());
        } finally {
            closeSocketQuietly(clientSocket);
        }
    }

    /**
     * Handles a SOCKS5 connection.
     */
    private void handleSocks5Connection(Socket clientSocket, InputStream clientIn, OutputStream clientOut) throws IOException {
        // Read authentication methods
        int numMethods = clientIn.read();
        byte[] methods = new byte[numMethods];
        clientIn.read(methods);
        
        // Send authentication method response (no auth required)
        clientOut.write(new byte[] {5, 0});
        clientOut.flush();
        
        // Read connection request
        byte[] request = new byte[4];
        clientIn.read(request);
        
        if (request[0] != 5) {
            logError("Invalid SOCKS5 request version");
            return;
        }
        
        byte command = request[1];
        if (command != 1) {
            // Only support CONNECT command (1)
            sendSocks5ErrorResponse(clientOut, (byte) 7); // Command not supported
            logError("Unsupported SOCKS5 command: " + command);
            return;
        }
        
        // Read address type
        byte addressType = request[3];
        
        // Parse target address and port
        String targetHost;
        int targetPort;
        
        switch (addressType) {
            case 1: // IPv4
                byte[] ipv4 = new byte[4];
                clientIn.read(ipv4);
                targetHost = (ipv4[0] & 0xff) + "." + (ipv4[1] & 0xff) + "." + 
                            (ipv4[2] & 0xff) + "." + (ipv4[3] & 0xff);
                break;
                
            case 3: // Domain name
                int domainLength = clientIn.read();
                byte[] domain = new byte[domainLength];
                clientIn.read(domain);
                targetHost = new String(domain);
                break;
                
            case 4: // IPv6
                byte[] ipv6 = new byte[16];
                clientIn.read(ipv6);
                // Format IPv6 address
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 16; i += 2) {
                    if (i > 0) sb.append(":");
                    sb.append(String.format("%02x%02x", ipv6[i], ipv6[i+1]));
                }
                targetHost = sb.toString();
                break;
                
            default:
                sendSocks5ErrorResponse(clientOut, (byte) 8); // Address type not supported
                logError("Unsupported address type: " + addressType);
                return;
        }
        
        // Read port (2 bytes, big endian)
        byte[] portBytes = new byte[2];
        clientIn.read(portBytes);
        targetPort = ((portBytes[0] & 0xff) << 8) | (portBytes[1] & 0xff);
        
        // Connect to target through random proxy
        connectAndRelay(clientSocket, clientOut, targetHost, targetPort, 5, addressType);
    }

    /**
     * Handles a SOCKS4 connection.
     */
    private void handleSocks4Connection(Socket clientSocket, InputStream clientIn, OutputStream clientOut, int version) throws IOException {
        // Read command
        int command = clientIn.read();
        
        if (command != 1) {
            // Only support CONNECT command (1)
            sendSocks4ErrorResponse(clientOut, (byte) 91); // Rejected/Failed
            logError("Unsupported SOCKS4 command: " + command);
            return;
        }
        
        // Read port (2 bytes, big endian)
        byte[] portBytes = new byte[2];
        clientIn.read(portBytes);
        int targetPort = ((portBytes[0] & 0xff) << 8) | (portBytes[1] & 0xff);
        
        // Read IPv4 address (4 bytes)
        byte[] ipv4 = new byte[4];
        clientIn.read(ipv4);
        
        String targetHost;
        if (ipv4[0] == 0 && ipv4[1] == 0 && ipv4[2] == 0 && ipv4[3] != 0) {
            // SOCKS4A - domain name is specified
            // Skip user ID
            while (clientIn.read() != 0) {
                // Skip bytes until 0
            }
            
            // Read domain
            StringBuilder domain = new StringBuilder();
            int b;
            while ((b = clientIn.read()) != 0) {
                domain.append((char) b);
            }
            targetHost = domain.toString();
        } else {
            // Regular SOCKS4 - IPv4 address
            targetHost = (ipv4[0] & 0xff) + "." + (ipv4[1] & 0xff) + "." + 
                        (ipv4[2] & 0xff) + "." + (ipv4[3] & 0xff);
            
            // Skip user ID
            while (clientIn.read() != 0) {
                // Skip bytes until 0
            }
        }
        
        // Connect to target through random proxy
        connectAndRelay(clientSocket, clientOut, targetHost, targetPort, 4, (byte) 1);
    }

    /**
     * Connects to the target through a randomly selected proxy and relays data.
     */
    private void connectAndRelay(Socket clientSocket, OutputStream clientOut, 
                               String targetHost, int targetPort, int socksVersion, byte addressType) throws IOException {
        InputStream clientIn = clientSocket.getInputStream();
        ProxyConnectionPool.PooledConnection connection = null;
        
        // Choose random proxy and attempt connection with retries
        for (int attempt = 0; attempt <= maxRetryCount; attempt++) {
            ProxyEntry proxy = selectRandomActiveProxy();
            
            if (proxy == null) {
                logError("No active proxies available");
                if (socksVersion == 5) {
                    sendSocks5ErrorResponse(clientOut, (byte) 1); // General failure
                } else {
                    sendSocks4ErrorResponse(clientOut, (byte) 91); // Rejected
                }
                return;
            }
            
            String proxyKey = proxy.getHost() + ":" + proxy.getPort();
            logInfo("Selected proxy: " + proxy.getProtocol() + "://" + proxyKey + 
                    " for target: " + targetHost + ":" + targetPort + 
                    (attempt > 0 ? " (attempt " + (attempt + 1) + ")" : ""));
            
            try {
                // Get a connection from the pool
                connection = connectionPool.getConnection(proxy);
                
                // Connect through the proxy to the target
                socketFactory.connectThroughProxy(connection, targetHost, targetPort, addressType);
                
                // Send success to client
                if (socksVersion == 5) {
                    sendSocks5SuccessResponse(clientOut);
                } else {
                    sendSocks4SuccessResponse(clientOut);
                }
                
                // Start bidirectional relay
                relay(clientSocket, connection);
                
                // Connection succeeded, exit retry loop
                return;
                
            } catch (IOException e) {
                logError("Connection through proxy " + proxy.getProtocol() + "://" + proxy.getHost() + ":" + proxy.getPort() + 
                         " failed: " + e.getMessage());
                
                // Close and discard this connection - it will be automatically removed from active count
                if (connection != null) {
                    connection.close();
                    connection = null;
                }
            }
        }
        
        // All attempts failed
        if (socksVersion == 5) {
            sendSocks5ErrorResponse(clientOut, (byte) 1); // General failure
        } else {
            sendSocks4ErrorResponse(clientOut, (byte) 91); // Rejected/Failed
        }
        logError("All connection attempts failed for target: " + targetHost + ":" + targetPort);
    }

    /**
     * Relays data between client and proxy with optimized performance.
     */
    private void relay(Socket clientSocket, ProxyConnectionPool.PooledConnection proxyConnection) throws IOException {
        Socket proxySocket = proxyConnection.getSocket();
        
        // Create threads to handle bidirectional data flow
        Thread clientToProxy = createRelayThread(clientSocket, proxySocket, "client -> proxy");
        Thread proxyToClient = createRelayThread(proxySocket, clientSocket, "proxy -> client");
        
        // Add to the active relay threads set for tracking
        activeRelayThreads.add(clientToProxy);
        activeRelayThreads.add(proxyToClient);
        
        // Start the threads
        clientToProxy.start();
        proxyToClient.start();
        
        // Wait for both threads to finish
        try {
            clientToProxy.join();
            activeRelayThreads.remove(clientToProxy);
            
            proxyToClient.join();
            activeRelayThreads.remove(proxyToClient);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            // Interrupt both threads if we're interrupted
            clientToProxy.interrupt();
            proxyToClient.interrupt();
        } finally {
            // Always remove threads from tracking
            activeRelayThreads.remove(clientToProxy);
            activeRelayThreads.remove(proxyToClient);
            
            // Return connection to the pool if it's still valid
            if (proxyConnection.isValid()) {
                proxyConnection.release();
            } else {
                proxyConnection.close();
            }
            
            // Note: We don't close the client socket here as it's managed by the caller
        }
    }

    /**
     * Creates an optimized thread to relay data between two sockets.
     */
    private Thread createRelayThread(Socket source, Socket destination, String description) {
        return new Thread(() -> {
            byte[] buffer = new byte[bufferSize];
            int bytesRead;
            
            try {
                InputStream in = source.getInputStream();
                OutputStream out = destination.getOutputStream();
                
                while (!Thread.currentThread().isInterrupted() && 
                       !source.isClosed() && !destination.isClosed() && 
                       (bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                    out.flush();
                }
            } catch (IOException e) {
                // Normal when connection closes
                if (serverRunning) {
                    logInfo("Relay ended: " + description + " - " + e.getMessage());
                }
            } finally {
                // Don't close sockets here, they're managed by the caller
            }
        }, "Relay-" + description);
    }

    /**
     * Selects a random active proxy.
     * Tries to match the requested SOCKS protocol version if possible.
     */
    private ProxyEntry selectRandomActiveProxy() {
        List<ProxyEntry> activeProxies = new ArrayList<>();
        
        proxyListLock.readLock().lock();
        try {
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
        
        // Select a random proxy
        return activeProxies.get(random.nextInt(activeProxies.size()));
    }

    /**
     * Sends a SOCKS5 error response.
     */
    private void sendSocks5ErrorResponse(OutputStream out, byte errorCode) throws IOException {
        byte[] response = new byte[] {5, errorCode, 0, 1, 0, 0, 0, 0, 0, 0};
        out.write(response);
        out.flush();
    }

    /**
     * Sends a SOCKS5 success response.
     */
    private void sendSocks5SuccessResponse(OutputStream out) throws IOException {
        byte[] response = new byte[] {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
        out.write(response);
        out.flush();
    }

    /**
     * Sends a SOCKS4 error response.
     */
    private void sendSocks4ErrorResponse(OutputStream out, byte errorCode) throws IOException {
        byte[] response = new byte[] {0, errorCode, 0, 0, 0, 0, 0, 0};
        out.write(response);
        out.flush();
    }

    /**
     * Sends a SOCKS4 success response.
     */
    private void sendSocks4SuccessResponse(OutputStream out) throws IOException {
        byte[] response = new byte[] {0, 90, 0, 0, 0, 0, 0, 0};
        out.write(response);
        out.flush();
    }

    /**
     * Quietly closes a socket.
     */
    private void closeSocketQuietly(Socket socket) {
        if (socket != null && !socket.isClosed()) {
            try {
                socket.shutdownInput();
            } catch (IOException e) {
                // Ignore
            }
            
            try {
                socket.shutdownOutput();
            } catch (IOException e) {
                // Ignore
            }
            
            try {
                socket.close();
            } catch (IOException e) {
                // Ignore
            }
        }
    }

    /**
     * Logs an info message.
     */
    private void logInfo(String message) {
        logging.logToOutput("[SocksProxy] " + message);
    }

    /**
     * Logs an error message.
     */
    private void logError(String message) {
        logging.logToError("[SocksProxy] ERROR: " + message);
    }

    /**
     * Gets statistics about the connection pool usage.
     * Only available when the service is running.
     */
    public String getConnectionPoolStats() {
        if (connectionPool != null) {
            return connectionPool.getStats();
        }
        return "Connection pool not active";
    }
} 