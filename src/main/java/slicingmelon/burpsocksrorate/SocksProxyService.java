package slicingmelon.burpsocksrorate;

import burp.api.montoya.logging.Logging;

import javax.swing.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReadWriteLock;

public class SocksProxyService {

    private final Logging logging;
    private final List<ProxyEntry> proxyList;
    private final ReadWriteLock proxyListLock;
    private final Random random = new Random();

    // Configuration
    private int bufferSize;
    private int connectionTimeout;
    private int dataTimeout;
    private boolean verboseLogging;
    private int maxConnections;
    private int maxPooledConnectionsPerProxy;
    private int localPort;

    // Server state
    private ServerSocket serverSocket;
    private Thread serverThread;
    private ExecutorService threadPool;
    private volatile boolean serverRunning = false;

    // Connection pooling
    private final Map<String, Queue<Socket>> proxyConnectionPool = new ConcurrentHashMap<>();

    public SocksProxyService(List<ProxyEntry> proxyList, ReadWriteLock proxyListLock, Logging logging,
                             int bufferSize, int connectionTimeout, int dataTimeout, boolean verboseLogging,
                             int maxConnections, int maxPooledConnectionsPerProxy) {
        this.proxyList = proxyList;
        this.proxyListLock = proxyListLock;
        this.logging = logging;
        this.bufferSize = bufferSize;
        this.connectionTimeout = connectionTimeout;
        this.dataTimeout = dataTimeout;
        this.verboseLogging = verboseLogging;
        this.maxConnections = maxConnections;
        this.maxPooledConnectionsPerProxy = maxPooledConnectionsPerProxy;
    }

    public boolean isRunning() {
        return serverRunning;
    }
    
    public int getLocalPort() {
        return localPort;
    }

    public void start(int port) {
        if (serverRunning) {
            logInfo("Server is already running.");
            return;
        }

        this.localPort = port;

        // Use a fixed thread pool based on maxConnections
        threadPool = Executors.newFixedThreadPool(maxConnections);

        // Initialize connection pool
        initializeConnectionPool();

        serverThread = new Thread(() -> {
            try {
                serverSocket = new ServerSocket(localPort);
                serverRunning = true;

                logInfo("SOCKS Proxy Rotator server started on localhost:" + localPort);

                while (serverRunning && !serverSocket.isClosed()) {
                    try {
                        Socket clientSocket = serverSocket.accept();
                        clientSocket.setTcpNoDelay(true); // Disable Nagle's algorithm
                        clientSocket.setSoTimeout(dataTimeout);
                        threadPool.execute(() -> handleSocksConnection(clientSocket));
                    } catch (IOException e) {
                        if (serverRunning) {
                            logError("Error accepting connection: " + e.getMessage());
                        }
                    }
                }
            } catch (IOException e) {
                logError("Error starting server: " + e.getMessage());
                SwingUtilities.invokeLater(() -> 
                    JOptionPane.showMessageDialog(null,
                        "Failed to start proxy server: " + e.getMessage(),
                        "Server Error",
                        JOptionPane.ERROR_MESSAGE)
                );
                serverRunning = false;
                // Consider adding a callback or event to notify the UI about the state change
            } finally {
                 serverRunning = false; // Ensure state is updated if loop exits unexpectedly
                 logInfo("Server thread finished.");
            }
        });

        serverThread.start();
    }

    public void stop() {
        if (!serverRunning) {
            logInfo("Server is not running.");
            return;
        }

        serverRunning = false; // Signal the server loop to stop

        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close(); // Force close the socket to interrupt accept()
                logInfo("Server socket closed.");
            }
        } catch (IOException e) {
            logError("Error closing server socket: " + e.getMessage());
        }

        if (threadPool != null) {
            threadPool.shutdownNow(); // Attempt to stop all executing tasks
            logInfo("Thread pool shut down.");
        }
        
        // Close all pooled connections
        closeAllPooledConnections();
        logInfo("Closed pooled connections.");

        // Wait for the server thread to finish (optional, with timeout)
        if (serverThread != null && serverThread.isAlive()) {
             try {
                 serverThread.join(1000); // Wait max 1 second
                 if (serverThread.isAlive()) {
                     logError("Server thread did not terminate gracefully.");
                     // Optionally interrupt if still alive: serverThread.interrupt();
                 }
             } catch (InterruptedException e) {
                 Thread.currentThread().interrupt();
                 logError("Interrupted while waiting for server thread to stop.");
             }
        }
        
        serverSocket = null;
        threadPool = null;
        serverThread = null;

        logInfo("SOCKS Proxy Rotator server stopped.");
    }

    private void handleSocksConnection(Socket clientSocket) {
        Socket upstreamSocket = null;
        try {
            clientSocket.setReceiveBufferSize(bufferSize);
            clientSocket.setSendBufferSize(bufferSize);

            InputStream clientIn = clientSocket.getInputStream();
            OutputStream clientOut = clientSocket.getOutputStream();

            // SOCKS5 Greeting
            byte[] buffer = new byte[1024];
            int read = clientIn.read(buffer, 0, 2);
            if (read != 2 || buffer[0] != 0x05) {
                if (verboseLogging) logDebug("Invalid SOCKS protocol version");
                return; // Close handled in finally
            }

            int numMethods = buffer[1] & 0xFF;
            read = clientIn.read(buffer, 0, numMethods);
            if (read != numMethods) {
                if (verboseLogging) logDebug("Failed to read authentication methods");
                return;
            }

            // Send SOCKS5 Response (No Auth)
            clientOut.write(new byte[]{0x05, 0x00});

            // Read Connection Request
            read = clientIn.read(buffer, 0, 4);
            if (read != 4 || buffer[0] != 0x05 || buffer[1] != 0x01) { // CONNECT command
                if (verboseLogging) logDebug("Invalid SOCKS connection request");
                return;
            }

            // Parse Target Address
            int addressType = buffer[3] & 0xFF;
            String targetHost;
            int targetPort;

            switch (addressType) {
                case 0x01: // IPv4
                    byte[] ipv4 = new byte[4];
                    if (clientIn.read(ipv4) != 4) {
                        if (verboseLogging) logDebug("Failed to read IPv4 address"); return;
                    }
                    targetHost = (ipv4[0] & 0xFF) + "." + (ipv4[1] & 0xFF) + "." + (ipv4[2] & 0xFF) + "." + (ipv4[3] & 0xFF);
                    break;
                case 0x03: // Domain name
                    int domainLength = clientIn.read() & 0xFF;
                    byte[] domain = new byte[domainLength];
                     if (clientIn.read(domain) != domainLength) {
                        if (verboseLogging) logDebug("Failed to read domain name"); return;
                    }
                    targetHost = new String(domain);
                    break;
                case 0x04: // IPv6 (Unsupported for now)
                     if (verboseLogging) logDebug("IPv6 addresses not supported yet");
                     // Read and discard IPv6 + port
                     clientIn.read(new byte[16+2]);
                     return;
                default:
                    if (verboseLogging) logDebug("Unsupported address type: " + addressType); return;
            }

            // Read Target Port
            byte[] portBytes = new byte[2];
            if (clientIn.read(portBytes) != 2) {
                if (verboseLogging) logDebug("Failed to read port"); return;
            }
            targetPort = ((portBytes[0] & 0xFF) << 8) | (portBytes[1] & 0xFF);

            // Get Upstream Proxy
            ProxyEntry proxy = getRandomProxy();
            if (proxy == null) {
                logError("No active proxies available");
                // TODO: Send SOCKS error response to client? (e.g., Host unreachable)
                return;
            }

            if (verboseLogging) {
                logDebug("Routing " + targetHost + ":" + targetPort + " via " + proxy.getHost() + ":" + proxy.getPort());
            }

            // Connect to Upstream Proxy
            upstreamSocket = getProxyConnection(proxy); // Throws IOException on failure
            InputStream upstreamIn = upstreamSocket.getInputStream();
            OutputStream upstreamOut = upstreamSocket.getOutputStream();

            // Upstream SOCKS5 Handshake (No Auth)
            upstreamOut.write(new byte[]{0x05, 0x01, 0x00});
            read = upstreamIn.read(buffer, 0, 2);
            if (read != 2 || buffer[0] != 0x05 || buffer[1] != 0x00) {
                if (verboseLogging) logDebug("Upstream proxy handshake failed");
                // Mark proxy as potentially bad?
                closeSocketQuietly(upstreamSocket); // Close upstream before returning
                upstreamSocket = null;
                return;
            }

            // Forward Connection Request to Upstream
            upstreamOut.write(new byte[]{0x05, 0x01, 0x00, (byte) addressType}); // CMD=CONNECT, RSV=0
            if (addressType == 0x01) { // IPv4
                String[] parts = targetHost.split("\\.");
                for (String part : parts) upstreamOut.write(Integer.parseInt(part) & 0xFF);
            } else if (addressType == 0x03) { // Domain
                upstreamOut.write(targetHost.length() & 0xFF);
                upstreamOut.write(targetHost.getBytes());
            }
            upstreamOut.write((targetPort >> 8) & 0xFF);
            upstreamOut.write(targetPort & 0xFF);

            // Read Upstream Response
            read = upstreamIn.read(buffer, 0, 4); // VER, REP, RSV, ATYP
            if (read != 4 || buffer[0] != 0x05 || buffer[1] != 0x00) { // Check for success reply (0x00)
                if (verboseLogging) logDebug("Upstream proxy connection failed (Reply: " + (read < 2 ? "N/A" : buffer[1]) + ")");
                 // Mark proxy as potentially bad?
                closeSocketQuietly(upstreamSocket);
                upstreamSocket = null;
                // TODO: Send appropriate SOCKS error back to client based on buffer[1]
                return;
            }

            // Read and discard bind address/port from upstream response
             int upstreamAtyp = buffer[3] & 0xFF;
             int bytesToSkip = 0;
             if (upstreamAtyp == 0x01) bytesToSkip = 4 + 2; // IPv4 + port
             else if (upstreamAtyp == 0x03) bytesToSkip = (upstreamIn.read() & 0xFF) + 2; // Read len byte + domain + port
             else if (upstreamAtyp == 0x04) bytesToSkip = 16 + 2; // IPv6 + port
             
             if (bytesToSkip > 0) {
                 long skipped = upstreamIn.skip(bytesToSkip);
                 // TODO: check skipped == bytesToSkip if needed
             }


            // Send Success Response to Client
            clientOut.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); // Using IPv4 BND.ADDR placeholder

            // Start Bidirectional Data Transfer
            transferData(clientIn, upstreamOut, clientSocket, upstreamSocket);

            // If transferData completes normally, try to return the upstream connection
            returnProxyConnection(proxy, upstreamSocket);
            upstreamSocket = null; // Mark as returned/handled

        } catch (IOException e) {
            logError("Error handling SOCKS connection for client " + clientSocket.getRemoteSocketAddress() + ": " + e.getMessage());
            // Close upstream if it wasn't returned/closed yet
            closeSocketQuietly(upstreamSocket);
            // Send SOCKS error to client? (e.g., general server failure)
        } finally {
            closeSocketQuietly(clientSocket); // Always close client socket
            // Ensure upstream is closed if not returned
             if (upstreamSocket != null) {
                 closeSocketQuietly(upstreamSocket);
             }
        }
    }
    
    // Helper for bidirectional data transfer
    private void transferData(InputStream in1, OutputStream out1, Socket sock1, Socket sock2) {
        ExecutorService transferExecutor = Executors.newFixedThreadPool(2);
        AtomicBoolean transferComplete = new AtomicBoolean(false);
        byte[] buffer1 = new byte[bufferSize];
        byte[] buffer2 = new byte[bufferSize];

        Runnable transfer1to2 = () -> {
            try {
                int bytesRead;
                while (!transferComplete.get() && (bytesRead = in1.read(buffer1)) != -1) {
                    out1.write(buffer1, 0, bytesRead);
                    out1.flush();
                }
            } catch (IOException e) {
                 if(serverRunning && !sock1.isClosed() && !sock2.isClosed()) { // Avoid logging errors during shutdown or normal closure
                    //logDebug("Transfer 1->2 error: " + e.getMessage());
                 }
            } finally {
                transferComplete.set(true);
                closeSocketQuietly(sock1); // Close associated sockets on completion/error
                closeSocketQuietly(sock2);
            }
        };

        Runnable transfer2to1 = () -> {
             try {
                 int bytesRead;
                 InputStream in2 = sock2.getInputStream(); // Get input stream for socket 2
                 OutputStream out2 = sock1.getOutputStream(); // Get output stream for socket 1
                 while (!transferComplete.get() && (bytesRead = in2.read(buffer2)) != -1) {
                     out2.write(buffer2, 0, bytesRead);
                     out2.flush();
                 }
             } catch (IOException e) {
                  if(serverRunning && !sock1.isClosed() && !sock2.isClosed()) {
                     //logDebug("Transfer 2->1 error: " + e.getMessage());
                  }
             } finally {
                 transferComplete.set(true);
                 closeSocketQuietly(sock1);
                 closeSocketQuietly(sock2);
             }
         };

        transferExecutor.submit(transfer1to2);
        transferExecutor.submit(transfer2to1);
        transferExecutor.shutdown(); // Allow submitted tasks to complete

         // Wait for transfer to complete (or timeout) - This might block the handler thread
         // Consider if this blocking is acceptable or if the handler should return earlier.
         // For simplicity, we'll let it block here. The transferComplete flag and socket closing
         // should eventually terminate the loops.
    }


    // Initialize connection pool
    private void initializeConnectionPool() {
        closeAllPooledConnections(); // Clear existing connections first
        proxyListLock.readLock().lock();
        try {
            for (ProxyEntry proxy : proxyList) {
                if (proxy.isActive()) {
                    proxyConnectionPool.put(
                        proxy.getHost() + ":" + proxy.getPort(),
                        new ConcurrentLinkedQueue<>()
                    );
                }
            }
            logInfo("Connection pool initialized for active proxies.");
        } finally {
            proxyListLock.readLock().unlock();
        }
    }

    // Get a connection from the pool or create a new one
    private Socket getProxyConnection(ProxyEntry proxy) throws IOException {
        String key = proxy.getHost() + ":" + proxy.getPort();
        Queue<Socket> pool = proxyConnectionPool.get(key);

        if (pool != null) {
            Socket socket = pool.poll();
            if (socket != null && socket.isConnected() && !socket.isClosed()) {
                // Basic check if connection is still alive (send a byte?) - Optional
                try {
                    socket.setSoTimeout(100); // Quick check timeout
                    socket.getInputStream().available(); // Simple check, might not be reliable
                    socket.setSoTimeout(dataTimeout); // Restore original timeout
                    if (verboseLogging) logDebug("Reusing pooled connection to " + key);
                    return socket;
                } catch (IOException e) {
                    if (verboseLogging) logDebug("Pooled connection to " + key + " seems dead. Closing.");
                    closeSocketQuietly(socket);
                    // Continue to create a new one
                }
            }
        }

        // Create a new connection if pool is empty or connection was dead
        if (verboseLogging) logDebug("Creating new connection to " + key);
        Socket socket = new Socket();
        socket.setTcpNoDelay(true);
        socket.setReceiveBufferSize(bufferSize);
        socket.setSendBufferSize(bufferSize);
        socket.setSoTimeout(dataTimeout); // Set data timeout *after* connecting
        try {
            socket.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()), connectionTimeout);
            // Successfully connected, now set the data timeout
             socket.setSoTimeout(dataTimeout);
        } catch (IOException e) {
             logError("Failed to connect to upstream proxy " + key + ": " + e.getMessage());
             closeSocketQuietly(socket); // Ensure socket is closed on connection failure
             throw e; // Re-throw exception
        }

        return socket;
    }

    // Return a connection to the pool
    private void returnProxyConnection(ProxyEntry proxy, Socket socket) {
        if (socket == null || socket.isClosed() || !socket.isConnected()) {
             if (verboseLogging) logDebug("Attempted to return invalid socket to pool for " + proxy.getHost() + ":" + proxy.getPort());
            return;
        }

        String key = proxy.getHost() + ":" + proxy.getPort();
        Queue<Socket> pool = proxyConnectionPool.get(key);

        // Check if the pool exists and has space
        if (pool != null && pool.size() < maxPooledConnectionsPerProxy) {
             // Optionally reset socket state (e.g., clear remaining data in buffer?)
            try {
                 // Clear any potential remaining data in input buffer before pooling
                 InputStream is = socket.getInputStream();
                 while (is.available() > 0) {
                     is.skip(is.available());
                 }
                pool.offer(socket);
                if (verboseLogging) logDebug("Returned connection to pool: " + key + " (Pool size: " + pool.size() + ")");
            } catch (IOException e) {
                 logError("Error preparing socket for pooling (" + key + "): " + e.getMessage());
                 closeSocketQuietly(socket); // Close if error occurs during prep
            }
        } else {
             if (verboseLogging) {
                 String reason = (pool == null) ? "pool doesn't exist (proxy inactive?)" : "pool full";
                 logDebug("Closing connection instead of pooling (" + key + "): " + reason);
             }
            closeSocketQuietly(socket); // Close if pool doesn't exist or is full
        }
    }

    // Close all pooled connections
    private void closeAllPooledConnections() {
        logInfo("Closing all pooled connections...");
        int closedCount = 0;
        for (Queue<Socket> pool : proxyConnectionPool.values()) {
            Socket socket;
            while ((socket = pool.poll()) != null) {
                closeSocketQuietly(socket);
                closedCount++;
            }
        }
        proxyConnectionPool.clear(); // Ensure the map itself is cleared
        logInfo("Closed " + closedCount + " pooled connections.");
    }

    private ProxyEntry getRandomProxy() {
        proxyListLock.readLock().lock();
        try {
            if (proxyList.isEmpty()) {
                return null;
            }

            List<ProxyEntry> activeProxies = new ArrayList<>();
            for (ProxyEntry proxy : proxyList) {
                if (proxy.isActive()) {
                    activeProxies.add(proxy);
                }
            }

            if (activeProxies.isEmpty()) {
                return null; // No active proxies
            }

            return activeProxies.get(random.nextInt(activeProxies.size()));
        } finally {
            proxyListLock.readLock().unlock();
        }
    }
    
    // Helper method to close socket without throwing checked exceptions
    private void closeSocketQuietly(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException e) {
                // Ignore in quiet close
                 //logError("Error closing socket quietly: " + e.getMessage()); // Optional logging
            }
        }
    }

    // Logging helpers
    private void logInfo(String message) {
        logging.logToOutput("[INFO] " + message);
    }

    private void logError(String message) {
        logging.logToError("[ERROR] " + message);
    }

    private void logDebug(String message) {
        if (verboseLogging) {
            logging.logToOutput("[DEBUG] " + message);
        }
    }
} 