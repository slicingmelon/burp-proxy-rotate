package slicingmelon.burpsocksrotate;

import burp.api.montoya.logging.Logging;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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
        
        logInfo("Settings updated: bufferSize=" + bufferSize + ", connectionTimeout=" + connectionTimeout + 
                "ms, socketTimeout=" + socketTimeout + "ms, maxRetryCount=" + maxRetryCount + 
                ", maxThreads=" + maxThreads);
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
     * Starts the SOCKS proxy rotation service.
     */
    public void start(int port, Runnable onSuccess, Consumer<String> onFailure) {
        if (serverRunning) {
            logInfo("Server is already running.");
            return;
        }

        this.localPort = port;
        
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
                        threadPool.execute(() -> handleConnection(clientSocket));
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

        serverRunning = false;

        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
                logInfo("Server socket closed.");
            }
        } catch (IOException e) {
            logError("Error closing server socket: " + e.getMessage());
        }

        if (threadPool != null) {
            threadPool.shutdownNow();
            logInfo("Thread pool shut down.");
        }

        if (serverThread != null && serverThread.isAlive()) {
            try {
                serverThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        serverSocket = null;
        threadPool = null;
        serverThread = null;

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
        connectAndRelay(clientSocket, targetHost, targetPort, 5, addressType);
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
        connectAndRelay(clientSocket, targetHost, targetPort, 4, (byte) 1);
    }

    /**
     * Connects to the target through a randomly selected proxy and relays data.
     */
    private void connectAndRelay(Socket clientSocket, String targetHost, int targetPort, 
                                int socksVersion, byte addressType) throws IOException {
        InputStream clientIn = clientSocket.getInputStream();
        OutputStream clientOut = clientSocket.getOutputStream();
        
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
            logInfo("Selected proxy: " + proxyKey + 
                    " for target: " + targetHost + ":" + targetPort + 
                    (attempt > 0 ? " (attempt " + (attempt + 1) + ")" : ""));
            
            Socket proxySocket = null;
            
            try {
                // Create a new connection to the SOCKS proxy
                proxySocket = new Socket();
                proxySocket.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()), connectionTimeout);
                proxySocket.setSoTimeout(socketTimeout);
                proxySocket.setTcpNoDelay(true); // Disable Nagle's algorithm
                proxySocket.setReceiveBufferSize(bufferSize);
                proxySocket.setSendBufferSize(bufferSize);
                
                InputStream proxyIn = proxySocket.getInputStream();
                OutputStream proxyOut = proxySocket.getOutputStream();
                
                if (socksVersion == 5) {
                    // SOCKS5 to proxy
                    
                    // Send greeting
                    proxyOut.write(new byte[] {5, 1, 0}); // Version, 1 method, No auth
                    proxyOut.flush();
                    
                    // Read response
                    byte[] response = new byte[2];
                    int read = proxyIn.read(response);
                    
                    if (read != 2 || response[0] != 5 || response[1] != 0) {
                        throw new IOException("Proxy authentication failed or not a SOCKS5 proxy");
                    }
                
                    // Send connection request to proxy
                    byte[] request;
                    
                    if (addressType == 1) { // IPv4
                        request = new byte[10];
                        request[0] = 5; // Version
                        request[1] = 1; // CONNECT command
                        request[2] = 0; // Reserved
                        request[3] = 1; // IPv4 address type
                        
                        // Parse IPv4 address
                        String[] parts = targetHost.split("\\.");
                        for (int i = 0; i < 4; i++) {
                            request[4 + i] = (byte) Integer.parseInt(parts[i]);
                        }
                        
                        // Set port (big endian)
                        request[8] = (byte) ((targetPort >> 8) & 0xff);
                        request[9] = (byte) (targetPort & 0xff);
                    } else if (addressType == 4) { // IPv6
                        request = new byte[22];
                        request[0] = 5;
                        request[1] = 1;
                        request[2] = 0;
                        request[3] = 4;
                        
                        // Parse simplified IPv6 address
                        String[] parts = targetHost.split(":");
                        int index = 4;
                        for (String part : parts) {
                            if (part.length() > 0 && index < 20) {
                                int value = Integer.parseInt(part, 16);
                                request[index++] = (byte) ((value >> 8) & 0xff);
                                request[index++] = (byte) (value & 0xff);
                            }
                        }
                        
                        // Set port
                        request[20] = (byte) ((targetPort >> 8) & 0xff);
                        request[21] = (byte) (targetPort & 0xff);
                    } else { // Domain name (type 3)
                        byte[] domain = targetHost.getBytes();
                        request = new byte[7 + domain.length];
                        request[0] = 5;
                        request[1] = 1;
                        request[2] = 0;
                        request[3] = 3;
                        request[4] = (byte) domain.length;
                        
                        // Copy domain
                        System.arraycopy(domain, 0, request, 5, domain.length);
                        
                        // Set port
                        request[5 + domain.length] = (byte) ((targetPort >> 8) & 0xff);
                        request[6 + domain.length] = (byte) (targetPort & 0xff);
                    }
                    
                    // Send request
                    proxyOut.write(request);
                    proxyOut.flush();
                    
                    // Read response
                    byte[] connResponse = new byte[4];
                    int readBytes = proxyIn.read(connResponse);
                    
                    if (readBytes != 4 || connResponse[0] != 5 || connResponse[1] != 0) {
                        String errorCode = (readBytes > 1) ? Byte.toString(connResponse[1]) : "unknown error";
                        throw new IOException("Connection request failed: " + errorCode);
                    }
                    
                    // Skip the rest of the response
                    byte respAddressType = connResponse[3];
                    int skipBytes = 0;
                    
                    switch (respAddressType) {
                        case 1: // IPv4
                            skipBytes = 4 + 2; // IPv4 + port
                            break;
                        case 3: // Domain
                            int domainLength = proxyIn.read();
                            skipBytes = domainLength + 2; // Domain + port
                            break;
                        case 4: // IPv6
                            skipBytes = 16 + 2; // IPv6 + port
                            break;
                    }
                    
                    // Skip bytes
                    byte[] skipBuffer = new byte[skipBytes];
                    proxyIn.read(skipBuffer);
                    
                    // Send success to client
                    sendSocks5SuccessResponse(clientOut);
                    
                } else if (socksVersion == 4) {
                    // SOCKS4 to proxy
                    
                    // Send connection request
                    proxyOut.write(new byte[] {
                        4, // Version
                        1, // CONNECT
                        (byte) ((targetPort >> 8) & 0xff), // Port high byte
                        (byte) (targetPort & 0xff) // Port low byte
                    });
                    
                    // Send IP or 0.0.0.x for SOCKS4A
                    if (addressType == 1) { // IPv4
                        String[] parts = targetHost.split("\\.");
                        for (String part : parts) {
                            proxyOut.write(Integer.parseInt(part) & 0xff);
                        }
                    } else {
                        // SOCKS4A for domain names
                        proxyOut.write(new byte[] {0, 0, 0, 1});
                    }
                    
                    // Null-terminated user ID
                    proxyOut.write(0);
                    
                    // For SOCKS4A with domain, send domain
                    if (addressType != 1) {
                        for (byte b : targetHost.getBytes()) {
                            proxyOut.write(b);
                        }
                        proxyOut.write(0); // Null-terminate domain
                    }
                    
                    proxyOut.flush();
                    
                    // Read response
                    byte[] response = new byte[8];
                    int read = proxyIn.read(response);
                    
                    if (read != 8 || response[0] != 0 || response[1] != 90) {
                        throw new IOException("SOCKS4 connection failed: " + response[1]);
                    }
                    
                    // Send success to client
                    sendSocks4SuccessResponse(clientOut);
                }
                
                // Start bidirectional relay
                relay(clientSocket, proxySocket);
                
                // Connection succeeded, exit retry loop
                return;
                
            } catch (IOException e) {
                logError("Connection through proxy " + proxy.getHost() + ":" + proxy.getPort() + 
                         " failed: " + e.getMessage());
                
                // Don't mark proxy as inactive here - only manual validation should do this
                
                // Close this proxy socket and try another
                closeSocketQuietly(proxySocket);
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
    private void relay(Socket clientSocket, Socket proxySocket) throws IOException {
        // Create threads to handle bidirectional data flow
        Thread clientToProxy = createRelayThread(clientSocket, proxySocket, "client -> proxy");
        Thread proxyToClient = createRelayThread(proxySocket, clientSocket, "proxy -> client");
        
        // Start the threads
        clientToProxy.start();
        proxyToClient.start();
        
        // Wait for both threads to finish
        try {
            clientToProxy.join();
            proxyToClient.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // Always close both sockets when done
        closeSocketQuietly(proxySocket);
        closeSocketQuietly(clientSocket);
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
                
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                    out.flush();
                }
            } catch (IOException e) {
                // Normal when connection closes
            }
        }, "Relay-" + description);
    }

    /**
     * Selects a random active proxy.
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
} 