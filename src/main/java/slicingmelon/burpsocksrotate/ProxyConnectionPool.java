package slicingmelon.burpsocksrotate;

import burp.api.montoya.logging.Logging;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Manages a pool of reusable SOCKS proxy connections for improved performance.
 */
public class ProxyConnectionPool {
    private final Map<String, Queue<PooledConnection>> connectionPool = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> activeConnectionCounts = new ConcurrentHashMap<>();
    private final Logging logging;
    private final ScheduledExecutorService cleanupService;
    
    // Configuration
    private final int maxConnectionsPerProxy;
    private final int connectionTimeout;
    private final int socketTimeout;
    private final int idleTimeoutSec;
    private final int bufferSize;
    
    // Statistics
    private final AtomicInteger totalConnectionsCreated = new AtomicInteger(0);
    private final AtomicInteger totalConnectionsReused = new AtomicInteger(0);
    
    /**
     * Creates a new proxy connection pool.
     */
    public ProxyConnectionPool(int maxConnectionsPerProxy, int connectionTimeout, 
                              int socketTimeout, int idleTimeoutSec, int bufferSize, Logging logging) {
        this.maxConnectionsPerProxy = maxConnectionsPerProxy;
        this.connectionTimeout = connectionTimeout;
        this.socketTimeout = socketTimeout;
        this.idleTimeoutSec = idleTimeoutSec;
        this.bufferSize = bufferSize;
        this.logging = logging;
        
        // Create a scheduled executor for cleaning up idle connections
        this.cleanupService = new ScheduledThreadPoolExecutor(1);
        this.cleanupService.scheduleAtFixedRate(
            this::cleanupIdleConnections, 
            idleTimeoutSec, 
            idleTimeoutSec, 
            TimeUnit.SECONDS
        );
        
        logInfo("Connection pool initialized with maxConnectionsPerProxy=" + maxConnectionsPerProxy + 
                ", idleTimeout=" + idleTimeoutSec + " seconds");
    }
    
    /**
     * Gets a connection to the specified proxy, either from the pool or by creating a new one.
     */
    public PooledConnection getConnection(ProxyEntry proxy) throws IOException {
        String proxyKey = getProxyKey(proxy);
        
        // Get or create the connection queue for this proxy
        Queue<PooledConnection> proxyConnections = connectionPool.computeIfAbsent(
            proxyKey, k -> new LinkedBlockingQueue<>());
        
        // Get or create the active connection counter
        AtomicInteger activeCount = activeConnectionCounts.computeIfAbsent(
            proxyKey, k -> new AtomicInteger(0));
        
        // First try to get an existing connection from the pool
        PooledConnection connection = proxyConnections.poll();
        
        // If we got a connection from the pool, check if it's still valid
        if (connection != null) {
            if (connection.isValid()) {
                logInfo("Reusing existing connection to " + proxyKey);
                connection.markInUse();
                totalConnectionsReused.incrementAndGet();
                return connection;
            } else {
                // Close the invalid connection
                connection.close();
                logInfo("Discarded invalid connection to " + proxyKey);
            }
        }
        
        // If we've reached the maximum number of connections for this proxy, wait for one to become available
        int currentActive = activeCount.incrementAndGet();
        if (currentActive > maxConnectionsPerProxy) {
            activeCount.decrementAndGet();
            throw new IOException("Maximum connections reached for proxy " + proxyKey);
        }
        
        // Create a new connection
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()), connectionTimeout);
            socket.setSoTimeout(socketTimeout);
            socket.setTcpNoDelay(true);
            socket.setReceiveBufferSize(bufferSize);
            socket.setSendBufferSize(bufferSize);
            socket.setKeepAlive(true);
            
            PooledConnection newConnection = new PooledConnection(socket, proxy, this);
            totalConnectionsCreated.incrementAndGet();
            logInfo("Created new connection to " + proxyKey + " (active: " + currentActive + ")");
            
            return newConnection;
        } catch (IOException e) {
            activeCount.decrementAndGet();
            throw e;
        }
    }
    
    /**
     * Returns a connection to the pool for reuse.
     */
    public void returnConnection(PooledConnection connection) {
        if (connection == null || !connection.isValid()) {
            return;
        }
        
        String proxyKey = getProxyKey(connection.getProxy());
        Queue<PooledConnection> proxyConnections = connectionPool.get(proxyKey);
        AtomicInteger activeCount = activeConnectionCounts.get(proxyKey);
        
        if (proxyConnections != null && activeCount != null) {
            connection.markAvailable();
            proxyConnections.offer(connection);
            activeCount.decrementAndGet();
            logInfo("Returned connection to pool for " + proxyKey + 
                    " (active: " + activeCount.get() + ", pooled: " + proxyConnections.size() + ")");
        }
    }
    
    /**
     * Removes a connection from the active count when it's closed/invalidated.
     */
    public void removeConnection(PooledConnection connection) {
        if (connection == null) {
            return;
        }
        
        String proxyKey = getProxyKey(connection.getProxy());
        AtomicInteger activeCount = activeConnectionCounts.get(proxyKey);
        
        if (activeCount != null) {
            activeCount.decrementAndGet();
        }
    }
    
    /**
     * Cleans up idle connections that have been unused for too long.
     */
    private void cleanupIdleConnections() {
        int totalClosed = 0;
        
        for (Map.Entry<String, Queue<PooledConnection>> entry : connectionPool.entrySet()) {
            String proxyKey = entry.getKey();
            Queue<PooledConnection> connections = entry.getValue();
            
            // Create a temporary list of connections to avoid modification during iteration
            int size = connections.size();
            PooledConnection[] connectionsArray = new PooledConnection[size];
            connections.toArray(connectionsArray);
            connections.clear();
            
            // Check each connection and only keep valid ones that haven't timed out
            for (PooledConnection conn : connectionsArray) {
                if (conn != null && conn.isValid() && !conn.isInUse() && !conn.hasTimedOut(idleTimeoutSec)) {
                    connections.offer(conn);
                } else {
                    if (conn != null) {
                        conn.close();
                        totalClosed++;
                    }
                }
            }
        }
        
        if (totalClosed > 0) {
            logInfo("Cleaned up " + totalClosed + " idle/invalid connections");
        }
    }
    
    /**
     * Shuts down the connection pool, closing all connections.
     */
    public void shutdown() {
        // Stop the cleanup service
        cleanupService.shutdown();
        try {
            cleanupService.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // Close all connections
        int totalClosed = 0;
        for (Queue<PooledConnection> connections : connectionPool.values()) {
            for (PooledConnection conn : connections) {
                conn.close();
                totalClosed++;
            }
            connections.clear();
        }
        
        connectionPool.clear();
        activeConnectionCounts.clear();
        
        logInfo("Connection pool shutdown. Closed " + totalClosed + " connections. " +
                "Stats: created=" + totalConnectionsCreated.get() + ", reused=" + totalConnectionsReused.get());
    }
    
    /**
     * Gets the current statistics of the connection pool.
     */
    public String getStats() {
        int totalActive = 0;
        int totalPooled = 0;
        
        for (AtomicInteger count : activeConnectionCounts.values()) {
            totalActive += count.get();
        }
        
        for (Queue<PooledConnection> queue : connectionPool.values()) {
            totalPooled += queue.size();
        }
        
        return "Connection pool stats: active=" + totalActive + 
               ", pooled=" + totalPooled +
               ", created=" + totalConnectionsCreated.get() + 
               ", reused=" + totalConnectionsReused.get();
    }
    
    /**
     * Creates a unique key for a proxy.
     */
    private String getProxyKey(ProxyEntry proxy) {
        return proxy.getProtocol() + "://" + proxy.getHost() + ":" + proxy.getPort();
    }
    
    /**
     * Logs an info message.
     */
    private void logInfo(String message) {
        logging.logToOutput("[ProxyPool] " + message);
    }
    
    /**
     * Represents a connection in the pool.
     */
    public static class PooledConnection {
        private final Socket socket;
        private final ProxyEntry proxy;
        private final ProxyConnectionPool pool;
        private boolean inUse;
        private long lastUsedTime;
        
        public PooledConnection(Socket socket, ProxyEntry proxy, ProxyConnectionPool pool) {
            this.socket = socket;
            this.proxy = proxy;
            this.pool = pool;
            this.inUse = true;
            this.lastUsedTime = System.currentTimeMillis();
        }
        
        public Socket getSocket() {
            return socket;
        }
        
        public ProxyEntry getProxy() {
            return proxy;
        }
        
        public boolean isInUse() {
            return inUse;
        }
        
        public void markInUse() {
            this.inUse = true;
            this.lastUsedTime = System.currentTimeMillis();
        }
        
        public void markAvailable() {
            this.inUse = false;
            this.lastUsedTime = System.currentTimeMillis();
        }
        
        public boolean isValid() {
            return socket != null && !socket.isClosed() && socket.isConnected() && !socket.isInputShutdown() && !socket.isOutputShutdown();
        }
        
        public boolean hasTimedOut(int timeoutSec) {
            return (System.currentTimeMillis() - lastUsedTime) > timeoutSec * 1000L;
        }
        
        public void close() {
            if (socket != null && !socket.isClosed()) {
                try {
                    socket.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
            
            // Remove from active count
            if (pool != null) {
                pool.removeConnection(this);
            }
        }
        
        /**
         * Returns the connection to the pool when done using it.
         */
        public void release() {
            if (pool != null) {
                pool.returnConnection(this);
            }
        }
    }
} 