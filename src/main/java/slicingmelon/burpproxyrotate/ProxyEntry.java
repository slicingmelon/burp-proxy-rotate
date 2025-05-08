/**
 * Burp Proxy Rotate
 * Author: slicingmelon 
 * https://github.com/slicingmelon
 * https://x.com/pedro_infosec
 * 
 * This burp extension routes each HTTP request through a different proxy from a provided list.
 */
package slicingmelon.burpproxyrotate;

/**
 * ProxyEntry class
 */
public class ProxyEntry {
    private final String host;
    private final int port;
    private boolean active;
    private String errorMessage;
    private String protocol; // Either "socks4", "socks5", "http", or "direct"
    private String username; // Username for authenticated proxies
    private String password; // Password for authenticated proxies

    /**
     * ProxyEntry constructor
     * 
     * @param host The proxy host address
     * @param port The proxy port
     * @param protocol Protocol to use (socks4, socks5, http, or direct). Defaults to socks5
     * @param protocolVersion Protocol version (used with direct connections)
     * @param active Whether this proxy is active. Defaults to true
     * @param isDirectConnection Whether this is a direct connection. Defaults to false
     * @param username Optional username for authenticated proxies
     * @param password Optional password for authenticated proxies
     */
    public ProxyEntry(String host, int port, String protocol, int protocolVersion, boolean active, 
                     boolean isDirectConnection, String username, String password) {
        this.host = host;
        this.port = port;
        this.active = active;
        this.errorMessage = "";
        this.protocol = protocol != null ? protocol.toLowerCase() : "socks5";
        this.username = username;
        this.password = password;
    }

    // Helper method for basic proxy entry
    public static ProxyEntry createBasic(String host, int port) {
        return new ProxyEntry(host, port, "socks5", 0, true, false, null, null);
    }

    // Helper method with protocol specification
    public static ProxyEntry createWithProtocol(String host, int port, String protocol) {
        return new ProxyEntry(host, port, protocol, 0, true, false, null, null);
    }

    // Helper method for authenticated proxies
    public static ProxyEntry createWithAuth(String host, int port, String protocol, String username, String password) {
        return new ProxyEntry(host, port, protocol, 0, true, false, username, password);
    }

    // Helper method for direct connections
    public static ProxyEntry createDirect(String host, int port) {
        return new ProxyEntry(host, port, "direct", 0, true, true, null, null);
    }

    // Helper method for HTTP proxy
    public static ProxyEntry createHttp(String host, int port) {
        return new ProxyEntry(host, port, "http", 0, true, false, null, null);
    }

    // Helper method for authenticated HTTP proxy
    public static ProxyEntry createHttpWithAuth(String host, int port, String username, String password) {
        return new ProxyEntry(host, port, "http", 0, true, false, username, password);
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
    
    public String getProtocol() {
        return protocol;
    }
    
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }
    
    /**
     * Get the protocol version (4 or 5 for SOCKS)
     */
    public int getProtocolVersion() {
        if ("socks4".equals(protocol)) {
            return 4;
        } else if ("socks5".equals(protocol)) {
            return 5;
        } else if ("http".equals(protocol)) {
            return 0;
        }
        return 5;
    }
    
    /**
     * Check if this proxy requires authentication
     */
    public boolean isAuthenticated() {
        return username != null && !username.isEmpty() && password != null;
    }

    /**
     * Check if this is an HTTP proxy
     */
    public boolean isHttp() {
        return "http".equals(protocol);
    }
    
    /**
     * Get the username for authenticated proxies
     */
    public String getUsername() {
        return username;
    }
    
    /**
     * Get the password for authenticated proxies
     */
    public String getPassword() {
        return password;
    }
    
    /**
     * Set the username for authenticated proxies
     */
    public void setUsername(String username) {
        this.username = username;
    }
    
    /**
     * Set the password for authenticated proxies
     */
    public void setPassword(String password) {
        this.password = password;
    }
} 