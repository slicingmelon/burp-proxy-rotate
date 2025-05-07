package slicingmelon.burpsocksrotate;

/**
 * Represents a SOCKS proxy entry with host, port and status information.
 */
public class ProxyEntry {
    private final String host;
    private final int port;
    private boolean active;
    private String errorMessage;
    private String protocol; // Either "socks4" or "socks5"

    /**
     * Unified constructor for ProxyEntry
     * 
     * @param host The proxy host address
     * @param port The proxy port
     * @param protocol Protocol to use (socks4, socks5, or direct). Defaults to socks5
     * @param protocolVersion Protocol version (used with direct connections)
     * @param active Whether this proxy is active. Defaults to true
     * @param isDirectConnection Whether this is a direct connection. Defaults to false
     */
    public ProxyEntry(String host, int port, String protocol, int protocolVersion, boolean active, boolean isDirectConnection) {
        this.host = host;
        this.port = port;
        this.active = active;
        this.errorMessage = "";
        this.protocol = protocol != null ? protocol.toLowerCase() : "socks5";
    }

    // Convenience method for basic proxy entry
    public static ProxyEntry createBasic(String host, int port) {
        return new ProxyEntry(host, port, "socks5", 0, true, false);
    }

    // Convenience method with protocol specification
    public static ProxyEntry createWithProtocol(String host, int port, String protocol) {
        return new ProxyEntry(host, port, protocol, 0, true, false);
    }

    // Convenience method for direct connections
    public static ProxyEntry createDirect(String host, int port) {
        return new ProxyEntry(host, port, "direct", 0, true, true);
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
     * Get the protocol version as an integer (4 or 5)
     */
    public int getProtocolVersion() {
        return "socks4".equals(protocol) ? 4 : 5;
    }
} 