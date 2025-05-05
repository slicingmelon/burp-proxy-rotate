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

    public ProxyEntry(String host, int port) {
        this.host = host;
        this.port = port;
        this.active = true;
        this.errorMessage = "";
        this.protocol = "socks5";
    }

    public ProxyEntry(String host, int port, String protocol) {
        this.host = host;
        this.port = port;
        this.active = true;
        this.errorMessage = "";
        this.protocol = protocol != null ? protocol.toLowerCase() : "socks5";
    }

    /**
     * Constructor with all parameters - used for direct connections
     */
    public ProxyEntry(String protocol, String host, int port, int protocolVersion, boolean active, boolean isDirectConnection) {
        this.protocol = protocol;
        this.host = host;
        this.port = port;
        this.active = active;
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