package slicingmelon.burpsocksrorate;

public class ProxyEntry {
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