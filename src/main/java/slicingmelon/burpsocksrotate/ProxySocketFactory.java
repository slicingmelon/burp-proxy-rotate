package slicingmelon.burpsocksrotate;

import burp.api.montoya.logging.Logging;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Factory class that handles SOCKS proxy handshake and establishing connections.
 */
public class ProxySocketFactory {
    private final Logging logging;
    private final int connectionTimeout;
    
    public ProxySocketFactory(Logging logging, int connectionTimeout) {
        this.logging = logging;
        this.connectionTimeout = connectionTimeout;
    }
    
    /**
     * Establishes a connection to a target through a SOCKS proxy.
     * Performs the initial SOCKS handshake.
     */
    public Socket connectThroughProxy(ProxyConnectionPool.PooledConnection connection, 
                                      String targetHost, int targetPort, byte addressType) throws IOException {
        Socket proxySocket = connection.getSocket();
        ProxyEntry proxy = connection.getProxy();
        
        try {
            InputStream proxyIn = proxySocket.getInputStream();
            OutputStream proxyOut = proxySocket.getOutputStream();
            
            int proxyProtocolVersion = proxy.getProtocolVersion();
            
            if (proxyProtocolVersion == 5) {
                // SOCKS5 handshake
                performSocks5Handshake(proxySocket, proxyIn, proxyOut, targetHost, targetPort, addressType);
            } else if (proxyProtocolVersion == 4) {
                // SOCKS4 handshake
                performSocks4Handshake(proxySocket, proxyIn, proxyOut, targetHost, targetPort, addressType);
            } else {
                throw new IOException("Unsupported SOCKS protocol version: " + proxyProtocolVersion);
            }
            
            return proxySocket;
        } catch (IOException e) {
            // If handshake fails, close the connection and rethrow
            connection.close();
            throw e;
        }
    }
    
    /**
     * Performs a SOCKS5 handshake.
     */
    private void performSocks5Handshake(Socket socket, InputStream in, OutputStream out,
                                      String targetHost, int targetPort, byte addressType) throws IOException {
        // Send greeting
        out.write(new byte[] {5, 1, 0}); // Version, 1 method, No auth
        out.flush();
        
        // Read response
        byte[] response = new byte[2];
        int read = in.read(response);
        
        if (read != 2 || response[0] != 5 || response[1] != 0) {
            throw new IOException("SOCKS5 authentication failed");
        }
        
        // Send connection request
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
        out.write(request);
        out.flush();
        
        // Read response
        byte[] connResponse = new byte[4];
        int readBytes = in.read(connResponse);
        
        if (readBytes != 4 || connResponse[0] != 5 || connResponse[1] != 0) {
            String errorCode = (readBytes > 1) ? Byte.toString(connResponse[1]) : "unknown error";
            throw new IOException("SOCKS5 connection request failed: " + errorCode);
        }
        
        // Skip the rest of the response
        byte respAddressType = connResponse[3];
        int skipBytes = 0;
        
        switch (respAddressType) {
            case 1: // IPv4
                skipBytes = 4 + 2; // IPv4 + port
                break;
            case 3: // Domain
                int domainLength = in.read();
                skipBytes = domainLength + 2; // Domain + port
                break;
            case 4: // IPv6
                skipBytes = 16 + 2; // IPv6 + port
                break;
        }
        
        // Skip bytes
        byte[] skipBuffer = new byte[skipBytes];
        in.read(skipBuffer);
    }
    
    /**
     * Performs a SOCKS4 handshake.
     */
    private void performSocks4Handshake(Socket socket, InputStream in, OutputStream out,
                                       String targetHost, int targetPort, byte addressType) throws IOException {
        // Send connection request
        out.write(new byte[] {
            4, // Version
            1, // CONNECT
            (byte) ((targetPort >> 8) & 0xff), // Port high byte
            (byte) (targetPort & 0xff) // Port low byte
        });
        
        // Send IP or 0.0.0.x for SOCKS4A
        if (addressType == 1) { // IPv4
            String[] parts = targetHost.split("\\.");
            for (String part : parts) {
                out.write(Integer.parseInt(part) & 0xff);
            }
        } else {
            // SOCKS4A for domain names
            out.write(new byte[] {0, 0, 0, 1});
        }
        
        // Null-terminated user ID
        out.write(0);
        
        // For SOCKS4A with domain, send domain
        if (addressType != 1) {
            for (byte b : targetHost.getBytes()) {
                out.write(b);
            }
            out.write(0); // Null-terminate domain
        }
        
        out.flush();
        
        // Read response
        byte[] response = new byte[8];
        int read = in.read(response);
        
        if (read != 8 || response[0] != 0 || response[1] != 90) {
            throw new IOException("SOCKS4 connection failed: " + response[1]);
        }
    }
    
    /**
     * Creates a direct socket connection to the SOCKS proxy.
     */
    public Socket createProxyConnection(ProxyEntry proxy, int bufferSize) throws IOException {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()), connectionTimeout);
        socket.setTcpNoDelay(true);
        socket.setReceiveBufferSize(bufferSize);
        socket.setSendBufferSize(bufferSize);
        socket.setKeepAlive(true);
        
        return socket;
    }
} 