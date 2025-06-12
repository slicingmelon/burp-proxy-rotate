/**
 * Burp Proxy Rotate
 * Author: slicingmelon 
 * https://github.com/slicingmelon
 * https://x.com/pedro_infosec
 * 
 * This burp extension routes each HTTP request through a different proxy from a provided list.
 */
package slicingmelon.burpproxyrotate;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

/**
 * SOCKS5 protocol handler
 */
public class Socks5 {
    
    /**
     * Process a SOCKS5 CONNECT request from client
     */
    public static Socks5ConnectResult processSocks5ConnectRequest(ByteBuffer buffer) throws IOException {
        if (buffer.remaining() < 4) {
            return new Socks5ConnectResult(false, null, 0, (byte) 0, "Need more data");
        }
        
        // Read the SOCKS5 command request
        byte version = buffer.get();
        if (version != 5) {
            return new Socks5ConnectResult(false, null, 0, (byte) 0, "Invalid SOCKS5 request version");
        }
        
        byte command = buffer.get();
        if (command != 1) {
            return new Socks5ConnectResult(false, null, 0, (byte) 7, "Only CONNECT command supported");
        }
        
        // Skip reserved byte
        buffer.get();
        
        // Read address type
        byte addressType = buffer.get();
        
        String targetHost;
        int targetPort;
        
        switch (addressType) {
            case 1: // IPv4
                if (buffer.remaining() < 6) {
                    return new Socks5ConnectResult(false, null, 0, (byte) 0, "Need more data");
                }
                
                byte[] ipv4 = new byte[4];
                buffer.get(ipv4);
                targetHost = (ipv4[0] & 0xFF) + "." + (ipv4[1] & 0xFF) + "." + 
                            (ipv4[2] & 0xFF) + "." + (ipv4[3] & 0xFF);
                break;
                
            case 3: // Domain name
                if (buffer.remaining() < 1) {
                    return new Socks5ConnectResult(false, null, 0, (byte) 0, "Need more data");
                }
                
                int domainLength = buffer.get() & 0xFF;
                
                if (buffer.remaining() < domainLength + 2) {
                    return new Socks5ConnectResult(false, null, 0, (byte) 0, "Need more data");
                }
                
                byte[] domain = new byte[domainLength];
                buffer.get(domain);
                targetHost = new String(domain);
                break;
                
            case 4: // IPv6
                if (buffer.remaining() < 18) {
                    return new Socks5ConnectResult(false, null, 0, (byte) 0, "Need more data");
                }
                
                byte[] ipv6 = new byte[16];
                buffer.get(ipv6);
                
                // Format IPv6 address properly
                try {
                    java.net.InetAddress inetAddress = java.net.InetAddress.getByAddress(ipv6);
                    targetHost = inetAddress.getHostAddress();
                    
                    // Remove IPv6 scope id if present
                    if (targetHost.contains("%")) {
                        targetHost = targetHost.substring(0, targetHost.indexOf("%"));
                    }
                } catch (Exception e) {
                    // Fallback to manual formatting
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 16; i += 2) {
                        if (i > 0) sb.append(":");
                        sb.append(String.format("%02x%02x", ipv6[i] & 0xFF, ipv6[i+1] & 0xFF));
                    }
                    targetHost = sb.toString();
                }
                break;
                
            default:
                return new Socks5ConnectResult(false, null, 0, (byte) 8, "Address type not supported");
        }
        
        // Read port (2 bytes, big endian)
        targetPort = ((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF);
        
        return new Socks5ConnectResult(true, targetHost, targetPort, addressType, null);
    }
    
    /**
     * Process SOCKS5 authentication response from proxy
     */
    public static Socks5AuthResult processSocks5AuthResponse(ByteBuffer buffer, boolean isAuthResponse) throws IOException {
        if (isAuthResponse) {
            // Response to username/password authentication
            if (buffer.remaining() < 2) {
                return new Socks5AuthResult(Socks5AuthResult.Status.NEED_MORE_DATA, null);
            }
            
            byte authVersion = buffer.get();
            byte authStatus = buffer.get();
            
            if (authVersion != 1) {
                return new Socks5AuthResult(Socks5AuthResult.Status.INVALID_VERSION, 
                    "Invalid SOCKS5 auth version: " + authVersion);
            }
            
            if (authStatus != 0) {
                return new Socks5AuthResult(Socks5AuthResult.Status.AUTH_FAILED, 
                    "Authentication failed with status: " + authStatus);
            }
            
            return new Socks5AuthResult(Socks5AuthResult.Status.AUTH_SUCCESS, null);
        } else {
            // Normal auth method selection
            if (buffer.remaining() < 2) {
                return new Socks5AuthResult(Socks5AuthResult.Status.NEED_MORE_DATA, null);
            }
            
            byte version = buffer.get();
            byte method = buffer.get();
            
            if (version != 5) {
                return new Socks5AuthResult(Socks5AuthResult.Status.INVALID_VERSION, 
                    "Invalid SOCKS5 version: " + version);
            }
            
            if (method == 0) {
                return new Socks5AuthResult(Socks5AuthResult.Status.NO_AUTH, null);
            } else if (method == 2) {
                return new Socks5AuthResult(Socks5AuthResult.Status.USERNAME_PASSWORD, null);
            } else {
                return new Socks5AuthResult(Socks5AuthResult.Status.UNSUPPORTED_METHOD, 
                    "Unsupported auth method: " + method);
            }
        }
    }
    
    /**
     * Process SOCKS5 connect response from proxy
     */
    public static Socks5ConnectResponse processSocks5ConnectResponse(ByteBuffer buffer) throws IOException {
        if (buffer.remaining() < 4) {
            return new Socks5ConnectResponse(false, (byte) 0, null, "Need more data");
        }
        
        byte version = buffer.get();
        byte status = buffer.get();
        
        // Skip reserved byte
        buffer.get();
        
        // Read bound address type
        byte boundType = buffer.get();
        
        // Skip address and port based on type
        int skipBytes = 0;
        switch (boundType) {
            case 1: // IPv4
                skipBytes = 4 + 2;
                break;
            case 3: // Domain
                if (buffer.remaining() < 1) {
                    return new Socks5ConnectResponse(false, (byte) 0, null, "Need more data");
                }
                skipBytes = (buffer.get() & 0xFF) + 2;
                break;
            case 4: // IPv6
                skipBytes = 16 + 2;
                break;
            default:
                return new Socks5ConnectResponse(false, (byte) 0, null, 
                    "Invalid address type: " + boundType);
        }
        
        if (buffer.remaining() < skipBytes) {
            return new Socks5ConnectResponse(false, (byte) 0, null, "Need more data");
        }
        
        // Skip the remaining data
        for (int i = 0; i < skipBytes; i++) {
            buffer.get();
        }
        
        if (version != 5) {
            return new Socks5ConnectResponse(false, (byte) 0, null, 
                "Invalid SOCKS5 response version: " + version);
        }
        
        if (status != 0) {
            return new Socks5ConnectResponse(false, status, null, 
                "SOCKS5 connection failed with status: " + status);
        }
        
        // Extract remaining data if any
        ByteBuffer remainingData = null;
        if (buffer.hasRemaining()) {
            remainingData = ByteBuffer.allocateDirect(buffer.remaining());
            remainingData.put(buffer);
            remainingData.flip();
        }
        
        return new Socks5ConnectResponse(true, (byte) 0, remainingData, null);
    }
    
    /**
     * Send SOCKS5 connect request to proxy
     */
    public static void sendSocks5ConnectRequest(SocketChannel proxyChannel, String targetHost, 
                                              int targetPort, byte addressType) throws IOException {
        ByteBuffer request;
        
        if (addressType == 1) { // IPv4
            String[] octets = targetHost.split("\\.");
            if (octets.length != 4) {
                throw new IOException("Invalid IPv4 address");
            }
            
            request = ByteBuffer.allocate(10);
            request.put((byte) 5); // SOCKS version
            request.put((byte) 1); // CONNECT command
            request.put((byte) 0); // Reserved
            request.put((byte) 1); // IPv4 address type
            
            for (String octet : octets) {
                request.put((byte) (Integer.parseInt(octet) & 0xFF));
            }
            
        } else if (addressType == 4) { // IPv6
            request = ByteBuffer.allocate(22);
            request.put((byte) 5); // SOCKS version
            request.put((byte) 1); // CONNECT command
            request.put((byte) 0); // Reserved
            request.put((byte) 4); // IPv6 address type
            
            try {
                java.net.Inet6Address inet6Address = (java.net.Inet6Address) 
                    java.net.InetAddress.getByName(targetHost);
                byte[] ipv6Bytes = inet6Address.getAddress();
                request.put(ipv6Bytes);
            } catch (Exception e) {
                // Fallback to zero address
                for (int i = 0; i < 16; i++) {
                    request.put((byte) 0);
                }
            }
            
        } else { // Domain name
            byte[] domain = targetHost.getBytes();
            request = ByteBuffer.allocate(7 + domain.length);
            request.put((byte) 5);
            request.put((byte) 1);
            request.put((byte) 0);
            request.put((byte) 3);
            request.put((byte) domain.length);
            request.put(domain);
        }
        
        // Add port (big endian)
        request.put((byte) ((targetPort >> 8) & 0xFF));
        request.put((byte) (targetPort & 0xFF));
        
        request.flip();
        proxyChannel.write(request);
    }
    
    /**
     * Send SOCKS5 handshake to proxy
     */
    public static void sendSocks5Handshake(SocketChannel proxyChannel, boolean requiresAuth) throws IOException {
        ByteBuffer handshake;
        
        if (requiresAuth) {
            // Support both no-auth and username/password
            handshake = ByteBuffer.allocate(4);
            handshake.put((byte) 0x05); // SOCKS version
            handshake.put((byte) 0x02); // 2 auth methods
            handshake.put((byte) 0x00); // No auth
            handshake.put((byte) 0x02); // Username/password auth
        } else {
            // No auth only
            handshake = ByteBuffer.allocate(3);
            handshake.put((byte) 0x05); // SOCKS version
            handshake.put((byte) 0x01); // 1 auth method
            handshake.put((byte) 0x00); // No auth
        }
        
        handshake.flip();
        proxyChannel.write(handshake);
    }
    
    /**
     * Send SOCKS5 username/password authentication
     */
    public static void sendSocks5Auth(SocketChannel proxyChannel, String username, String password) throws IOException {
        byte[] usernameBytes = username.getBytes();
        byte[] passwordBytes = password.getBytes();
        
        ByteBuffer authRequest = ByteBuffer.allocate(3 + usernameBytes.length + passwordBytes.length);
        authRequest.put((byte) 0x01); // Auth version
        authRequest.put((byte) usernameBytes.length);
        authRequest.put(usernameBytes);
        authRequest.put((byte) passwordBytes.length);
        authRequest.put(passwordBytes);
        
        authRequest.flip();
        proxyChannel.write(authRequest);
    }
    
    /**
     * Send SOCKS5 error response to client
     */
    public static void sendSocks5ErrorResponse(SocketChannel channel, byte errorCode) throws IOException {
        ByteBuffer response = ByteBuffer.allocate(10);
        response.put((byte) 5);  // SOCKS version
        response.put(errorCode); // Error code
        response.put((byte) 0);  // Reserved
        response.put((byte) 1);  // Address type (IPv4)
        
        // IP address (0.0.0.0)
        response.put((byte) 0);
        response.put((byte) 0);
        response.put((byte) 0);
        response.put((byte) 0);
        
        // Port (0)
        response.put((byte) 0);
        response.put((byte) 0);
        
        response.flip();
        channel.write(response);
    }
    
    /**
     * Send SOCKS5 success response to client
     */
    public static void sendSocks5SuccessResponse(SocketChannel channel) throws IOException {
        ByteBuffer response = ByteBuffer.allocate(10);
        response.put((byte) 5);  // SOCKS version
        response.put((byte) 0);  // Success
        response.put((byte) 0);  // Reserved
        response.put((byte) 1);  // Address type (IPv4)
        
        // IP address (0.0.0.0)
        response.put((byte) 0);
        response.put((byte) 0);
        response.put((byte) 0);
        response.put((byte) 0);
        
        // Port (0)
        response.put((byte) 0);
        response.put((byte) 0);
        
        response.flip();
        channel.write(response);
    }
    
    /**
     * Process initial SOCKS5 greeting from client
     */
    public static Socks5GreetingResult processSocks5Greeting(ByteBuffer buffer) throws IOException {
        if (buffer.remaining() < 2) {
            return new Socks5GreetingResult(false, "Need more data");
        }
        
        byte version = buffer.get();
        if (version != 5) {
            return new Socks5GreetingResult(false, "Invalid SOCKS version: " + version);
        }
        
        int numMethods = buffer.get() & 0xFF;
        
        if (buffer.remaining() < numMethods) {
            return new Socks5GreetingResult(false, "Need more data");
        }
        
        // Skip the auth methods
        for (int i = 0; i < numMethods; i++) {
            buffer.get();
        }
        
        return new Socks5GreetingResult(true, null);
    }
    
    /**
     * Send SOCKS5 greeting response to client
     */
    public static void sendSocks5GreetingResponse(SocketChannel channel) throws IOException {
        ByteBuffer response = ByteBuffer.allocate(2);
        response.put((byte) 5);  // SOCKS version
        response.put((byte) 0);  // No auth method
        response.flip();
        channel.write(response);
    }
    
    // Helper classes for return values
    public static class Socks5ConnectResult {
        public final boolean success;
        public final String targetHost;
        public final int targetPort;
        public final byte addressType;
        public final String errorMessage;
        public final byte errorCode;
        
        public Socks5ConnectResult(boolean success, String targetHost, int targetPort, 
                                 byte addressType, String errorMessage) {
            this.success = success;
            this.targetHost = targetHost;
            this.targetPort = targetPort;
            this.addressType = addressType;
            this.errorMessage = errorMessage;
            this.errorCode = addressType; // Reuse addressType as errorCode when failed
        }
    }
    
    public static class Socks5AuthResult {
        public enum Status {
            NEED_MORE_DATA,
            NO_AUTH,
            USERNAME_PASSWORD,
            AUTH_SUCCESS,
            AUTH_FAILED,
            INVALID_VERSION,
            UNSUPPORTED_METHOD
        }
        
        public final Status status;
        public final String errorMessage;
        
        public Socks5AuthResult(Status status, String errorMessage) {
            this.status = status;
            this.errorMessage = errorMessage;
        }
    }
    
    public static class Socks5ConnectResponse {
        public final boolean success;
        public final byte errorCode;
        public final ByteBuffer remainingData;
        public final String errorMessage;
        
        public Socks5ConnectResponse(boolean success, byte errorCode, ByteBuffer remainingData, String errorMessage) {
            this.success = success;
            this.errorCode = errorCode;
            this.remainingData = remainingData;
            this.errorMessage = errorMessage;
        }
    }
    
    public static class Socks5GreetingResult {
        public final boolean success;
        public final String errorMessage;
        
        public Socks5GreetingResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }
    }
} 