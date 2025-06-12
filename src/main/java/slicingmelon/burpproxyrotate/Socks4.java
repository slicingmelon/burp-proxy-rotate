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
 * SOCKS4 protocol handler
 */
public class Socks4 {
    
    /**
     * Process initial SOCKS4 CONNECT request from client
     */
    public static Socks4ConnectResult processSocks4ConnectRequest(ByteBuffer buffer) throws IOException {
        if (buffer.remaining() < 8) {
            return new Socks4ConnectResult(false, null, 0, "Need more data");
        }
        
        // Version should already be consumed, but let's verify command
        byte command = buffer.get();
        
        if (command != 1) {
            return new Socks4ConnectResult(false, null, 0, "Only CONNECT command supported");
        }
        
        // Read port (2 bytes, big endian)
        int targetPort = ((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF);
        
        // Read IPv4 address (4 bytes)
        byte[] ipv4 = new byte[4];
        buffer.get(ipv4);
        
        String targetHost;
        
        if (ipv4[0] == 0 && ipv4[1] == 0 && ipv4[2] == 0 && ipv4[3] != 0) {
            // SOCKS4A - domain name follows
            // Skip the user ID
            while (buffer.hasRemaining() && buffer.get() != 0) {
                // Skip to null terminator
            }
            
            // Read domain name
            StringBuilder domain = new StringBuilder();
            while (buffer.hasRemaining()) {
                byte b = buffer.get();
                if (b == 0) break;
                domain.append((char) b);
            }
            
            targetHost = domain.toString();
        } else {
            // Regular SOCKS4 - IPv4 address
            targetHost = (ipv4[0] & 0xFF) + "." + (ipv4[1] & 0xFF) + "." + 
                        (ipv4[2] & 0xFF) + "." + (ipv4[3] & 0xFF);
            
            // Skip the user ID
            while (buffer.hasRemaining() && buffer.get() != 0) {
                // Skip to null terminator
            }
        }
        
        return new Socks4ConnectResult(true, targetHost, targetPort, null);
    }
    
    /**
     * Process SOCKS4 connect response from proxy
     */
    public static Socks4ConnectResponse processSocks4ConnectResponse(ByteBuffer buffer) throws IOException {
        if (buffer.remaining() < 8) {
            return new Socks4ConnectResponse(false, (byte) 0, null, "Need more data");
        }
        
        byte nullByte = buffer.get();
        byte status = buffer.get();
        
        // Skip the rest of the response (port and IP)
        for (int i = 0; i < 6; i++) {
            buffer.get();
        }
        
        if (nullByte != 0) {
            return new Socks4ConnectResponse(false, (byte) 0, null, "Invalid SOCKS4 response format");
        }
        
        if (status != 90) {
            return new Socks4ConnectResponse(false, status, null, "SOCKS4 connection failed with status: " + status);
        }
        
        // Extract remaining data if any
        ByteBuffer remainingData = null;
        if (buffer.hasRemaining()) {
            remainingData = ByteBuffer.allocateDirect(buffer.remaining());
            remainingData.put(buffer);
            remainingData.flip();
        }
        
        return new Socks4ConnectResponse(true, (byte) 90, remainingData, null);
    }
    
    /**
     * Create a SOCKS4 connection request to send to proxy
     */
    public static ByteBuffer createSocks4ConnectRequest(String targetHost, int targetPort) {
        ByteBuffer request;
        
        // Check if targetHost is an IP address
        String[] ipParts = targetHost.split("\\.");
        if (ipParts.length == 4) {
            // Regular SOCKS4
            request = ByteBuffer.allocate(9);
            request.put((byte) 4); // SOCKS version
            request.put((byte) 1); // CONNECT command
            request.put((byte) ((targetPort >> 8) & 0xFF)); // Port high byte
            request.put((byte) (targetPort & 0xFF)); // Port low byte
            
            // IP address
            for (String part : ipParts) {
                request.put((byte) (Integer.parseInt(part) & 0xFF));
            }
            
            // Null-terminated user ID
            request.put((byte) 0);
        } else {
            // SOCKS4A with domain name
            byte[] domain = targetHost.getBytes();
            request = ByteBuffer.allocate(10 + domain.length);
            request.put((byte) 4); // SOCKS version
            request.put((byte) 1); // CONNECT command
            request.put((byte) ((targetPort >> 8) & 0xFF)); // Port high byte
            request.put((byte) (targetPort & 0xFF)); // Port low byte
            request.put((byte) 0); // 0.0.0.x for SOCKS4A
            request.put((byte) 0);
            request.put((byte) 0);
            request.put((byte) 1); // Non-zero value
            request.put((byte) 0); // Null-terminated user ID
            
            // Domain name
            request.put(domain);
            request.put((byte) 0); // Null-terminate domain
        }
        
        request.flip();
        return request;
    }
    
    /**
     * Send SOCKS4 error response to client
     */
    public static void sendSocks4ErrorResponse(SocketChannel channel, byte errorCode) throws IOException {
        ByteBuffer response = ByteBuffer.allocate(8);
        response.put((byte) 0);  // Null byte
        response.put(errorCode); // Error code
        
        // Port (0)
        response.put((byte) 0);
        response.put((byte) 0);
        
        // IP (0.0.0.0)
        response.put((byte) 0);
        response.put((byte) 0);
        response.put((byte) 0);
        response.put((byte) 0);
        
        response.flip();
        channel.write(response);
    }
    
    /**
     * Send SOCKS4 success response to client
     */
    public static void sendSocks4SuccessResponse(SocketChannel channel) throws IOException {
        ByteBuffer response = ByteBuffer.allocate(8);
        response.put((byte) 0);  // Null byte
        response.put((byte) 90); // Success
        
        // Port (0)
        response.put((byte) 0);
        response.put((byte) 0);
        
        // IP (0.0.0.0)
        response.put((byte) 0);
        response.put((byte) 0);
        response.put((byte) 0);
        response.put((byte) 0);
        
        response.flip();
        channel.write(response);
    }
    
    // Helper classes for return values
    public static class Socks4ConnectResult {
        public final boolean success;
        public final String targetHost;
        public final int targetPort;
        public final String errorMessage;
        
        public Socks4ConnectResult(boolean success, String targetHost, int targetPort, String errorMessage) {
            this.success = success;
            this.targetHost = targetHost;
            this.targetPort = targetPort;
            this.errorMessage = errorMessage;
        }
    }
    
    public static class Socks4ConnectResponse {
        public final boolean success;
        public final byte statusCode;
        public final ByteBuffer remainingData;
        public final String errorMessage;
        
        public Socks4ConnectResponse(boolean success, byte statusCode, ByteBuffer remainingData, String errorMessage) {
            this.success = success;
            this.statusCode = statusCode;
            this.remainingData = remainingData;
            this.errorMessage = errorMessage;
        }
    }
} 