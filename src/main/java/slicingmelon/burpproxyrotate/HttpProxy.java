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
 * HTTP CONNECT proxy protocol handler
 */
public class HttpProxy {
    
    /**
     * Send HTTP CONNECT request to proxy
     */
    public static void sendHttpConnectRequest(SocketChannel proxyChannel, String targetHost, 
                                            int targetPort, ProxyEntry proxy) throws IOException {
        // Use an efficient StringBuilder to build the request
        StringBuilder requestBuilder = new StringBuilder(512);
        
        // CONNECT host:port HTTP/1.1\r\n
        requestBuilder.append("CONNECT ")
                     .append(targetHost)
                     .append(':')
                     .append(targetPort)
                     .append(" HTTP/1.1\r\n");
        
        // Host: host:port\r\n
        requestBuilder.append("Host: ")
                     .append(targetHost)
                     .append(':')
                     .append(targetPort)
                     .append("\r\n");
        
        // Add authentication if needed
        if (proxy != null && proxy.isAuthenticated()) {
            String auth = proxy.getUsername() + ":" + proxy.getPassword();
            String encodedAuth = java.util.Base64.getEncoder().encodeToString(auth.getBytes());
            requestBuilder.append("Proxy-Authorization: Basic ")
                         .append(encodedAuth)
                         .append("\r\n");
        }
        
        // Add standard headers
        requestBuilder.append("Connection: keep-alive\r\n");
        requestBuilder.append("User-Agent: BurpProxyRotate\r\n");
        requestBuilder.append("\r\n"); // End request with blank line
        
        // Convert to bytes
        String request = requestBuilder.toString();
        byte[] requestBytes = request.getBytes();
        
        // Create a properly sized direct buffer
        ByteBuffer headerBuffer = ByteBuffer.allocateDirect(requestBytes.length);
        headerBuffer.put(requestBytes);
        headerBuffer.flip();
        
        // Send the request
        proxyChannel.write(headerBuffer);
    }
    
    /**
     * Process HTTP CONNECT response from proxy
     */
    public static HttpConnectResponse processHttpConnectResponse(ByteBuffer buffer) throws IOException {
        byte[] responseBytes = new byte[buffer.remaining()];
        buffer.get(responseBytes);
        
        // Find the first line to check status code
        int endOfFirstLine = -1;
        boolean isSuccessStatus = false;
        
        // Find end of status line and check for "200" status code
        for (int i = 0; i < responseBytes.length - 1; i++) {
            if (responseBytes[i] == '\r' && responseBytes[i + 1] == '\n') {
                endOfFirstLine = i;
                // Find "200" in the status line
                boolean found200 = false;
                for (int j = 0; j < endOfFirstLine - 2; j++) {
                    if (responseBytes[j] == '2' && responseBytes[j + 1] == '0' && responseBytes[j + 2] == '0') {
                        isSuccessStatus = true;
                        found200 = true;
                        break;
                    }
                }
                
                // If we didn't find 200, check if it might be a 407 (auth required)
                if (!found200) {
                    boolean found407 = false;
                    for (int j = 0; j < endOfFirstLine - 2; j++) {
                        if (responseBytes[j] == '4' && responseBytes[j + 1] == '0' && responseBytes[j + 2] == '7') {
                            found407 = true;
                            break;
                        }
                    }
                    
                    // Authentication required
                    if (found407) {
                        String statusLine = new String(responseBytes, 0, Math.min(endOfFirstLine, 100));
                        return new HttpConnectResponse(false, null, 
                            "HTTP proxy requires authentication or credentials are invalid: " + statusLine);
                    }
                }
                break;
            }
        }
        
        if (endOfFirstLine == -1) {
            // We didn't receive a complete line yet, need more data
            ByteBuffer remainingData = ByteBuffer.allocateDirect(Math.max(responseBytes.length * 2, 32768));
            remainingData.put(responseBytes);
            remainingData.flip();
            return new HttpConnectResponse(false, remainingData, "Incomplete HTTP response, waiting for more data");
        }
        
        if (isSuccessStatus) {
            int endOfHeaders = -1;
            for (int i = 0; i < responseBytes.length - 3; i++) {
                if (responseBytes[i] == '\r' && responseBytes[i + 1] == '\n' &&
                    responseBytes[i + 2] == '\r' && responseBytes[i + 3] == '\n') {
                    endOfHeaders = i + 3; // Point to the last \n in \r\n\r\n
                    break;
                }
            }
            
            if (endOfHeaders == -1) {
                // Headers not complete yet, buffer and wait for more
                ByteBuffer remainingData = ByteBuffer.allocateDirect(Math.max(responseBytes.length * 2, 32768));
                remainingData.put(responseBytes);
                remainingData.flip();
                return new HttpConnectResponse(false, remainingData, 
                    "HTTP headers incomplete, waiting for more data (received " + responseBytes.length + " bytes)");
            }
            
            // Successfully connected
            String statusLine = new String(responseBytes, 0, Math.min(endOfFirstLine, 100));
            
            // If there's data after the headers, that's the beginning of the tunneled connection
            ByteBuffer bodyData = null;
            if (endOfHeaders + 1 < responseBytes.length) {
                bodyData = ByteBuffer.allocateDirect(responseBytes.length - (endOfHeaders + 1));
                bodyData.put(responseBytes, endOfHeaders + 1, responseBytes.length - (endOfHeaders + 1));
                bodyData.flip();
            }
            
            return new HttpConnectResponse(true, bodyData, "HTTP CONNECT successful: " + statusLine);
        } else {
            String statusLine = new String(responseBytes, 0, Math.min(responseBytes.length, 100));
            return new HttpConnectResponse(false, null, "HTTP CONNECT failed: " + statusLine + 
                (responseBytes.length > 100 ? "..." : ""));
        }
    }
    
    // Helper class for return values
    public static class HttpConnectResponse {
        public final boolean success;
        public final ByteBuffer bodyData; // Data after headers or buffered response data
        public final String message;
        
        public HttpConnectResponse(boolean success, ByteBuffer bodyData, String message) {
            this.success = success;
            this.bodyData = bodyData;
            this.message = message;
        }
    }
} 