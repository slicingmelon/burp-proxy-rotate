# Burp Proxy Rotate

A Burp Suite extension that routes each HTTP request through a random proxy from a configurable list. Each new connection from Burp is assigned a proxy from your list, ensuring diverse egress points for your testing activities.

## Key Features

-   **Advanced Proxy Rotation:** Leverages Java NIO for non-blocking, event-driven proxying, assigning a different proxy node on a per-connection basis.
-   **Multiple Protocol Support:**
    -   **SOCKS5:** Full support, including username/password authentication.
    -   **SOCKS4 & SOCKS4a:** Full support.
    -   **HTTP Proxies:** Supports HTTP `CONNECT` tunneling, including Basic authentication.
    -   **Direct Connections:** Ability to bypass proxies for specified domains (e.g., Burp Collaborator).
-   **Authentication:** Supports SOCKS5 username/password and HTTP Basic proxy authentication.
-   **Support for Bypass Domains:**
    -   Pre-configured to bypass Burp Collaborator domains (`burpcollaborator.net`, `oastify.com`).
    -   Supports adding custom domains to the bypass list.
-   **Proxy List:**
    -   Add proxies individually or in bulk.
    -   Formats supported: `protocol://host:port` and `protocol://user:pass@host:port`.
    -   Validate individual or all proxies to exclude unresponsive proxies.
    -   Easy to manage the proxy list through the UI.
-   **Internal Proxy Service Control:**
    -   Configure local listening port (manual or random).
    -   Adjust buffer sizes, idle timeouts, and maximum connections per proxy.
    -   Choose between "Round-Robin" or "Random" proxy selection strategies.
-   **Detailed Logging & Status:** Real-time logging of operations and connection statistics.

## Technical Architecture & Performance

Burp Proxy Rotate is designed for stability and speed, utilizing modern Java features:

-   **Core Engine (`ProxyRotateService`):**
    -   **Java NIO (Non-blocking I/O):** Built around a `java.nio.channels.Selector` for managing many concurrent connections with a single thread, minimizing overhead.
    -   **Event-Driven:** Handles network events (accept, connect, read, write) asynchronously.
    -   **Connection State Management:** Each client-to-proxy-to-target pipeline is managed by a `ConnectionState` object, tracking the current stage (e.g., SOCKS handshake, HTTP CONNECT, data relay).
    -   **Protocol Handling:** Implements SOCKS4/SOCKS5 and HTTP CONNECT handshake logic.
-   **Buffer Management:**
    -   **Direct `ByteBuffer`s:** Used for I/O operations to potentially reduce copying between JVM heap and native memory.
    -   **Adaptive Buffer Sizing:** Starts with a default buffer size (configurable, 8KB default) and dynamically increases capacity for specific connections (e.g., 128KB-256KB for HTTP/Direct/HTTPS) to handle larger data chunks like HTTP headers or TLS records efficiently.
-   **Socket Optimizations:**
    -   `TCP_NODELAY`: Enabled to disable Nagle's algorithm, reducing latency for small, frequent packets.
    -   `SO_REUSEADDR`: Enabled on the server socket.
    -   Socket `keepAlive` is enabled for client connections.
    -   Performance preferences (`setPerformancePreferences(0, 1, 0)`) are set for direct connections to prioritize latency.
-   **Thread Management:**
    -   Dedicated, prioritized selector thread for network I/O.
    -   Scheduled executor for periodic idle connection cleanup and enforcing rotation.
    -   Thread pool for concurrent proxy validation.
-   **Resilience:**
    -   **Proxy Failure:** Notifies the UI if an upstream proxy fails during connection establishment.
    -   **Direct Connection Fallback:** If a direct connection to a bypass domain fails, it can attempt to route through a standard proxy.
    -   **JDK Epoll Bug Workaround:** Includes logic to recreate the selector in case of a known JDK bug related to `epoll_wait` returning 0 indefinitely.

## Screenshots

#### Main Tab
![Main Tab](images/burp-proxy-rotate-main.png)

#### Settings
![Settings Tab](images/burp-proxy-rotate-settings.png)

## Demo

![Demo](images/burp-proxy-rorate-demo.gif)

## How to Use

1.  **Install/Build:**
    *   Grab a precompiled JAR from `build/libs/`.
    *   OR build the extension using (`./gradlew build`).
    *   In Burp Suite, go to `Extensions` -> `Installed` -> `Add` and select the JAR file available under `build/libs`.
2.  **Configure Proxies:**
    *   Navigate to the "Proxy Rotate" tab in Burp Suite.
    *   Use the "Single Proxy" or "Bulk Add" options to add your SOCKS4, SOCKS5, or HTTP proxies.
        *   **Format:** `protocol://host:port` (e.g., `socks5://127.0.0.1:1080`)
        *   **Authenticated Format:** `protocol://username:password@host:port` (e.g., `http://user:pass@proxy.example.com:8080`)
3.  **Validate Proxies (Recommended):**
    *   Click "Validate All" to check the status of your added proxies. Inactive or problematic proxies will be indicated and exluded. 
4.  **Enable Extension**
    *   Click "Enable Proxy Rotate". The status will update to "Running on 127.0.0.1:PORT".
    *   Configure the "Local port" if needed (or use random port -- recommended).
    

## User Interface Guide

The extension provides a user-friendly interface with two main tabs:

### Main Tab

-   **Local Port:** Configure the port on `localhost` where the Proxy Rotate service will listen. Can be set to a specific port or "Random Port" (default option and recommended).
-   **Service Control:**
    -   `Enable Proxy Rotate`: Enables the extension and starts the local proxy service.
    -   `Disable Proxy Rotate`: Disables the extesion and stops the local proxy service.
-   **Status & Stats:**
    -   `Status`: Shows if the service is "Stopped", "Running on 127.0.0.1:PORT", or "Failed to start".
    -   `Stats`: Displays the number of active connections and details about proxy utilization (e.g., "Active connections: 5 | Using 3 proxies, busiest: ...").
-   **Proxy List Table:** Displays your configured upstream proxies with columns for:
    -   `Protocol`: (socks4, socks5, http)
    -   `Host`: Proxy host.
    -   `Port`: Proxy port.
    -   `Auth`: "Yes" if credentials are provided, "No" otherwise.
    -   `Status`: "Active", "Inactive", or "Validating..." with any error messages.
-   **Proxy Management Buttons:**
    -   `Remove Selected`: Removes the highlighted proxy from the list.
    -   `Clear All`: Removes all proxies from the list (with confirmation).
    -   `Validate All`: Initiates a health check for all proxies in the list.
-   **Proxy Addition Tabs:**
    -   `Single Proxy`: Add one proxy at a time using the URL format.
    -   `Bulk Add`: Paste multiple proxy URLs (one per line).

### Settings Tab

-   **Connection Settings:**
    -   `Buffer Size (bytes)`: Default read/write buffer size for new connections (default: 8192 bytes). Adaptive sizing increases this for HTTP/direct connections.
    -   `Idle Timeout (sec)`: Time after which an inactive connection is closed (default: 60 seconds). A shorter, internal "moderately idle" timeout (10s) also helps enforce rotation.
    -   `Max Connections Per Proxy`: (Currently informational in `ProxyRotateService` but not strictly enforced as a hard limit by the service in terms of rejecting new connections beyond this count per proxy).
-   **Enable Logging:** Toggles detailed logging to the Burp Extensions output and the Log panel in the UI.
-   **Bypass Collaborator:** If checked, attempts to connect directly to known Burp Collaborator domains, bypassing upstream proxies.
-   **Proxy Selection Mode:**
    -   `Round-Robin`: Selects proxies sequentially from the active list.
    -   `Random`: Selects a random proxy from the active list for each new connection.
-   **Bypass Domains (one per line):** Manage a list of domains that should be connected to directly, bypassing the proxy list. Default entries include `burpcollaborator.net` and `oastify.com`.
-   **Reset to Default Settings:** Resets all settings in this tab to their original default values.

### Log Panel (Bottom of Main Tab)

-   Displays real-time operational logs from the extension, including connection attempts, proxy selections, errors, and status changes.

