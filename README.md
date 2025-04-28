# Burp SOCKS Proxy Rotator

A Burp Suite extension that routes HTTP/HTTPS requests through a rotating SOCKS proxy from a configured list.

## Features

- Randomly selects a different SOCKS proxy for each connection
- Supports both SOCKS4 and SOCKS5 protocols
- Full IPv4 and IPv6 support
- Manual proxy validation
- Simple UI for managing proxy list

## How to Use

1. Add one or more SOCKS proxies to the list
2. Validate proxies to ensure they're working
3. Start the proxy server
4. Configure Burp to use the local proxy:
   - Go to Burp → Settings → Network → Connections → SOCKS Proxy
   - Check "Use SOCKS proxy"
   - Set Host to "localhost" and Port to match your configured port (default 1080)

## Code Organization

The extension consists of three main classes:

- `BurpSocksRotate` - Main extension class with UI
- `SocksProxyService` - Core SOCKS proxy rotation logic
- `ProxyEntry` - Simple data class for proxy information

## Architecture

For each incoming connection:
1. The SocksProxyService accepts the connection
2. It randomly selects an active proxy from the list
3. It connects to the target via the selected proxy
4. It relays traffic bidirectionally

If a connection fails, it automatically tries another proxy.