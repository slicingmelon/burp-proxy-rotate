# v1.0.1

- Added standalone service tab UX improvements: separate stats labels per mode, cleaner layout, ports now shown without thousands separators.
- Default ports set to 10420 (main) and 10421 (standalone).
- Standalone start/stop UX hardened: prevents double-starts, allows cancel while starting, and keeps buttons in sync.
- Fixed thread/resource handling: selector thread pool and cleanup scheduler are cleaned up on start failure/stop; start callbacks run on EDT to keep Swing safe.
- Bumped Burp Montoya API to 2025.11.
- Fixed light theme text visibility for proxy inputs (see Burp feedback: [issuecomment-3626557084](https://github.com/PortSwigger/extension-portal/issues/32#issuecomment-3626557084)).

# v0.0.1 - v1.0

- Secret, private project.