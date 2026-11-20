#!/system/bin/sh
# Run as the shell UID, outside the VPN-exempt app. The only argument is the test nonce.
exec 2>&1
printf 'GET /%s HTTP/1.0\r\nHost: fixture\r\n\r\n' "$1" | timeout 10 nc -w 8 192.0.2.42 80
