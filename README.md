# LagRelay (personal ExitLag-style tunnel for Android, tuned for Mobile Legends)

Phone game -> AES-256-GCM encrypted UDP tunnel -> your VPS (Manila / SEA) -> game server.

## 1. Set up each relay VPS (Ubuntu, as root)
    apt install -y python3-cryptography
    mkdir -p /opt/lagrelay
    # copy relay/relay_server.py to /opt/lagrelay/ and relay/lagrelay.service to /etc/systemd/system/
    echo "RELAY_KEY=$(openssl rand -hex 32)" > /etc/lagrelay.env
    chmod 600 /etc/lagrelay.env
    cat /etc/lagrelay.env          # copy the 64-character key into the app
    ufw allow 5555/udp             # and open UDP 5555 in the provider firewall
    systemctl daemon-reload && systemctl enable --now lagrelay
Use a different key per server if you like; the app uses one key for all servers, so for simplicity use the same key everywhere.

## 2. Build the APK (GitHub Actions)
1. Put your VPS IPs in `app/src/main/java/com/example/lagrelay/Proto.kt`.
2. Commit. Actions -> Build APK -> download the `LagRelay-APK` artifact -> install `app-debug.apk`.

## 3. Use it
Enter the 64-character key, leave Server on Auto, Mobile Legends is preselected, Connect.

## Security notes
- Encrypted + authenticated (AES-256-GCM), replay-protected, random per-packet nonces.
- Whoever has the key can use your relay. Keep the repo private; the key is typed into the app, not stored in the repo. Rotate it by editing /etc/lagrelay.env and restarting.
- The tunnel client can't reach the relay itself, cloud metadata or private networks.
- The relay owner (you) can see traffic leaving the relay, as with any VPN. No forward secrecy; not independently audited.
- Debug-signed APK, key kept in the app's private storage: fine for personal use.
- If you change the phone's clock backwards and it stops connecting, restart the relay (`systemctl restart lagrelay`).
