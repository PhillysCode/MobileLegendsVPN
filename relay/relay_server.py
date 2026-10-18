#!/usr/bin/env python3
"""
LagRelay server (Linux VPS, run as root; it drops privileges after setup).

  pip install cryptography        # or: apt install python3-cryptography
  export RELAY_KEY=$(openssl rand -hex 32)   # 64 hex chars; same key goes in the app
  python3 relay_server.py

Wire format (UDP, must match the app):
  [12-byte random nonce][AES-256-GCM( type(1) | session(8) | seq(8) | payload )]
  type 0 = ping (echoed), 1 = hello/keepalive, 2 = raw IP packet.
Packets that fail authentication, or are replays / from an older session, are dropped.
One phone per relay (client gets 10.8.0.2).
"""
import fcntl, os, select, socket, struct, subprocess, sys, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HEXKEY = os.environ.get("RELAY_KEY", "").strip()
try:
    KEY = bytes.fromhex(HEXKEY)
except ValueError:
    KEY = b""
if len(KEY) != 32:
    sys.exit("RELAY_KEY must be 64 hex characters. Generate one with: openssl rand -hex 32")

PORT = int(os.environ.get("RELAY_PORT", "5555"))
TUN = "lagtun0"
PING, HELLO, DATA = 0, 1, 2
TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x400454CA, 0x0001, 0x1000
AES = AESGCM(KEY)
SESSION = time.time_ns() // 1_000_000
_seq = 0
WINDOW = 1024


def seal(ftype: int, payload: bytes) -> bytes:
    global _seq
    _seq += 1
    nonce = os.urandom(12)
    pt = struct.pack(">BQQ", ftype, SESSION, _seq) + payload
    return nonce + AES.encrypt(nonce, pt, None)


def open_(data: bytes):
    if len(data) < 12 + 16 + 17:
        return None
    try:
        pt = AES.decrypt(data[:12], data[12:], None)
    except Exception:
        return None
    ftype, sess, seq = struct.unpack(">BQQ", pt[:17])
    return ftype, sess, seq, pt[17:]


class ReplayWindow:
    def __init__(self):
        self.sess, self.max, self.seen = 0, -1, set()

    def accept(self, sess, seq):
        if sess < self.sess:
            return False
        if sess > self.sess:
            self.sess, self.max, self.seen = sess, -1, set()
        if seq <= self.max - WINDOW or seq in self.seen:
            return False
        self.seen.add(seq)
        if seq > self.max:
            self.max = seq
            if len(self.seen) > 2 * WINDOW:
                self.seen = {s for s in self.seen if s > self.max - WINDOW}
        return True


def sh(cmd):
    subprocess.run(cmd, shell=True, check=False)


def ipt(rule, table=None, insert=False):
    t = f"-t {table} " if table else ""
    sh(f"iptables {t}-C {rule} 2>/dev/null || iptables {t}{'-I' if insert else '-A'} {rule}")


def open_tun():
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", TUN.encode(), IFF_TUN | IFF_NO_PI))
    sh(f"ip addr add 10.8.0.1/24 dev {TUN}")
    sh(f"ip link set {TUN} mtu 1350 up")
    sh("sysctl -w net.ipv4.ip_forward=1")
    out = subprocess.run("ip route show default", shell=True, capture_output=True, text=True).stdout.split()
    iface = out[out.index("dev") + 1] if "dev" in out else "eth0"
    ipt(f"POSTROUTING -s 10.8.0.0/24 -o {iface} -j MASQUERADE", table="nat")
    # The tunnel client may only reach the public internet, never the relay itself,
    # cloud metadata, or private networks behind the VPS.
    ipt(f"INPUT -i {TUN} -j DROP", insert=True)
    for net in ("169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"):
        ipt(f"FORWARD -i {TUN} -d {net} -j DROP", insert=True)
    ipt(f"FORWARD -i {TUN} -j ACCEPT")
    ipt(f"FORWARD -o {TUN} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
    return fd


def main():
    tun = open_tun()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    try:  # nothing below needs root
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
    except Exception as e:
        print("warning: could not drop privileges:", e)
    rx = ReplayWindow()
    client = None
    print(f"LagRelay listening on UDP {PORT}")
    while True:
        r, _, _ = select.select([sock, tun], [], [])
        if sock in r:
            data, addr = sock.recvfrom(4096)
            res = open_(data)
            if res is None:
                continue
            ftype, sess, seq, payload = res
            if ftype == PING:
                sock.sendto(seal(PING, payload), addr)
                continue
            if ftype not in (HELLO, DATA) or not rx.accept(sess, seq):
                continue
            client = addr
            if ftype == HELLO:
                sock.sendto(seal(HELLO, b""), addr)
            else:
                try:
                    os.write(tun, payload)
                except OSError:
                    pass
        if tun in r:
            pkt = os.read(tun, 4096)
            if client:
                sock.sendto(seal(DATA, pkt), client)


if __name__ == "__main__":
    main()
