package com.example.lagrelay

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

class TunnelVpnService : VpnService() {

    companion object {
        const val ACTION_STOP = "lagrelay.STOP"
        @Volatile var running = false
    }

    private var tun: ParcelFileDescriptor? = null
    private var sock: DatagramSocket? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel(); stopSelf(); return START_NOT_STICKY
        }
        val host = intent?.getStringExtra("host") ?: return START_NOT_STICKY
        val port = intent.getIntExtra("port", 5555)
        val key = intent.getStringExtra("key") ?: return START_NOT_STICKY
        val pkg = intent.getStringExtra("pkg") ?: return START_NOT_STICKY
        val kb = hexToBytes(key.trim()) ?: return START_NOT_STICKY
        stopTunnel()
        Thread { startTunnel(host, port, kb, pkg) }.start()
        return START_NOT_STICKY
    }

    private fun startTunnel(host: String, port: Int, key: ByteArray, pkg: String) {
        try {
            val auth = Auth(key)
            val s = DatagramSocket()
            protect(s) // keep the tunnel's own socket OUT of the VPN, or it loops
            s.connect(InetSocketAddress(InetAddress.getByName(host), port))
            sock = s

            val fd = Builder()
                .setSession("LagRelay")
                .addAddress("10.8.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .setMtu(1350)
                .addAllowedApplication(pkg) // only the selected game uses the tunnel
                .setBlocking(true)
                .establish() ?: return
            tun = fd
            running = true

            val input = FileInputStream(fd.fileDescriptor)
            val output = FileOutputStream(fd.fileDescriptor)

            // phone -> relay
            Thread {
                val buf = ByteArray(32767)
                try {
                    while (running) {
                        val n = input.read(buf)
                        if (n > 0) {
                            val f = auth.seal(T_DATA, buf, n)
                            s.send(DatagramPacket(f, f.size))
                        }
                    }
                } catch (_: Exception) {}
            }.start()

            // keepalive so the relay knows where to send packets back
            Thread {
                try {
                    while (running) {
                        val f = auth.seal(T_HELLO, ByteArray(0), 0)
                        s.send(DatagramPacket(f, f.size))
                        Thread.sleep(10_000)
                    }
                } catch (_: Exception) {}
            }.start()

            // relay -> phone (this thread)
            val rb = ByteArray(65535)
            val pkt = DatagramPacket(rb, rb.size)
            while (running) {
                s.receive(pkt)
                val p = auth.open(rb, pkt.length)
                if (p != null && p.type == T_DATA) output.write(p.payload)
                pkt.length = rb.size
            }
        } catch (_: Exception) {
        } finally {
            stopTunnel()
        }
    }

    private fun stopTunnel() {
        running = false
        try { sock?.close() } catch (_: Exception) {}
        try { tun?.close() } catch (_: Exception) {}
        sock = null; tun = null
    }

    override fun onRevoke() { stopTunnel(); super.onRevoke() }
    override fun onDestroy() { stopTunnel(); super.onDestroy() }
}
