package com.example.lagrelay

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.text.InputType
import android.widget.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer

class MainActivity : Activity() {

    companion object {
        const val MLBB = "com.mobile.legends" // Mobile Legends: Bang Bang (global)
    }

    private lateinit var serverSpinner: Spinner
    private lateinit var appSpinner: Spinner
    private lateinit var keyInput: EditText
    private lateinit var launchBox: CheckBox
    private lateinit var status: TextView
    private lateinit var connectBtn: Button
    private lateinit var serverAdapter: ArrayAdapter<String>
    // index 0 = Auto (best ping), then SERVERS in order
    private val serverLabels = (listOf("Auto (best ping)") + SERVERS.map { it.name }).toMutableList()
    private val apps = mutableListOf<Pair<String, String>>() // label to package
    private val prefs by lazy { getSharedPreferences("lagrelay", Context.MODE_PRIVATE) }
    private var chosen: Server? = null
    @Volatile private var monitoring = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(pad, pad, pad, pad) }

        root.addView(TextView(this).apply { text = "LagRelay · Mobile Legends"; textSize = 22f })

        serverSpinner = Spinner(this)
        serverAdapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, serverLabels)
        serverSpinner.adapter = serverAdapter
        root.addView(label("Server")); root.addView(serverSpinner)

        loadApps()
        appSpinner = Spinner(this)
        appSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, apps.map { it.first })
        val mlIdx = apps.indexOfFirst { it.second == MLBB }
        if (mlIdx >= 0) appSpinner.setSelection(mlIdx)
        else Toast.makeText(this, "Mobile Legends not found - pick your game version manually", Toast.LENGTH_LONG).show()
        root.addView(label("Game")); root.addView(appSpinner)

        keyInput = EditText(this).apply {
            hint = "Relay key (64 hex characters)"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setText(prefs.getString("key", ""))
        }
        root.addView(keyInput)

        launchBox = CheckBox(this).apply { text = "Launch game after connecting"; isChecked = true }
        root.addView(launchBox)

        val pingBtn = Button(this).apply { text = "Ping all servers"; setOnClickListener { pingAll() } }
        connectBtn = Button(this).apply { text = "Connect"; setOnClickListener { toggle() } }
        status = TextView(this).apply { text = "Disconnected" }
        root.addView(pingBtn); root.addView(connectBtn); root.addView(status)
        setContentView(root)
    }

    private fun label(t: String) = TextView(this).apply { text = t; setPadding(0, 24, 0, 0) }

    private fun loadApps() {
        val i = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        packageManager.queryIntentActivities(i, 0)
            .map { it.loadLabel(packageManager).toString() to it.activityInfo.packageName }
            .filter { it.second != packageName }
            .distinctBy { it.second }
            .sortedBy { it.first.lowercase() }
            .let { apps.addAll(it) }
    }

    private fun toggle() {
        if (TunnelVpnService.running || monitoring) {
            startService(Intent(this, TunnelVpnService::class.java).setAction(TunnelVpnService.ACTION_STOP))
            setConnected(false); return
        }
        val key = keyInput.text.toString().trim()
        val keyBytes = hexToBytes(key)
        if (keyBytes == null) { toast("Key must be 64 hex characters (see README)"); return }
        prefs.edit().putString("key", key).apply()

        val pos = serverSpinner.selectedItemPosition
        if (pos == 0) {
            // Auto: ping every configured server, take the lowest
            status.text = "Testing servers..."
            connectBtn.isEnabled = false
            val auth = Auth(keyBytes)
            Thread {
                val best = SERVERS.filter { !it.host.startsWith("YOUR_") }
                    .mapNotNull { s -> ping(s, auth, 3)?.let { s to it } }
                    .minByOrNull { it.second }
                runOnUiThread {
                    connectBtn.isEnabled = true
                    if (best == null) status.text = "No server replied. Check IPs, key and firewall (UDP 5555)."
                    else { chosen = best.first; requestVpn() }
                }
            }.start()
        } else {
            val s = SERVERS[pos - 1]
            if (s.host.startsWith("YOUR_")) { toast("Set this server's IP in Proto.kt first"); return }
            chosen = s
            requestVpn()
        }
    }

    private fun requestVpn() {
        val prep = VpnService.prepare(this)
        if (prep != null) startActivityForResult(prep, 1) else startTunnel()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1 && resultCode == RESULT_OK) startTunnel()
    }

    private fun startTunnel() {
        val server = chosen ?: return
        val pkg = apps[appSpinner.selectedItemPosition].second
        startService(Intent(this, TunnelVpnService::class.java)
            .putExtra("host", server.host).putExtra("port", server.port)
            .putExtra("key", keyInput.text.toString().trim())
            .putExtra("pkg", pkg))
        connectBtn.text = "Disconnect"
        startMonitor(server, Auth(hexToBytes(keyInput.text.toString().trim())!!))
        if (launchBox.isChecked) {
            window.decorView.postDelayed({
                packageManager.getLaunchIntentForPackage(pkg)?.let { startActivity(it) }
            }, 1200)
        }
    }

    private fun setConnected(on: Boolean) {
        if (!on) { monitoring = false; connectBtn.text = "Connect"; status.text = "Disconnected" }
    }

    /** Live latency + loss to the relay while connected (last 20 pings). */
    private fun startMonitor(server: Server, auth: Auth) {
        monitoring = true
        Thread {
            val t0 = System.currentTimeMillis()
            val window = ArrayDeque<Long?>()
            while (monitoring) {
                window.addLast(ping(server, auth, 1))
                if (window.size > 20) window.removeFirst()
                val ok = window.filterNotNull()
                val loss = 100 * (window.size - ok.size) / window.size
                val avg = if (ok.isEmpty()) null else ok.average().toLong()
                val dead = !TunnelVpnService.running && System.currentTimeMillis() - t0 > 6000
                runOnUiThread {
                    if (dead) setConnected(false)
                    else status.text = "Connected via ${server.name}\nRelay ping: ${avg ?: "-"} ms · loss: $loss%"
                }
                if (dead) break
                try { Thread.sleep(2000) } catch (_: InterruptedException) {}
            }
        }.start()
    }

    private fun pingAll() {
        val keyBytes = hexToBytes(keyInput.text.toString().trim())
        if (keyBytes == null) { toast("Key must be 64 hex characters (see README)"); return }
        Thread {
            val auth = Auth(keyBytes)
            SERVERS.forEachIndexed { idx, s ->
                val ms = if (s.host.startsWith("YOUR_")) null else ping(s, auth, 3)
                runOnUiThread {
                    serverLabels[idx + 1] = "${s.name}  -  " + when {
                        s.host.startsWith("YOUR_") -> "not set"
                        ms == null -> "no reply"
                        else -> "$ms ms"
                    }
                    serverAdapter.notifyDataSetChanged()
                }
            }
        }.start()
    }

    /** Best of [count] round trips to the relay in ms, or null if none came back. */
    private fun ping(s: Server, auth: Auth, count: Int): Long? {
        var best: Long? = null
        try {
            DatagramSocket().use { sock ->
                sock.soTimeout = 1000
                sock.connect(InetSocketAddress(InetAddress.getByName(s.host), s.port))
                repeat(count) {
                    val payload = ByteBuffer.allocate(8).putLong(System.nanoTime()).array()
                    val f = auth.seal(T_PING, payload, 8)
                    val t0 = System.nanoTime()
                    sock.send(DatagramPacket(f, f.size))
                    val rb = ByteArray(128)
                    val p = DatagramPacket(rb, rb.size)
                    try {
                        sock.receive(p)
                        val r = auth.open(rb, p.length)
                        if (r != null && r.type == T_PING && r.payload.contentEquals(payload)) {
                            val ms = (System.nanoTime() - t0) / 1_000_000
                            val b = best
                            if (b == null || ms < b) best = ms
                        }
                    } catch (_: Exception) {}
                }
            }
        } catch (_: Exception) {}
        return best
    }

    private fun toast(m: String) = Toast.makeText(this, m, Toast.LENGTH_SHORT).show()
}
