package com.example.lagrelay

import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// EDIT THIS: put the public IP of each VPS you rent.
data class Server(val name: String, val host: String, val port: Int = 5555)

val SERVERS = listOf(
    Server("Manila (PH)", "YOUR_MANILA_IP"),
    Server("Singapore", "YOUR_SINGAPORE_IP"),
    Server("Jakarta (ID)", "YOUR_JAKARTA_IP"),
    Server("Bangkok (TH)", "YOUR_BANGKOK_IP"),
)

const val T_PING: Byte = 0
const val T_HELLO: Byte = 1
const val T_DATA: Byte = 2

/** 64 hex characters -> 32-byte key, or null if malformed. */
fun hexToBytes(s: String): ByteArray? {
    if (!Regex("^[0-9a-fA-F]{64}$").matches(s)) return null
    return ByteArray(32) { i -> s.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
}

class Packet(val type: Byte, val payload: ByteArray)

/**
 * Wire format (must match relay_server.py):
 *   [12-byte random nonce][AES-256-GCM( type(1) | session(8) | seq(8) | payload )]
 * session = sender start time in ms (only ever increases), seq counts up per packet.
 * Receivers drop anything that fails authentication, is from an older session,
 * or repeats / is far older than a sequence number already seen (replay protection).
 */
class Auth(keyBytes: ByteArray) {
    private val key = SecretKeySpec(keyBytes, "AES")
    private val rng = SecureRandom()
    private val session = System.currentTimeMillis()
    private var seq = 0L

    private var rxSession = 0L
    private var rxMax = -1L
    private val rxSeen = HashSet<Long>()
    private val WINDOW = 1024

    private val encCipher = object : ThreadLocal<Cipher>() {
        override fun initialValue(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
    }
    private val decCipher = object : ThreadLocal<Cipher>() {
        override fun initialValue(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
    }

    fun seal(type: Byte, payload: ByteArray, len: Int): ByteArray {
        val s = synchronized(this) { ++seq }
        val pt = ByteBuffer.allocate(17 + len)
            .put(type).putLong(session).putLong(s).put(payload, 0, len).array()
        val nonce = ByteArray(12).also { rng.nextBytes(it) }
        val c = encCipher.get()!!
        c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
        return nonce + c.doFinal(pt)
    }

    fun open(buf: ByteArray, n: Int): Packet? {
        if (n < 12 + 16 + 17) return null
        val pt = try {
            val c = decCipher.get()!!
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, buf, 0, 12))
            c.doFinal(buf, 12, n - 12)
        } catch (_: Exception) { return null }
        val bb = ByteBuffer.wrap(pt)
        val type = bb.get(); val sess = bb.getLong(); val sq = bb.getLong()
        if (type != T_PING && !accept(sess, sq)) return null
        val payload = ByteArray(pt.size - 17)
        bb.get(payload)
        return Packet(type, payload)
    }

    @Synchronized
    private fun accept(sess: Long, sq: Long): Boolean {
        if (sess < rxSession) return false
        if (sess > rxSession) { rxSession = sess; rxMax = -1; rxSeen.clear() }
        if (sq <= rxMax - WINDOW) return false
        if (!rxSeen.add(sq)) return false
        if (sq > rxMax) {
            rxMax = sq
            if (rxSeen.size > 2 * WINDOW) rxSeen.removeAll { it <= rxMax - WINDOW }
        }
        return true
    }
}
