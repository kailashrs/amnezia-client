package org.amnezia.vpn.protocol.wireguard

import android.util.Base64
import java.util.concurrent.TimeUnit
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.IpRange
import org.amnezia.vpn.util.net.IpRangeSet

private const val TAG = "KernelTunnel"

// Before netd's VPN rules at 13000, which privileged sockets can opt out of.
private const val STRICT_RULE_PRIORITY = 12500

// Every uid except root (the tunnel's own socket), radio, wifi, dhcp, clat, network stack and shell (adb).
private val STRICT_UID_RANGES = listOf(
    1..1000, 1002..1009, 1011..1013, 1015..1028, 1030..1072, 1074..1999, 2001..2147483646
)

// Installed over adb. The module is built for one kernel, so it does not ship in the APK.
private const val ROOT_DIR = "/data/adb/amnezia-kernel"
private const val SHELL_ENV = "export PATH=$ROOT_DIR/bin:\$PATH"
private const val COMMAND_TIMEOUT_SECONDS = 30L

private val PACKAGE_UIDS = Regex("package:(\\S+) uid:([0-9,]+)")

/** Runs an AmneziaWG tunnel through the amneziawg kernel module and awg-quick, as root. */
class KernelTunnel(private val ifName: String, private val config: WireguardConfig) {

    private val configPath = "$ROOT_DIR/$ifName.conf"
    private val publicKey = config.publicKeyHex.hexToBase64()

    // Android keeps IPv6 disabled on an interface with no IPv6 address, so IPv6 routes can't use it.
    private val hasIpv6Address = config.addresses.any { it.isIpv6 }
    private val tunnelsIpv6 = hasIpv6Address && config.routes.any { it.include && it.inetNetwork.isIpv6 }

    // netd names the table after the interface. Only its rules match the tunnel's uids, so no other app is affected.
    // awg-quick only routes what AllowedIPs lists, so IPv6 would bypass the tunnel. VpnService blocks
    // a family the VPN doesn't carry with an unreachable route, so this does the same in the tunnel's table.
    private val findRouteTable =
        "table=\$(ip rule | grep -oE 'lookup $ifName( |\$)' | head -1 | awk '{print \$2}')"
    private val blockIpv6 =
        "[ -n \"\$table\" ] && ip -6 route replace unreachable ::/0 table \"\$table\""
    private val unblockIpv6 =
        "[ -z \"\$table\" ] || ip -6 route del unreachable ::/0 table \"\$table\" 2>/dev/null"

    // A full tunnel also covers system apps, bound sockets and other users, which netd's VPN rules leave out.
    // Excluded apps stay out by uid. An included-apps list means only those apps should use the tunnel.
    private val strictMode = config.includedApplications.isEmpty() &&
        config.routes.any { it.include && it.inetNetwork == InetNetwork("0.0.0.0", 0) }

    // Called only on start: resolving uids needs a pm call.
    private fun enableStrict(): String = buildList {
        val excludedUids = excludedUids()
        STRICT_UID_RANGES.flatMap { it.without(excludedUids) }.forEach {
            val uids = "${it.first}-${it.last}"
            add("ip rule add pref $STRICT_RULE_PRIORITY iif lo uidrange $uids lookup $ifName")
            add("ip -6 rule add pref $STRICT_RULE_PRIORITY iif lo uidrange $uids lookup $ifName")
        }
        // Rerouted sockets keep their old source address, which the server would drop.
        config.addresses.firstOrNull { it.isIpv4 }?.let { address ->
            add("iptables -w -t nat -N AWG_SNAT")
            add("iptables -w -t nat -A AWG_SNAT -o $ifName ! -s ${address.address.hostAddress} -j SNAT --to-source ${address.address.hostAddress}")
            add("iptables -w -t nat -A POSTROUTING -j AWG_SNAT")
        }
        // DNS bound to the underlying network would otherwise reach a resolver the tunnel can't.
        config.dnsServers.firstOrNull { it is java.net.Inet4Address }?.hostAddress?.let { dns ->
            add("iptables -w -t nat -N AWG_DNS")
            excludedUids.forEach { add("iptables -w -t nat -A AWG_DNS -m owner --uid-owner $it -j RETURN") }
            STRICT_UID_RANGES.forEach {
                listOf("udp", "tcp").forEach { protocol ->
                    add("iptables -w -t nat -A AWG_DNS -m owner --uid-owner ${it.first}-${it.last} -p $protocol --dport 53 ! -d $dns -j DNAT --to-destination $dns:53")
                }
            }
            add("iptables -w -t nat -A OUTPUT -j AWG_DNS")
        }
    }.joinToString(" && ")

    /** Returns the excluded apps' uids in every user they're installed for. */
    private fun excludedUids(): List<Int> {
        if (config.excludedApplications.isEmpty()) return emptyList()
        val result = root("pm list packages -U")
        // Without this list the rules would capture every excluded app.
        if (result.exitCode != 0 || !result.output.contains("package:")) {
            throw VpnStartException("Can't resolve excluded apps: ${result.output}")
        }
        return result.output.lineSequence()
            .mapNotNull { PACKAGE_UIDS.matchEntire(it.trim()) }
            .filter { it.groupValues[1] in config.excludedApplications }
            .flatMap { it.groupValues[2].split(",") }
            .map { it.toInt() }
            .toList()
    }

    private fun IntRange.without(uids: List<Int>): List<IntRange> = buildList {
        var start = first
        uids.filter { it in this@without }.distinct().sorted().forEach {
            if (it > start) add(start until it)
            start = it + 1
        }
        if (start <= last) add(start..last)
    }

    // Rules go by priority, as a table name stops resolving once the interface is gone.
    private val disableStrict = listOf(
        "while ip rule del pref $STRICT_RULE_PRIORITY 2>/dev/null; do :; done",
        "while ip -6 rule del pref $STRICT_RULE_PRIORITY 2>/dev/null; do :; done",
        "iptables -w -t nat -D OUTPUT -j AWG_DNS 2>/dev/null",
        "iptables -w -t nat -F AWG_DNS 2>/dev/null",
        "iptables -w -t nat -X AWG_DNS 2>/dev/null",
        "iptables -w -t nat -D POSTROUTING -j AWG_SNAT 2>/dev/null",
        "iptables -w -t nat -F AWG_SNAT 2>/dev/null",
        "iptables -w -t nat -X AWG_SNAT 2>/dev/null"
    ).joinToString("\n")

    private val tearDown = "$disableStrict\nawg-quick down $configPath\nrm -f $configPath"

    fun up() {
        // Built line by line: a heredoc terminator must start at column 0.
        val result = root(
            listOf(
                SHELL_ENV,
                "[ -d /sys/module/amneziawg ] || exit 10",
                "if ip link show $ifName >/dev/null 2>&1; then",
                findRouteTable,
                unblockIpv6,
                disableStrict,
                "awg-quick down $configPath",
                "fi",
                disableStrict,
                "umask 077",
                "cat > $configPath <<'AWG_CONFIG_END'",
                toAwgQuickString(),
                "AWG_CONFIG_END",
                "awg-quick up $configPath || exit \$?",
                if (tunnelsIpv6) ":" else "$findRouteTable\n$blockIpv6 || { $tearDown\nexit 11; }",
                if (strictMode) "{ ${enableStrict()}; } || { $findRouteTable\n$unblockIpv6\n$tearDown\nexit 12; }" else ":"
            ).joinToString("\n")
        )
        if (result.exitCode != 0) {
            throw VpnStartException("awg-quick up failed (${result.exitCode}): ${result.output}")
        }
    }

    /** True when this exact tunnel is already up, so it can be adopted without dropping the connection. */
    fun isRunning(): Boolean = root(
        listOf(
            SHELL_ENV,
            "[ -d /sys/class/net/$ifName ] || exit 1",
            "umask 077",
            "cat > $configPath.new <<'AWG_CONFIG_END'",
            toAwgQuickString(),
            "AWG_CONFIG_END",
            "cmp -s $configPath $configPath.new; same=\$?",
            "rm -f $configPath.new",
            "[ \$same -eq 0 ] || exit 1",
            if (tunnelsIpv6) ":" else "ip -6 route show table $ifName | grep -q '^unreachable' || exit 1",
            if (strictMode) "ip rule | grep -q '^$STRICT_RULE_PRIORITY:'" else "! ip rule | grep -q '^$STRICT_RULE_PRIORITY:'"
        ).joinToString("\n")
    ).exitCode == 0

    fun down() {
        val result = root("$SHELL_ENV\n$findRouteTable\n$unblockIpv6\n$tearDown")
        if (result.exitCode != 0) Log.e(TAG, "awg-quick down failed: ${result.output}")
    }

    /** Setting the endpoint drops the cached source address, so the next packet uses the new network. */
    fun refreshEndpoint() {
        val result = root("$SHELL_ENV\nawg set $ifName peer '$publicKey' endpoint '${config.endpoint}'")
        if (result.exitCode != 0) Log.e(TAG, "Endpoint refresh failed: ${result.output}")
    }

    fun latestHandshake(): Long =
        root("$SHELL_ENV\nawg show $ifName latest-handshakes").output
            .trim().split(Regex("\\s+")).getOrNull(1)?.toLongOrNull() ?: 0L

    /** Returns received and sent bytes, or null if the tunnel can't be read. */
    fun transferBytes(): Pair<Long, Long>? {
        val fields = root("$SHELL_ENV\nawg show $ifName transfer").output.trim().split(Regex("\\s+"))
        val rx = fields.getOrNull(1)?.toLongOrNull() ?: return null
        val tx = fields.getOrNull(2)?.toLongOrNull() ?: return null
        return rx to tx
    }

    private fun toAwgQuickString(): String = with(StringBuilder()) {
        appendLine("[Interface]")
        appendLine("PrivateKey=${config.privateKeyHex.hexToBase64()}")
        appendLine("Address=${config.addresses.joinToString(",")}")
        if (config.dnsServers.isNotEmpty()) {
            appendLine("DNS=${config.dnsServers.joinToString(",") { it.hostAddress.orEmpty() }}")
        }
        appendLine("MTU=${config.mtu}")
        if (config.includedApplications.isNotEmpty()) {
            appendLine("IncludedApplications=${config.includedApplications.joinToString(",")}")
        }
        if (config.excludedApplications.isNotEmpty()) {
            appendLine("ExcludedApplications=${config.excludedApplications.joinToString(",")}")
        }
        appendObfuscation()
        appendLine("[Peer]")
        appendLine("PublicKey=$publicKey")
        config.preSharedKeyHex?.let { appendLine("PresharedKey=${it.hexToBase64()}") }
        appendLine("AllowedIPs=${allowedIps().joinToString(",")}")
        appendLine("Endpoint=${config.endpoint}")
        config.persistentKeepalive?.takeIf { it.isNotEmpty() && it != "0" }?.let {
            appendLine("PersistentKeepalive=$it")
        }
        toString().trimEnd()
    }

    private fun StringBuilder.appendObfuscation() = with(config) {
        fun line(key: String, value: Any?) {
            if (value != null && value.toString().isNotEmpty()) appendLine("$key=$value")
        }
        if (useProtocolExtension) {
            line("Jc", jc); line("Jmin", jmin); line("Jmax", jmax)
            line("S1", s1); line("S2", s2); line("S3", s3); line("S4", s4)
            line("H1", h1); line("H2", h2); line("H3", h3); line("H4", h4)
            line("I1", i1); line("I2", i2); line("I3", i3); line("I4", i4); line("I5", i5)
        }
        line("HeaderProtectionKey", headerProtectionKeyHex?.takeIf { it.isNotEmpty() }?.hexToBase64())
        line("ContentPaddingAddition", contentPaddingAddition)
        line("RekeyAfterTime", rekeyAfterTime)
        line("RekeyTimeout", rekeyTimeout)
        line("RejectAfterTime", rejectAfterTime)
        line("KeepaliveTimeout", keepaliveTimeout)
        line("MaxHandshakeAttempts", maxHandshakeAttempts)
        line("RandomTrailers", randomTrailers)
        line("DisableCookies", disableCookies)
    }

    /** AllowedIPs can't express exclusions, so excluded sites are subtracted from the included routes. */
    private fun allowedIps(): List<InetNetwork> = includedNetworks().filter { it.isIpv4 || hasIpv6Address }

    private fun includedNetworks(): List<InetNetwork> {
        if (config.routes.all { it.include }) return config.routes.map { it.inetNetwork }
        val ranges = IpRangeSet()
        config.routes.filter { it.include }.forEach { ranges.add(IpRange(it.inetNetwork)) }
        config.routes.filterNot { it.include }.forEach { ranges.remove(IpRange(it.inetNetwork)) }
        ranges.remove(IpRange("127.0.0.0", 8))
        ranges.remove(IpRange("::1", 128))
        return ranges.subnets()
    }

    private fun String.hexToBase64(): String {
        val bytes = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    companion object {
        /** True when root works, the module is loaded and the tools are installed. */
        fun isAvailable(): Boolean = root(
            "[ -d /sys/module/amneziawg ] && [ -x $ROOT_DIR/bin/awg ] && [ -x $ROOT_DIR/bin/awg-quick ]"
        ).exitCode == 0

        /** True when an interface outlived the process that created it, for example after a crash. */
        fun isInterfaceUp(ifName: String): Boolean = root("[ -d /sys/class/net/$ifName ]").exitCode == 0

        private data class Result(val exitCode: Int, val output: String)

        // The script goes over stdin so keys never appear in process arguments.
        private fun root(script: String): Result = try {
            val process = ProcessBuilder("su").redirectErrorStream(true).start()
            process.outputStream.bufferedWriter().use { it.write(script + "\n") }
            val output = process.inputStream.bufferedReader().readText()
            if (process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                Result(process.exitValue(), output)
            } else {
                process.destroyForcibly()
                Result(-1, "timed out")
            }
        } catch (e: java.io.IOException) {
            Result(-1, e.message.orEmpty())
        }
    }
}
