package org.amnezia.vpn.protocol.awg

import android.net.VpnService.Builder
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.Statistics
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.protocol.wireguard.KernelTunnel
import org.amnezia.vpn.protocol.wireguard.Wireguard
import org.amnezia.vpn.protocol.wireguard.WireguardConfig
import org.amnezia.vpn.util.Log
import org.json.JSONObject

private const val TAG = "Awg"
const val IF_NAME = "awg0"

class Awg : Wireguard() {

    override val ifName: String = IF_NAME

    private var kernelTunnel: KernelTunnel? = null
    private var kernelStatusJob: Job? = null

    override val statistics: Statistics
        get() = kernelTunnel?.let { tunnel ->
            val (rx, tx) = tunnel.transferBytes() ?: return Statistics.EMPTY_STATISTICS
            Statistics.build {
                setRxBytes(rx)
                setTxBytes(tx)
            }
        } ?: super.statistics

    override fun parseConfig(config: JSONObject): WireguardConfig {
        val configData = config.getJSONObject("awg_config_data")
        return WireguardConfig.build {
            setUseProtocolExtension(true)
            configExtensionParameters(configData)
            configWireguard(config, configData)
            configSplitTunneling(config)
            configAppSplitTunneling(config)
        }
    }

    override suspend fun startVpn(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        if (KernelTunnel.isAvailable()) {
            try {
                val tunnel = KernelTunnel(ifName, parseConfig(config))
                if (tunnel.isRunning()) Log.i(TAG, "Adopting running kernel tunnel") else tunnel.up()
                kernelTunnel = tunnel
                launchKernelStatusJob(tunnel)
                return
            } catch (e: VpnStartException) {
                Log.e(TAG, "Kernel tunnel failed, falling back to userspace: ${e.message}")
            }
        }
        super.startVpn(config, vpnBuilder, protect)
    }

    override fun stopVpn() {
        val tunnel = kernelTunnel ?: return super.stopVpn()
        kernelStatusJob?.cancel()
        kernelStatusJob = null
        kernelTunnel = null
        tunnel.down()
        state.value = DISCONNECTED
    }

    override fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean) {
        val tunnel = kernelTunnel ?: return super.reconnectVpn(vpnBuilder, protect)
        tunnel.refreshEndpoint()
        state.value = CONNECTED
    }

    private fun launchKernelStatusJob(tunnel: KernelTunnel) {
        kernelStatusJob = scope.launch {
            while (tunnel.latestHandshake() <= 0L) delay(1000)
            state.value = CONNECTED
            kernelStatusJob = null
        }
    }
}
