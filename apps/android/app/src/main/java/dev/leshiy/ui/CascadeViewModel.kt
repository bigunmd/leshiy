package dev.leshiy.ui

import androidx.lifecycle.ViewModel
import dev.leshiy.data.VaultHolder
import dev.leshiy.ui.screens.ProvisionPreset
import kotlinx.coroutines.flow.MutableStateFlow
import uniffi.leshiy_mobile.ServerInfo

/**
 * Drives the guided Cascade Builder: holds the plan, tracks which slots are deployed, and
 * computes the exit-first deploy sequence + each hop's DeployScreen preset. The pure logic
 * lives in Cascade.kt; this only wires state + the vault lookup.
 */
class CascadeViewModel : ViewModel() {
    val plan = MutableStateFlow(CascadePlan.default())
    val deployedIds = MutableStateFlow<Map<Int, String>>(emptyMap())
    val currentSlot = MutableStateFlow<Int?>(null)
    val entryCredential = MutableStateFlow<Credential?>(null)

    fun setSource(i: Int, source: SlotSource) { plan.value = plan.value.withSource(i, source) }
    fun addMiddle() { plan.value = plan.value.withMiddleAdded() }
    fun removeMiddle(i: Int) { plan.value = plan.value.withMiddleRemoved(i) }

    fun reset() {
        plan.value = CascadePlan.default()
        deployedIds.value = emptyMap()
        currentSlot.value = null
        entryCredential.value = null
    }

    private fun connectorOf(id: String): String? = VaultHolder.get()?.connectorUri(id)

    /** Next DeployNew slot to provision (exit-first), or null when the chain is fully deployed. */
    fun nextSlotToDeploy(): Int? = nextToDeploy(plan.value, deployedIds.value)

    /** Move to the next un-deployed slot; returns it (or null when done). */
    fun beginNext(): Int? = nextSlotToDeploy().also { currentSlot.value = it }

    fun recordDeployed(i: Int, serverId: String) {
        deployedIds.value = deployedIds.value + (i to serverId)
    }

    /** True once the entry (slot 0) has been deployed — its credential is the connect point. */
    fun entryDeployed(): Boolean = deployedIds.value.containsKey(0) ||
        plan.value.slots.getOrNull(0)?.source is SlotSource.UseExisting

    /** Build the DeployScreen preset for the current slot, naming the next hop for the banner. */
    fun presetForCurrent(servers: List<ServerInfo>): ProvisionPreset? {
        val i = currentSlot.value ?: return null
        val data = presetFor(plan.value, i, deployedIds.value, ::connectorOf)
        val role = plan.value.slots[i].role
        val labelHint = "${role.wire()}-$i"
        return ProvisionPreset(
            role = data.role,
            connector = data.connector,
            downstreamId = data.downstreamId,
            labelHint = labelHint,
            nextHopName = downstreamName(i, servers),
        )
    }

    private fun downstreamName(upstreamIndex: Int, servers: List<ServerInfo>): String? {
        val di = upstreamIndex + 1
        val slot = plan.value.slots.getOrNull(di) ?: return null // exit has no downstream
        return when (val s = slot.source) {
            is SlotSource.UseExisting -> servers.firstOrNull { it.id == s.serverId }?.label ?: s.serverId
            is SlotSource.PasteLink -> "external node"
            SlotSource.DeployNew -> deployedIds.value[di]?.let { id -> servers.firstOrNull { it.id == id }?.label ?: id }
            null -> null
        }
    }
}
