package dev.leshiy.ui

import uniffi.leshiy_mobile.ServerInfo

/** A hop's role in the chain. Client dials ENTRY; traffic leaves at EXIT. */
enum class HopRole { ENTRY, MIDDLE, EXIT }

/** The role string the bridge/engine expects. */
fun HopRole.wire(): String = when (this) {
    HopRole.ENTRY -> "entry"
    HopRole.MIDDLE -> "middle"
    HopRole.EXIT -> "exit"
}

/** How a slot is filled. */
sealed interface SlotSource {
    /** Deploy a fresh server for this hop. */
    data object DeployNew : SlotSource
    /** Reuse one of the user's saved servers. */
    data class UseExisting(val serverId: String) : SlotSource
    /** An external node referenced only by its connector link (exit/middle only). */
    data class PasteLink(val connectorUri: String) : SlotSource
}

data class Slot(val role: HopRole, val source: SlotSource? = null)

/** Ordered entry→exit. Pure; no Android/FFI deps so it unit-tests on the JVM. */
data class CascadePlan(val slots: List<Slot>) {
    val isReady: Boolean get() = slots.all { it.source != null } && entryValid()

    /** The entry hop must be the user's own node (never an external paste). */
    fun entryValid(): Boolean =
        slots.firstOrNull { it.role == HopRole.ENTRY }?.source.let { it != null && it !is SlotSource.PasteLink }

    /** Deploy order: exit first (each upstream needs its downstream's connector). */
    fun wiringOrder(): List<Int> = slots.indices.reversed().toList()

    fun withSource(index: Int, source: SlotSource): CascadePlan =
        copy(slots = slots.mapIndexed { i, s -> if (i == index) s.copy(source = source) else s })

    /** Insert a MIDDLE just before the EXIT (the last slot). */
    fun withMiddleAdded(): CascadePlan {
        val exitIdx = slots.indexOfLast { it.role == HopRole.EXIT }
        val out = slots.toMutableList()
        out.add(exitIdx, Slot(HopRole.MIDDLE))
        return copy(slots = out)
    }

    /** Remove the MIDDLE at [index] (no-op if it isn't a middle). */
    fun withMiddleRemoved(index: Int): CascadePlan {
        if (slots.getOrNull(index)?.role != HopRole.MIDDLE) return this
        return copy(slots = slots.filterIndexed { i, _ -> i != index })
    }

    companion object {
        fun default() = CascadePlan(listOf(Slot(HopRole.ENTRY), Slot(HopRole.EXIT)))
    }
}

/** The wiring an upstream node needs to point at its downstream. */
data class Wiring(val connector: String, val downstreamId: String?)

/**
 * Resolve a downstream slot into the (connector, downstreamId) its upstream needs.
 * [deployedId] is the just-deployed server id for a `DeployNew` slot (null before deploy).
 * [connectorOf] fetches a saved server's connector credential (ServerManager.connectorUri).
 * Returns null when not yet resolvable (a DeployNew not deployed, or a node with no connector).
 */
fun resolveDownstream(
    source: SlotSource,
    deployedId: String?,
    connectorOf: (String) -> String?,
): Wiring? = when (source) {
    is SlotSource.UseExisting -> connectorOf(source.serverId)?.let { Wiring(it, source.serverId) }
    is SlotSource.PasteLink -> Wiring(source.connectorUri, null)
    SlotSource.DeployNew -> deployedId?.let { id -> connectorOf(id)?.let { Wiring(it, id) } }
}

/** Plain data the screen maps to a ProvisionPreset (kept FFI/Compose-free for tests). */
data class ProvisionPresetData(val role: String, val connector: String?, val downstreamId: String?)

/** Next DeployNew slot to provision, in exit-first order, not yet deployed. Null when done. */
fun nextToDeploy(plan: CascadePlan, deployed: Map<Int, String>): Int? =
    plan.wiringOrder().firstOrNull { i ->
        plan.slots[i].source is SlotSource.DeployNew && !deployed.containsKey(i)
    }

/** Build the preset for slot [i]: role from the slot, downstream from slot i+1 (toward exit). */
fun presetFor(
    plan: CascadePlan,
    i: Int,
    deployed: Map<Int, String>,
    connectorOf: (String) -> String?,
): ProvisionPresetData {
    val role = plan.slots[i].role
    val down = plan.slots.getOrNull(i + 1) // toward the exit
    val wiring = down?.let {
        resolveDownstream(it.source ?: SlotSource.DeployNew, deployed[i + 1], connectorOf)
    }
    return ProvisionPresetData(
        role = role.wire(),
        connector = if (role == HopRole.EXIT) null else wiring?.connector,
        downstreamId = if (role == HopRole.EXIT) null else wiring?.downstreamId,
    )
}

data class ChainNode(val server: ServerInfo? = null, val missingId: String? = null)
data class Cascade(val nodes: List<ChainNode>) // ordered entry → exit

/** Build entry→exit chains by following `downstream` links from every entry node. */
fun buildCascades(servers: List<ServerInfo>): List<Cascade> {
    val byId = servers.associateBy { it.id }
    return servers.filter { it.role == "entry" }.map { entry ->
        val nodes = mutableListOf(ChainNode(server = entry))
        var cur: ServerInfo? = entry
        val seen = mutableSetOf(entry.id)
        while (cur?.downstream != null) {
            val nextId = cur.downstream!!
            val next = byId[nextId]
            if (next == null) {
                nodes.add(ChainNode(missingId = nextId)); break
            }
            nodes.add(ChainNode(server = next))
            if (!seen.add(next.id)) break // cycle guard
            cur = next
        }
        Cascade(nodes)
    }
}

/** Ids that participate in any multi-hop chain (for badging / list dedupe). */
fun chainedIds(servers: List<ServerInfo>): Set<String> =
    buildCascades(servers).flatMap { c -> c.nodes.mapNotNull { it.server?.id } }.toSet()
