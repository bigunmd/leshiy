package dev.leshiy.ui

import uniffi.leshiy_mobile.ServerInfo

/**
 * Detects that a deploy would overwrite a server already saved in the vault.
 *
 * The vault keys records by `"{host}-{ssh_port}"` and `Vault::upsert` *replaces* a record with a
 * matching id. That is right for a re-provision or a repair, and wrong — silently — when the user
 * believes they are adding a second, separate server on a host they already use.
 *
 * The damage is not the record itself but the chain metadata on it. Deploying to a host that holds
 * a cascade's exit node overwrites that record's `role`, `connector_uri`, and `downstream` with
 * `single`, so the upstream entry node's `downstream` is left pointing at a record that no longer
 * claims to be part of any chain. Both servers keep working; only the client's view of them is
 * wrong, which is exactly the confusing part.
 *
 * Worth knowing when reading this: a second deploy to the same host does not actually produce a
 * second server. The container name is hardcoded to `leshiy` and the image's `boot` skips
 * initialisation whenever `server.toml` already exists on the surviving `leshiy-data` volume — so
 * the redeploy reuses the same identity and keys. One host is one server, and the vault id encodes
 * that correctly. The gap is purely that the UI never said so.
 *
 * Pure; no Android or FFI calls, so it unit-tests on the JVM.
 */
data class DeployCollision(
    val existingId: String,
    val existingLabel: String,
    /** `single` | `entry` | `middle` | `exit` — the role about to be overwritten. */
    val existingRole: String,
    /** Labels of saved servers whose `downstream` points at this record, in vault order. */
    val chainedFrom: List<String>,
) {
    /** True when replacing this record would dangle another server's chain reference. */
    val breaksCascade: Boolean get() = chainedFrom.isNotEmpty()
}

/**
 * The vault id a deploy to `host`:`sshPort` will claim.
 *
 * MUST mirror `build_params` in `crates/leshiy-mobile/src/provision.rs` verbatim, including the
 * fact that the host is compared as typed (trimmed, but not case-folded). Case-folding here would
 * warn about a collision the engine would not actually produce.
 */
fun vaultIdFor(host: String, sshPort: Int): String = "${host.trim()}-$sshPort"

/**
 * The record a deploy to `host`:`sshPort` would replace, or `null` if the id is unused.
 */
fun deployCollision(servers: List<ServerInfo>, host: String, sshPort: Int): DeployCollision? {
    if (host.isBlank()) return null
    val id = vaultIdFor(host, sshPort)
    val existing = servers.firstOrNull { it.id == id } ?: return null
    return DeployCollision(
        existingId = existing.id,
        existingLabel = existing.label,
        existingRole = existing.role,
        chainedFrom = servers.filter { it.downstream == id }.map { it.label },
    )
}
