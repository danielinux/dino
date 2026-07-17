namespace Dino.Plugins.X3dhpq.Protocol {

public const string NS_X3DHPQ = "urn:xmppqr:x3dhpq:0";
public const string NS_DEVICELIST = "urn:xmppqr:x3dhpq:devicelist:0";
public const string NS_BUNDLE = "urn:xmppqr:x3dhpq:bundle:0";
public const string NS_ENVELOPE = "urn:xmppqr:x3dhpq:envelope:0";
public const string NS_PAIR = "urn:xmppqr:x3dhpq:pair:0";
public const string NS_RECOVERY = "urn:xmppqr:x3dhpq:recovery:0";
public const string NS_GROUP = "urn:xmppqr:x3dhpq:group:0";
// §11.8: sealed device-state tracker + queued enrollment request (persisted on
// the existing NS_PAIR node, see StreamModule.publish_enrollment_request).
public const string NS_DEVTRACKER = "urn:xmppqr:x3dhpq:devtracker:0";
// Trust Manifest (Phase 1): AIK-rooted delegation DAG of authorized devices,
// published as a single signed blob. See trust_manifest.vala.
public const string NS_TRUSTMANIFEST = "urn:xmppqr:x3dhpq:trustmanifest:0";

public const string PAYLOAD_TYPE_SENDER_CHAIN = "sender-chain";
// A group-sync payload bundles the sender-chain announcement with the current
// membership journal, delivered over the pairwise channel (the epoch-rotation
// rekey already fans out to every member device). This makes journal delivery
// independent of MUC MAM. Decrypted plaintext layout (all integers big-endian):
//   uint16 version(=1) | uint32 ann_len | <ann bytes> | uint32 n_entries |
//   { uint32 entry_len | <MemberAuditEntry.marshal()> } * n_entries
public const string PAYLOAD_TYPE_GROUP_SYNC = "group-sync";
// A session re-negotiation heartbeat: an (otherwise empty) message carrying a
// fresh prekey so the recipient re-establishes the pairwise session. Sent when a
// message fails to decrypt (stale/mismatched session, e.g. after a peer reset
// left our cached bundle stale) so the key is renegotiated instead of the
// conversation staying wedged. Carries no visible body.
public const string PAYLOAD_TYPE_REKEY = "rekey";

public string[] get_disco_features() {
    return {
        NS_X3DHPQ,
        NS_DEVICELIST,
        NS_BUNDLE,
        NS_ENVELOPE,
        NS_PAIR,
        NS_RECOVERY,
        NS_GROUP,
        NS_DEVTRACKER,
        NS_TRUSTMANIFEST,
    };
}

}
