/* The single decision point for an inbound <x3dhpq-group> message.
 *
 * WHY THIS FILE EXISTS. The receive-side checks used to be split across two layers:
 * device authorization (§13.5b) and the drop-every-chain side effect lived in
 * Manager, while the removed-member and chain-selection checks lived inside
 * GroupSession.decrypt_with_heads(). Several of those checks carry SIDE EFFECTS, so
 * the ORDER they fire in is observable — an implementation that decides on the epoch
 * before device authorization reaches the same verdict while failing to drop the
 * revoked device's chains, and nothing in either layer's own tests can see that. The
 * shared conformance corpus (§19.2.0, conformance/v2/group-accept.json) pins that
 * order, which is only testable if there is ONE place the whole sequence runs.
 * GroupSession.receive() is that place; this file gives it its vocabulary.
 *
 * Device authorization is deliberately an INPUT, not a lookup: resolving it needs
 * the Trust Manifest fold, the tombstone set and the account database, none of which
 * belong in the protocol layer — and making it a parameter is what lets the corpus
 * drive the ordering directly.
 */

namespace Dino.Plugins.X3dhpq.Protocol {

/* §13.5b step 1 input. Three-valued on purpose: "we hold no manifest for this
 * account" is NOT the same as "the manifest says no". Both reject — this path does
 * not fail open — but only the first asks for a manifest fetch. */
public enum GroupDeviceAuthorization {
    AUTHORIZED,
    NOT_AUTHORIZED,
    NO_MANIFEST,
}

/* The verdicts of conformance/v2/group-accept.json, one-for-one.
 *
 * v1's REJECT_STALE_EPOCH is gone and MUST NOT come back (§13.7a, OQ-12 resolved).
 * The global comparison it encoded refused a lagging peer's messages permanently —
 * our fold epoch only grows, so it never descends to meet them — while every threat
 * it appeared to cover is caught by REJECT_REMOVED_MEMBER (at any epoch),
 * REJECT_UNAUTHORIZED_DEVICE, the (epoch, epoch_id) chain selection and the §13.7
 * chain-index rules, none of which depend on two peers' folds being in step. */
public enum GroupDecision {
    ACCEPT,
    REJECT_UNAUTHORIZED_DEVICE,
    REJECT_REMOVED_MEMBER,
    REJECT_EPOCH_ID_MISMATCH,
    DEFER_NO_CHAIN,
    REJECT_SIGNATURE,
    REJECT_AEAD,
    /* §13.7: the requested chain index cannot be served — already ratcheted past
     * (ErrSenderChainPast) or beyond the skipped-key budget
     * (ErrSenderChainTooManySkipped). Deliberately NOT folded into REJECT_AEAD: the
     * tag is never evaluated on this path, and the past-index case is the routine
     * DUPLICATE delivery (a replayed archive message), not a failure at all. A caller
     * that saw REJECT_AEAD here would be told "authentication failed" about a message
     * it already displayed correctly. */
    REJECT_CHAIN_INDEX;

    // Corpus spelling. Kept next to the enum so the two cannot drift apart.
    public string to_name() {
        switch (this) {
            case ACCEPT:                     return "ACCEPT";
            case REJECT_UNAUTHORIZED_DEVICE: return "REJECT_UNAUTHORIZED_DEVICE";
            case REJECT_REMOVED_MEMBER:      return "REJECT_REMOVED_MEMBER";
            case REJECT_EPOCH_ID_MISMATCH:   return "REJECT_EPOCH_ID_MISMATCH";
            case DEFER_NO_CHAIN:             return "DEFER_NO_CHAIN";
            case REJECT_SIGNATURE:           return "REJECT_SIGNATURE";
            case REJECT_AEAD:                return "REJECT_AEAD";
            case REJECT_CHAIN_INDEX:         return "REJECT_CHAIN_INDEX";
            default:                         return "UNKNOWN";
        }
    }
}

/* What the evaluator decided, plus the side effects the CALLER must carry out.
 *
 * The flags are returned rather than performed because their scope is wider than one
 * session: dropping a revoked device's chains spans every room (§13.5b), stashing
 * belongs to the message pipeline, and fetching a manifest is network I/O. The
 * evaluator stays a pure function of (session state, header, authorization) with
 * exactly one in-session mutation — the recv-chain ratchet, and only on ACCEPT.
 */
public class GroupReceiveOutcome : Object {
    public GroupDecision decision { get; private set; }
    // Set only when decision == ACCEPT.
    public uint8[]? plaintext { get; private set; default = null; }

    /* §13.5b: delete every recv chain held for this (aik_fp, device_id) in EVERY
     * room. Rejecting the message is not enough on its own — a device revoked
     * mid-epoch already holds the chain key and would keep being served by state we
     * installed. */
    public bool drop_recv_chains_all_rooms { get; private set; default = false; }
    // §13.5b: no manifest held for the sender's account, so ask for one.
    public bool fetch_manifest { get; private set; default = false; }
    /* §13.4a.3: hold the ciphertext rather than surfacing a decryption failure. MAM
     * de-duplicates, so a discarded message is gone for good. */
    public bool stash_for_retry { get; private set; default = false; }
    // Observable on ACCEPT: the recv chain moved forward exactly once.
    public bool recv_chain_advanced { get; private set; default = false; }

    // Non-sensitive diagnostic text. Never carries key material or plaintext.
    public string detail { get; private set; default = ""; }

    public GroupReceiveOutcome(GroupDecision decision, string detail = "") {
        this.decision = decision;
        this.detail = detail;
    }

    public GroupReceiveOutcome.accepted(uint8[] plaintext) {
        this.decision = GroupDecision.ACCEPT;
        this.plaintext = plaintext;
        this.recv_chain_advanced = true;
    }

    public GroupReceiveOutcome.unauthorized_device(bool fetch_manifest, string detail) {
        this.decision = GroupDecision.REJECT_UNAUTHORIZED_DEVICE;
        this.drop_recv_chains_all_rooms = true;
        this.fetch_manifest = fetch_manifest;
        this.detail = detail;
    }

    public GroupReceiveOutcome.stashed(GroupDecision decision, string detail) {
        this.decision = decision;
        this.stash_for_retry = true;
        this.detail = detail;
    }
}

}
