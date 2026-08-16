namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

/* §13.1a.0 step 5 — the RESOLVER counterpart to the shared corpus's journal-fold
 * `device_auth` vectors.
 *
 * The corpus cannot cover this. In conformance/v2/journal-fold.json `device_auth` is a
 * harness INPUT: a vector states the already-resolved status ("ALICE_FP/43":
 * "UNRESOLVED") and pins what the fold does GIVEN it. Which status a receiver's own
 * manifest bookkeeping PRODUCES for a given (tombstone, history, ever-authorized) state
 * is precisely what those vectors leave unpinned — and it is where the two reference
 * clients silently diverged: for "we hold manifest history for this account and this
 * device id has never appeared in it", Dino answered REJECTED and PQonversations
 * answered UNRESOLVED, while both passed every corpus vector. In the field that folds
 * different member sets from identical entries and the two fold_hashes never
 * reconverge, which is the exact failure the corpus exists to prevent.
 *
 * So each test below is named after the corpus vector whose INPUT it is now pinning the
 * production of.
 */
class IssuerStatusTest : Gee.TestCase {

    public IssuerStatusTest() {
        base("IssuerStatus");
        add_test("no_manifest_at_all_is_unresolved", test_no_manifest_at_all);
        add_test("never_in_any_accepted_manifest_is_unresolved", test_never_in_any_accepted_manifest);
        add_test("tombstoned_device_is_rejected", test_tombstoned_device);
        add_test("device_present_is_authorized", test_device_present);
        add_test("owner_unnameable_is_unresolved", test_owner_unnameable);
        add_test("tombstone_beats_ever_authorized", test_tombstone_beats_ever_authorized);
        add_test("tombstone_beats_missing_history", test_tombstone_beats_missing_history);
        add_test("never_in_any_accepted_manifest_triggers_fetch", test_never_seen_triggers_fetch);
        add_test("no_manifest_at_all_triggers_fetch", test_no_manifest_triggers_fetch);
        add_test("decided_verdicts_trigger_no_fetch", test_decided_verdicts_trigger_no_fetch);
    }

    /* Corpus vector `issuer-unresolved-is-quarantined-not-dropped`: this receiver holds
     * no accepted manifest for the author's account AT ALL. Undecidable, not refused. */
    private void test_no_manifest_at_all() {
        var st = classify_issuer(true, false, false, false);
        fail_if_not(st == IssuerAuthStatus.UNRESOLVED,
            "no manifest held for the account must be UNRESOLVED (quarantine), not a refusal");
    }

    /* Corpus vector `issuer-never-in-any-accepted-manifest-rejected`: manifest history
     * IS held and the device id has never appeared in it — the fresh-device-id attack
     * shape. Still UNRESOLVED, NOT rejected: the ever-authorized set is only as complete
     * as the manifests this receiver folded, so a late joiner or one that missed a
     * version legitimately lacks the authorizing entry its peers folded. Quarantine
     * blocks the attack just as completely (never folded until authorization is
     * positively established) while staying self-healing when the gap was local. */
    private void test_never_in_any_accepted_manifest() {
        var st = classify_issuer(true, false, true, false);
        fail_if_not(st == IssuerAuthStatus.UNRESOLVED,
            "manifest held but device never seen must be UNRESOLVED (quarantine): REJECTED here"
            + " permanently skips an entry our peers folded and the fold_hashes never reconverge");
    }

    /* Corpus vector `entry-from-tombstoned-device-rejected`: the one DEFINITIVE
     * negative. No manifest we could later fetch undoes a tombstone, so there is nothing
     * to wait for — this must stay a hard refusal and must NOT be softened to
     * quarantine along with the case above. */
    private void test_tombstoned_device() {
        var st = classify_issuer(true, true, true, false);
        fail_if_not(st == IssuerAuthStatus.REJECTED,
            "a positive revocation tombstone must be REJECTED, never quarantined");
    }

    private void test_device_present() {
        var st = classify_issuer(true, false, true, true);
        fail_if_not(st == IssuerAuthStatus.AUTHORIZED,
            "a device present in an accepted manifest fold and not tombstoned must be AUTHORIZED");
    }

    /* We cannot even name the account behind the signer fingerprint, so we certainly
     * hold no manifest for it. Same answer as "no manifest at all". */
    private void test_owner_unnameable() {
        var st = classify_issuer(false, false, false, false);
        fail_if_not(st == IssuerAuthStatus.UNRESOLVED,
            "an unnameable signer account must be UNRESOLVED (quarantine)");
    }

    /* Check ORDER, not just the four states: the tombstone test runs before the
     * ever-authorized test, so revoking a device that IS in our ever-authorized set
     * still refuses it. Getting this backwards would make revocation a no-op for every
     * device that was ever legitimately authorized — i.e. all of them. */
    private void test_tombstone_beats_ever_authorized() {
        var st = classify_issuer(true, true, true, true);
        fail_if_not(st == IssuerAuthStatus.REJECTED,
            "a tombstone must override membership of the ever-authorized set");
    }

    /* Also order: tombstone BEFORE the manifest-history test, matching PQonversations.
     * Holding a tombstone but no folded history is reachable — a revocation can be
     * recorded by a path other than a peer manifest fold — and it is still a positive
     * result, so it refuses rather than quarantines. Testing the tombstone only in the
     * history-held state would leave this arm free to diverge across clients again. */
    private void test_tombstone_beats_missing_history() {
        var st = classify_issuer(true, true, false, false);
        fail_if_not(st == IssuerAuthStatus.REJECTED,
            "a tombstone must be answered before the manifest-history test, not after it");
    }

    /* The other half of the fix: quarantine is only honest if it RETRIES. The
     * history-held/never-seen shape must drive a manifest fetch exactly as the
     * no-manifest shape does — wiring the fetch to the no-manifest case alone leaves
     * this one held forever, which is dropping it with extra steps. Composed with
     * test_never_in_any_accepted_manifest above, this pins the whole path:
     * never-seen -> UNRESOLVED -> fetch. */
    private void test_never_seen_triggers_fetch() {
        var st = classify_issuer(true, false, true, false);
        fail_if_not(issuer_status_wants_manifest_fetch(st, true),
            "manifest held but device never seen must schedule a manifest fetch, or it stays"
            + " quarantined forever");
    }

    private void test_no_manifest_triggers_fetch() {
        var st = classify_issuer(true, false, false, false);
        fail_if_not(issuer_status_wants_manifest_fetch(st, true),
            "no manifest held must schedule a manifest fetch");
    }

    /* A decided verdict has nothing to wait for: no manifest undoes a tombstone, and an
     * authorized issuer is already folded. Fetching on either would spin. */
    private void test_decided_verdicts_trigger_no_fetch() {
        fail_if(issuer_status_wants_manifest_fetch(IssuerAuthStatus.REJECTED, true),
            "a tombstoned issuer must not schedule a fetch");
        fail_if(issuer_status_wants_manifest_fetch(IssuerAuthStatus.AUTHORIZED, true),
            "an authorized issuer must not schedule a fetch");
        fail_if(issuer_status_wants_manifest_fetch(IssuerAuthStatus.UNRESOLVED, false),
            "an account we cannot name has no node to fetch from");
    }
}

}
