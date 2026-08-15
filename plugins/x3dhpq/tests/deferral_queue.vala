using Dino.Entities;
using Dino.Plugins.X3dhpq;
using Xmpp;

namespace X3dhpq.Test {

// §9.4.2, "Deferral queue": the bounded per-session FIFO MUST be persisted
// alongside the session state, capped at 64 with oldest-first eviction, and a
// drain must not be able to lose entries part-way through.
class DeferralQueueTest : Gee.TestCase {
    private string db_path;
    private const string PEER = "bob@example.test";
    private const int DEVICE = 3;

    public DeferralQueueTest() {
        base("DeferralQueue");
        add_test("queue_survives_restart", test_queue_survives_restart);
        add_test("restart_with_new_deferral_before_drain", test_restart_with_new_deferral_before_drain);
        add_test("eviction_caps_at_64", test_eviction_caps_at_64);
        add_test("drain_failure_keeps_remaining", test_drain_failure_keeps_remaining);
    }

    public override void set_up() {
        db_path = GLib.Path.build_filename(GLib.Environment.get_tmp_dir(),
            "x3dhpq-deferral-%u.db".printf(Random.next_int()));
    }

    public override void tear_down() {
        FileUtils.unlink(db_path);
        FileUtils.unlink(db_path + "-shm");
        FileUtils.unlink(db_path + "-wal");
    }

    private Account account(int id = 91) throws GLib.Error {
        Account a = new Account(new Jid("alice@example.test"), "pw");
        a.id = id;
        return a;
    }

    private DeferredPairwiseMessage entry(string dedup) {
        DeferredPairwiseMessage e = new DeferredPairwiseMessage();
        e.dedup_key = dedup;
        e.stanza_xml = "<message id='%s'><x3dhpq xmlns='urn:xmppqr:x3dhpq:envelope:0'/></message>".printf(dedup);
        return e;
    }

    // A message deferred before a restart must still be there after it, in FIFO
    // order, with the exact stanza it arrived as, and scoped to its own
    // (account, jid, device) triple.
    private void test_queue_survives_restart() {
        try {
            Account a = account();
            {
                Database db = new Database(db_path);
                DeferralQueue q = new DeferralQueue(db);
                q.enqueue(a, PEER, DEVICE, entry("m1"));
                q.enqueue(a, PEER, DEVICE, entry("m2"));
                // A duplicate of an already-queued message is not queued twice.
                q.enqueue(a, PEER, DEVICE, entry("m2"));
                // A different device on the same peer is a different session.
                q.enqueue(a, PEER, DEVICE + 1, entry("other"));
                fail_if_not_eq_int(q.size(a, PEER, DEVICE), 2, "two entries before the restart");
            }

            // ── restart: nothing whatsoever is carried over in memory ──
            Database restarted = new Database(db_path);
            DeferralQueue restored_queue = new DeferralQueue(restarted);

            fail_if_not(restored_queue.has_pending(a, PEER, DEVICE),
                "a checkpoint arriving after a restart must still find the deferral queue");
            Gee.List<DeferredPairwiseMessage> restored = restored_queue.restore(a, PEER, DEVICE);
            if (fail_if_not_eq_int(restored.size, 2, "both deferred messages must survive the restart")) return;
            fail_if_not_eq_str(restored.get(0).dedup_key, "m1", "FIFO order must survive the restart");
            fail_if_not_eq_str(restored.get(1).dedup_key, "m2", "FIFO order must survive the restart");
            fail_if_not_eq_str(restored.get(0).stanza_xml, entry("m1").stanza_xml,
                "the persisted stanza must come back byte-for-byte");
            fail_if_not(restored.get(0).row_id > 0, "a restored entry must carry its row handle");

            // Scoping is exactly pairwise_session's: account, bare jid, device id.
            fail_if_not_eq_int(restored_queue.restore(a, PEER, DEVICE + 1).size, 1,
                "the sibling device's queue must be separate, not merged");
            fail_if(restored_queue.has_pending(a, "carol@example.test", DEVICE),
                "another peer must not see this queue");
            fail_if(restored_queue.has_pending(account(92), PEER, DEVICE),
                "another account must not see this queue");

            // Dropping one entry once the pipeline is done with it clears exactly
            // that row, and only that row.
            restored_queue.forget(restored.get(0));
            fail_if_not_eq_int(restarted.get_deferred_pairwise_messages(a, PEER, DEVICE).size, 1,
                "forget() must drop exactly one row");
            fail_if_not_eq_str(restarted.get_deferred_pairwise_messages(a, PEER, DEVICE).get(0).dedup_key, "m2",
                "forget() must drop the entry it was given");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // A deferral arriving after the restart but BEFORE the first drain must not
    // hide the entries the previous run left on disk.
    private void test_restart_with_new_deferral_before_drain() {
        try {
            Account a = account();
            {
                Database db = new Database(db_path);
                DeferralQueue q = new DeferralQueue(db);
                q.enqueue(a, PEER, DEVICE, entry("m1"));
                q.enqueue(a, PEER, DEVICE, entry("m2"));
            }

            Database restarted = new Database(db_path);
            DeferralQueue q2 = new DeferralQueue(restarted);
            q2.enqueue(a, PEER, DEVICE, entry("m3"));
            fail_if_not_eq_int(q2.size(a, PEER, DEVICE), 1, "only the fresh deferral is in memory yet");

            Gee.List<DeferredPairwiseMessage> all = q2.restore(a, PEER, DEVICE);
            if (fail_if_not_eq_int(all.size, 3,
                    "a fresh deferral must not hide the entries the previous run persisted")) return;
            fail_if_not_eq_str(all.get(0).dedup_key, "m1", "FIFO order across the restart");
            fail_if_not_eq_str(all.get(1).dedup_key, "m2", "FIFO order across the restart");
            fail_if_not_eq_str(all.get(2).dedup_key, "m3", "the fresh deferral sorts last");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // §9.4.2 RECOMMENDED cap of 64 per session, oldest evicted first — in memory
    // and on disk alike, so a restart cannot resurrect an evicted entry.
    private void test_eviction_caps_at_64() {
        try {
            Account a = account();
            Database db = new Database(db_path);
            DeferralQueue q = new DeferralQueue(db);
            for (int i = 0; i < 70; i++) {
                q.enqueue(a, PEER, DEVICE, entry("m%d".printf(i)));
            }
            if (fail_if_not_eq_int(q.size(a, PEER, DEVICE), 64, "the in-memory queue must cap at 64")) return;
            fail_if_not_eq_str(q.entries(a, PEER, DEVICE).get(0).dedup_key, "m6",
                "eviction must be oldest-first");
            fail_if_not_eq_str(q.entries(a, PEER, DEVICE).get(63).dedup_key, "m69",
                "the newest entry must be kept");

            Gee.List<Database.DeferredPairwiseRecord> rows =
                db.get_deferred_pairwise_messages(a, PEER, DEVICE);
            if (fail_if_not_eq_int(rows.size, 64, "the persisted queue must cap at 64 too")) return;
            fail_if_not_eq_str(rows.get(0).dedup_key, "m6",
                "an evicted entry must not survive on disk");
            fail_if_not_eq_str(rows.get(63).dedup_key, "m69", "the newest entry must be persisted");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // A drain that throws part-way must not take the entries behind it with it:
    // every entry is still either dispatched or still queued (and still on disk).
    private void test_drain_failure_keeps_remaining() {
        try {
            Account a = account();
            Database db = new Database(db_path);
            DeferralQueue q = new DeferralQueue(db);
            q.enqueue(a, PEER, DEVICE, entry("m1"));
            q.enqueue(a, PEER, DEVICE, entry("m2"));
            q.enqueue(a, PEER, DEVICE, entry("m3"));

            Gee.List<string> dispatched = new Gee.ArrayList<string>();
            // The queue logs the failure it swallows; g_test makes warnings fatal.
            GLib.Test.expect_message("x3dhpq", LogLevelFlags.LEVEL_WARNING, "*deferred re-run failed*");
            q.drain(a, PEER, DEVICE, (e) => {
                dispatched.add(e.dedup_key);
                if (e.dedup_key == "m2") {
                    throw new IOError.FAILED("simulated pipeline failure");
                }
                // What the manager does once the pipeline is done with an entry.
                q.forget(e);
            });
            GLib.Test.assert_expected_messages();

            if (fail_if_not_eq_int(dispatched.size, 3,
                    "a throw on one entry must not stop the drain: every entry must be attempted")) return;
            fail_if_not_eq_str(dispatched.get(2), "m3",
                "the entry behind the failing one must still be attempted");
            if (fail_if_not_eq_int(q.size(a, PEER, DEVICE), 1,
                    "the entry that threw must stay queued, not be dropped")) return;
            fail_if_not_eq_str(q.entries(a, PEER, DEVICE).get(0).dedup_key, "m2",
                "the entry that threw is the one that must stay");

            Gee.List<Database.DeferredPairwiseRecord> rows =
                db.get_deferred_pairwise_messages(a, PEER, DEVICE);
            if (fail_if_not_eq_int(rows.size, 1, "only the entry that threw may still hold a row")) return;
            fail_if_not_eq_str(rows.get(0).dedup_key, "m2", "the surviving row must be the failed entry");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }
}

}
