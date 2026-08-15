using Dino.Entities;
using Gee;
using Qlite;
using Xmpp;

namespace Dino.Plugins.X3dhpq {

// ── §9.4.2: the bounded, PERSISTED checkpoint-deferral queue ─────────────────
//
// A message that overtook a checkpoint-bearing one cannot be processed yet: what
// is missing is a STATE TRANSITION, not a chain step, so the skipped-key cache
// cannot serve it. It is held here — per session, FIFO, oldest evicted first —
// and re-run through the receive pipeline immediately after any successful
// checkpoint application or DH ratchet on that session.
//
// The queue is written through to the database, because the spec requires it to
// survive a restart: a checkpoint delayed long enough for deferral to matter is
// routinely delayed across a client restart (the common case on mobile), and an
// in-memory-only queue drops exactly the messages the mechanism exists to save.
//
// The persisted unit is the original stanza's XML, because this client re-runs
// the ordinary receive pipeline on it rather than trial-decrypting against a
// ratchet snapshot. §9.4.2 leaves that an implementation choice; what it fixes
// is that the queue survives, and that ratchet state is committed exactly once
// per message — which holds here because the persisted row is only dropped once
// the pipeline has finished with it (and a re-deferral has already re-queued a
// fresh row of its own by then).

public class DeferredPairwiseMessage : Object {
    // deferred_pairwise_message.id; 0 when the entry could not be persisted.
    public int64 row_id { get; set; default = 0; }
    // The message's server_id or stanza_id; "" when it has neither. Only ever
    // used to suppress duplicates.
    public string dedup_key { get; set; default = ""; }
    // StanzaNode.to_xml() of the received <message/>, i.e. everything a re-run of
    // the receive pipeline needs. Never contains plaintext: the payload inside is
    // the ciphertext exactly as it arrived.
    public string stanza_xml { get; set; default = ""; }

    // Populated for a live deferral, and rebuilt from stanza_xml by the manager
    // for an entry restored from disk. An entry that has not (yet) been rebuilt
    // cannot be dispatched.
    public Entities.Message? message { get; set; default = null; }
    public Xmpp.MessageStanza? stanza { get; set; default = null; }
    public Conversation? conversation { get; set; default = null; }

    public bool is_runnable() {
        return message != null && stanza != null && conversation != null;
    }
}

// Runs one entry back through the receive path. It is allowed to throw: a
// failure on one entry must never cost the queue the entries behind it.
public delegate void DeferredDispatchFunc(DeferredPairwiseMessage entry) throws GLib.Error;

public class DeferralQueue : Object {
    // §9.4.2 RECOMMENDED cap: 64 messages per session, oldest evicted first.
    public const int MAX_PER_SESSION = 64;

    private Database? db;
    private HashMap<string, Gee.ArrayList<DeferredPairwiseMessage>> queues =
        new HashMap<string, Gee.ArrayList<DeferredPairwiseMessage>>();
    // Sessions already hydrated from disk in this process. After that the
    // in-memory queue is authoritative (enqueue writes through), so neither
    // restore() nor has_pending() needs to touch the database again.
    private Gee.Set<string> restored_keys = new Gee.HashSet<string>();

    // db may be null in tests that only exercise the in-memory semantics.
    public DeferralQueue(Database? db) {
        this.db = db;
    }

    // Keyed exactly as the pairwise session store is: (account, sender jid,
    // device id).
    public static string session_key(Account account, string sender_jid, int device_id) {
        return "%d/%s/%d".printf(account.id, sender_jid, device_id);
    }

    private Gee.ArrayList<DeferredPairwiseMessage> ensure_queue(string key) {
        Gee.ArrayList<DeferredPairwiseMessage>? q = queues.has_key(key) ? queues.get(key) : null;
        if (q == null) {
            q = new Gee.ArrayList<DeferredPairwiseMessage>();
            queues.set(key, q);
        }
        return q;
    }

    // Append one live deferral. Duplicates (same non-empty dedup key) are
    // dropped, the cap is enforced oldest-first, and the entry is written
    // through to the database so a restart does not lose it.
    public void enqueue(Account account, string sender_jid, int device_id, DeferredPairwiseMessage entry) {
        string key = session_key(account, sender_jid, device_id);
        Gee.ArrayList<DeferredPairwiseMessage> q = ensure_queue(key);
        if (entry.dedup_key != "") {
            foreach (DeferredPairwiseMessage p in q) {
                if (p.dedup_key == entry.dedup_key) return;
            }
        }
        while (q.size >= MAX_PER_SESSION) {
            DeferredPairwiseMessage evicted = q.remove_at(0);   // oldest evicted first
            forget(evicted);
        }
        q.add(entry);
        if (db != null && entry.stanza_xml != "") {
            entry.row_id = ((!) db).store_deferred_pairwise_message(account, sender_jid, device_id,
                entry.dedup_key, entry.stanza_xml, MAX_PER_SESSION);
        }
    }

    // True if anything is pending for this session, in memory OR on disk. The
    // disk half is what lets a checkpoint arriving after a restart find the
    // queue at all.
    public bool has_pending(Account account, string sender_jid, int device_id) {
        string key = session_key(account, sender_jid, device_id);
        if (queues.has_key(key) && queues.get(key).size > 0) return true;
        if (restored_keys.contains(key)) return false;
        return db != null && ((!) db).has_deferred_pairwise_messages(account, sender_jid, device_id);
    }

    public int size(Account account, string sender_jid, int device_id) {
        string key = session_key(account, sender_jid, device_id);
        return queues.has_key(key) ? queues.get(key).size : 0;
    }

    // Rebuild the in-memory queue for one session from the persisted rows, once
    // per process. It is NOT enough to do this only while memory is empty: a
    // deferral arriving before the first drain would otherwise hide every row
    // written by the previous run. So the queue is rebuilt from the rows in id
    // (= FIFO) order, reusing the live objects — the ones that already carry a
    // parsed Message/Conversation — wherever a row is theirs.
    public Gee.List<DeferredPairwiseMessage> restore(Account account, string sender_jid, int device_id) {
        string key = session_key(account, sender_jid, device_id);
        Gee.ArrayList<DeferredPairwiseMessage> q = ensure_queue(key);
        if (db == null || restored_keys.contains(key)) return q;
        restored_keys.add(key);

        Gee.HashMap<string, DeferredPairwiseMessage> live_by_row =
            new Gee.HashMap<string, DeferredPairwiseMessage>();
        Gee.Set<string> live_dedups = new Gee.HashSet<string>();
        foreach (DeferredPairwiseMessage e in q) {
            if (e.row_id <= 0) continue;
            live_by_row.set(e.row_id.to_string(), e);
            if (e.dedup_key != "") live_dedups.add(e.dedup_key);
        }

        Gee.ArrayList<DeferredPairwiseMessage> rebuilt = new Gee.ArrayList<DeferredPairwiseMessage>();
        Gee.Set<string> seen = new Gee.HashSet<string>();
        foreach (Database.DeferredPairwiseRecord rec in
                ((!) db).get_deferred_pairwise_messages(account, sender_jid, device_id)) {
            DeferredPairwiseMessage? live = live_by_row.get(rec.id.to_string());
            if (live == null && rec.dedup_key != "" && live_dedups.contains(rec.dedup_key)) {
                // The same message, deferred again in this run: the live copy is
                // already parsed and supersedes the stored one.
                ((!) db).delete_deferred_pairwise_message(rec.id);
                continue;
            }
            // A crash between "dispatch re-deferred it" and "drop the old row"
            // can leave two rows sharing a dedup key. Collapse them here, the
            // same way enqueue() would have.
            if (rec.dedup_key != "" && !seen.add(rec.dedup_key)) {
                ((!) db).delete_deferred_pairwise_message(rec.id);
                continue;
            }
            if (live != null) {
                rebuilt.add((!) live);
                continue;
            }
            DeferredPairwiseMessage entry = new DeferredPairwiseMessage();
            entry.row_id = rec.id;
            entry.dedup_key = rec.dedup_key;
            entry.stanza_xml = rec.stanza_xml;
            rebuilt.add(entry);
        }
        // Entries that never reached the database (serialising the stanza failed)
        // are still owed a re-run; they sort after the persisted ones, which is
        // where they already were.
        foreach (DeferredPairwiseMessage e in q) {
            if (e.row_id <= 0) rebuilt.add(e);
        }
        q.clear();
        q.add_all(rebuilt);
        return q;
    }

    public Gee.List<DeferredPairwiseMessage> entries(Account account, string sender_jid, int device_id) {
        return ensure_queue(session_key(account, sender_jid, device_id));
    }

    // Drop one entry's persisted row. Called once the pipeline is done with the
    // entry — not when it is handed to the pipeline — so a crash mid-pipeline
    // leaves the message queued rather than losing it.
    public void forget(DeferredPairwiseMessage entry) {
        if (db == null || entry.row_id <= 0) return;
        ((!) db).delete_deferred_pairwise_message(entry.row_id);
        entry.row_id = 0;
    }

    public void discard(DeferredPairwiseMessage entry, Account account, string sender_jid, int device_id) {
        ensure_queue(session_key(account, sender_jid, device_id)).remove(entry);
        forget(entry);
    }

    // Re-attempt every entry for one session.
    //
    // Entries are popped ONE AT A TIME, so a dispatch that throws part-way
    // through cannot take the entries behind it with it — they are still in the
    // live queue, and their rows are still on disk. The entry that threw is put
    // back at the tail rather than dropped, because a dispatch failure is not
    // evidence the message is undecryptable. The loop is bounded by the queue
    // size on entry so a re-deferral appended during the drain waits for the
    // next transition instead of spinning here.
    public void drain(Account account, string sender_jid, int device_id, DeferredDispatchFunc dispatch) {
        string key = session_key(account, sender_jid, device_id);
        if (!queues.has_key(key)) return;
        Gee.ArrayList<DeferredPairwiseMessage> q = queues.get(key);
        Gee.ArrayList<DeferredPairwiseMessage> failed = new Gee.ArrayList<DeferredPairwiseMessage>();
        int budget = q.size;
        while (q.size > 0 && budget > 0) {
            budget--;
            DeferredPairwiseMessage entry = q.remove_at(0);
            try {
                dispatch(entry);
            } catch (GLib.Error e) {
                // No stanza, no jid, no key material — just the failure reason.
                warning("x3dhpq: deferred re-run failed, keeping the entry queued: %s", e.message);
                failed.add(entry);
            }
        }
        foreach (DeferredPairwiseMessage entry in failed) {
            q.add(entry);
        }
        if (q.size == 0) queues.unset(key);
    }
}

}
