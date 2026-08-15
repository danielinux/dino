using Dino.Entities;
using Gee;
using Qlite;
using Xmpp;
using Xmpp.Xep;

namespace Dino.Plugins.X3dhpq {

public class Manager : Object, global::Dino.Plugins.X3dhpqGroupManager {
    private Dino.Application app;
    private Database db;
    private HashMap<Entities.Message, Conversation> pending_messages = new HashMap<Entities.Message, Conversation>(Entities.Message.hash_func, Entities.Message.equals_func);

    // WS2: per-room multi-admin membership DAG (v2). Hydrated lazily from the
    // persisted raw-entry table on first use, then kept hot in memory. A room is
    // "v2-active" once its DAG holds at least one entry (a v2 genesis or a
    // v1->v2 bridge Snapshot). Keyed by "<account_id>\0<room_bare_jid>".
    private HashMap<string, Protocol.MembershipDag> dags = new HashMap<string, Protocol.MembershipDag>();

    private static string dag_key(Account account, string room_jid_str) {
        return "%d %s".printf(account.id, room_jid_str);
    }
    private Protocol.MembershipDag? hydrate_dag(Account account, string room_jid_str, bool create_empty) {
        string k = dag_key(account, room_jid_str);
        Protocol.MembershipDag? d = dags.get(k);
        if (d != null) return d;
        if (!create_empty && !db.has_membership_dag_entries(account, room_jid_str)) return null;
        d = new Protocol.MembershipDag();
        foreach (Bytes b in db.list_membership_dag_entry_blobs(account, room_jid_str)) {
            d.ingest(bytes_to_uint8_array(b));
        }
        dags.set(k, d);
        return d;
    }
    private Protocol.MembershipDag get_or_create_dag(Account account, string room_jid_str) {
        return (!) hydrate_dag(account, room_jid_str, true);
    }
    private Protocol.MembershipDag? get_dag(Account account, string room_jid_str) {
        return hydrate_dag(account, room_jid_str, false);
    }
    // A room has switched to the v2 multi-admin engine once we hold any v2 entry.
    private bool is_v2_active(Account account, string room_jid_str) {
        Protocol.MembershipDag? d = get_dag(account, room_jid_str);
        return d != null && d.size > 0;
    }

    private bool ingest_and_store_v2(Account account, string room_jid_str, uint8[] entry_bytes) {
        Protocol.MembershipDag dag = get_or_create_dag(account, room_jid_str);
        bool inserted = dag.ingest(entry_bytes);
        if (inserted) {
            db.store_membership_dag_entry_blob(account, room_jid_str, entry_bytes);
        }
        return inserted;
    }

    public Manager(Dino.Application app, Database db) {
        this.app = app;
        this.db = db;

        app.stream_interactor.account_added.connect(on_account_added);
        app.stream_interactor.stream_negotiated.connect(on_stream_negotiated);
        app.stream_interactor.get_module(MessageProcessor.IDENTITY).pre_message_send.connect(on_pre_message_send);
        app.stream_interactor.get_module(MessageProcessor.IDENTITY).received_pipeline.connect(new DecryptMessageListener(this));
        app.stream_interactor.get_module(MucManager.IDENTITY).room_info_updated.connect(on_room_info_updated);
        app.stream_interactor.get_module(MucManager.IDENTITY).private_room_occupant_updated.connect(on_private_room_occupant_updated);
    }

    // Subscribe to the room's X3DHPQ membership-journal PEP node when MUC info
    // is settled. A room-hosted pubsub node is not the account's own PEP
    // service, so Entity Caps +notify does not cover it; a standard XEP-0060
    // explicit <subscribe> IQ is used instead. Works against stock servers.
    private void on_room_info_updated(Account account, Jid muc_jid) {
        XmppStream? stream = app.stream_interactor.get_stream(account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (stream == null || module == null) {
            return;
        }
        // WS1: the membership journal now rides the MUC groupchat channel and is
        // archived by the room (MAM), not a room-JID PubSub node. On join we force
        // a MUC MAM catch-up so a late joiner replays every <journal-entry> the
        // owner/admins published before we arrived; each replayed groupchat message
        // flows through the received pipeline into try_handle_journal_entry.
        trigger_group_mam_catchup(account, muc_jid.bare_jid.to_string());
        // We just (re)joined — push our own sender chain so existing members
        // refresh our recv chain, and (via the checkpoint) so anyone can decrypt
        // our recent history without waiting for our next message.
        maybe_reannounce_group(account, muc_jid);
    }

    // A member's presence appeared/refreshed in a private channel. If it isn't
    // us, re-broadcast our sender chain so a RETURNING member promptly gets our
    // current checkpoint (and can then decrypt recent history via MAM) instead of
    // waiting for our next message.
    private void on_private_room_occupant_updated(Account account, Jid room, Jid occupant) {
        if (occupant.equals_bare(account.bare_jid)) return;
        maybe_reannounce_group(account, room);
    }

    // Per-room cooldown so a join burst (many occupant updates at once) coalesces
    // into a single sender-chain re-broadcast instead of one fan-out per occupant.
    private HashMap<string, int64?> group_reannounce_at = new HashMap<string, int64?>();
    private const int64 GROUP_REANNOUNCE_COOLDOWN_US = 5 * 1000000;

    // Re-broadcast our sender chain to a private channel, rate-limited per room.
    // No-op for rooms we have no x3dhpq membership state for (not our channels).
    private void maybe_reannounce_group(Account account, Jid room) {
        string room_jid_str = room.bare_jid.to_string();
        if (!db.has_membership_journal(account, room_jid_str)
                && !db.has_membership_dag_entries(account, room_jid_str)) {
            return;
        }
        string key = "%d/%s".printf(account.id, room_jid_str);
        int64 now = get_monotonic_time();
        int64? last = group_reannounce_at.has_key(key) ? group_reannounce_at.get(key) : null;
        if (last != null && now - (!) last < GROUP_REANNOUNCE_COOLDOWN_US) {
            return;
        }
        group_reannounce_at.set(key, now);
        announce_group_to_members(account, room);
    }

    private void wipe_sessions_once(Account account) {
        try {
            string flag_dir = GLib.Path.build_filename(
                GLib.Environment.get_user_cache_dir(), "dino", "x3dhpq");
            DirUtils.create_with_parents(flag_dir, 0700);
            string flag_path = GLib.Path.build_filename(
                flag_dir, "session_wipe_v1_%d.flag".printf(account.id));
            if (FileUtils.test(flag_path, FileTest.EXISTS)) {
                return;
            }
            db.wipe_all_sessions(account);
            FileUtils.set_contents(flag_path, "done\n");
        } catch (Error e) {
            warning("x3dhpq session wipe-v1 failed: %s", e.message);
        }
    }

    // Replay every persisted journal entry into the supplied GroupSession's
    // members map without rotating the epoch. Without this, the in-memory
    // session has zero members, so accept_sender_chain rejects every
    // incoming announcement with ANNOUNCEMENT_UNKNOWN_SENDER and decrypts
    // surface as "no recv chain".
    private void rebuild_group_session_from_journal(Account account, string room_jid_str,
            Protocol.GroupSession gs) {
        // Once the room has switched to the v2 multi-admin engine, the folded
        // DagState (not the linear v1 journal) is authoritative for membership.
        if (is_v2_active(account, room_jid_str)) {
            rebuild_group_session_from_dag(account, room_jid_str, gs);
            return;
        }
        var entries = db.list_membership_journal_entries(account, room_jid_str);
        int added = 0;
        int skipped_not_found = 0;
        // Derived-epoch counter for the §13.5 SHOULD-level cross-check: genesis
        // (first entry) lands on epoch 0, every subsequent entry rotates once.
        uint32 derived_epoch = 0;
        int entry_index = 0;
        foreach (Protocol.MemberAuditEntry e in entries) {
            uint8[] aik_fp_raw;
            uint32 epoch_after;
            if (!Protocol.MemberAuditEntry.parse_member_payload(e.payload, out aik_fp_raw, out epoch_after)) {
                entry_index++;
                continue;
            }
            uint32 expected_epoch = (entry_index == 0) ? 0 : derived_epoch + 1;
            if (epoch_after != expected_epoch) {
                // SHOULD-level: log and keep going (interop robustness); the
                // replay-derived epoch is authoritative, not the wire value.
                warning("rebuild journal: epoch_after mismatch at seq=%llu: wire=%u derived=%u",
                    e.seq, epoch_after, expected_epoch);
            }
            derived_epoch = expected_epoch;
            entry_index++;
            uint8[] aik_ed;
            uint8[] aik_mldsa;
            if (!db.find_peer_account_identity_by_aik_fp(account, aik_fp_raw, out aik_ed, out aik_mldsa)) {
                // Could be ourselves (we are the owner). Build canonical AIK
                // from the local account identity if the fp matches.
                uint8[] my_ed = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_ed25519_base64));
                uint8[] my_ml = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_mldsa_base64));
                int total = 3 + my_ed.length + my_ml.length;
                uint8[] enc = new uint8[total];
                enc[0] = 0; enc[1] = 1; enc[2] = 1;
                Memory.copy((uint8*) enc + 3, my_ed, my_ed.length);
                Memory.copy((uint8*) enc + 3 + my_ed.length, my_ml, my_ml.length);
                bool is_self = false;
                try {
                    Bytes my_fp = global::X3dhpq.Crypto.blake2b160(new Bytes(enc));
                    unowned uint8[] my_fp_bytes = my_fp.get_data();
                    is_self = true;
                    for (int i = 0; i < 20; i++) {
                        if (my_fp_bytes[i] != aik_fp_raw[i]) { is_self = false; break; }
                    }
                } catch (Error err) {
                    continue;
                }
                if (!is_self) {
                    // Last resort: scan the bundle table — when dino fetched
                    // the peer's bundle (e.g., for 1:1 chat or to broadcast
                    // a sender chain), the AIK halves were stored on the
                    // bundle row. The peer_account_identity index can lag
                    // briefly when the bundle landed before the bundle
                    // handler updated peer_account_identity. Falling
                    // through here means rebuild silently drops the entry
                    // and gs ends up with zero members, which makes
                    // accept_sender_chain reject every announcement.
                    if (!find_peer_aik_in_bundles(account, aik_fp_raw, out aik_ed, out aik_mldsa)) {
                        skipped_not_found++;
                        continue;
                    }
                } else {
                    aik_ed = my_ed;
                    aik_mldsa = my_ml;
                }
            }
            // Rebuild canonical AIK pub bytes for the GroupMember.
            int total = 3 + aik_ed.length + aik_mldsa.length;
            uint8[] aik_canonical = new uint8[total];
            aik_canonical[0] = 0; aik_canonical[1] = 1; aik_canonical[2] = 1;
            Memory.copy((uint8*) aik_canonical + 3, aik_ed, aik_ed.length);
            Memory.copy((uint8*) aik_canonical + 3 + aik_ed.length, aik_mldsa, aik_mldsa.length);
            try {
                if (e.action == (uint8) Protocol.MemberAuditAction.ADD_MEMBER) {
                    Protocol.GroupMember m = new Protocol.GroupMember();
                    m.aik_pub_bytes = aik_canonical;
                    gs.add_initial_member(m);
                    added++;
                } else if (e.action == (uint8) Protocol.MemberAuditAction.REMOVE_MEMBER) {
                    string fp_hex = "";
                    StringBuilder sb = new StringBuilder();
                    foreach (uint8 b in aik_fp_raw) {
                        sb.append_printf("%02X", b);
                    }
                    fp_hex = sb.str.substring(0, 30);
                    fp_hex = @"$(fp_hex.substring(0, 5)) $(fp_hex.substring(5, 5)) $(fp_hex.substring(10, 5)) $(fp_hex.substring(15, 5)) $(fp_hex.substring(20, 5)) $(fp_hex.substring(25, 5))";
                    gs.remove_member_by_fp(fp_hex);
                }
            } catch (GLib.Error err) {
                warning("rebuild journal: failed at seq=%llu: %s", e.seq, err.message);
            }
        }
    }

    // WS2: drive the GroupSession member set from the folded v2 DagState. The
    // admin set is enforced inside the fold (signer_fp must be an admin for an
    // entry to apply). We diff the fold's member set against the session's
    // current members: additions call add_initial_member; removals call
    // remove_member_by_fp, which rotates the sender-chain epoch so a removed
    // member cannot read future group messages. The fold only includes entries
    // whose parents are all present (canonical_order), i.e. the causally-stable
    // prefix, so rotation is bound to stable state, not a movable raw index.
    // Fold a room's membership DAG under the §13.1a.1 owner pin, pinning the owner the
    // first time a fold produces one. Every DAG fold MUST go through here: a fold that
    // re-derives the genesis from the current entry set is trust-on-first-FOLD, and the
    // AIK resolver is seeded from the whole local key cache (every contact whose bundle
    // we ever fetched), so any known contact could otherwise inject a root entry that
    // sorts ahead of the real genesis and seize the room.
    private Protocol.DagState recompute_dag_pinned(Account account, string room_jid_str,
                                                   Protocol.MembershipDag dag) {
        string? pin = db.get_pinned_room_owner(account, room_jid_str);
        Protocol.DagState st = dag.recompute_pinned(make_aik_resolver(account), pin);
        if (pin == null && st.owner_fp != null) {
            db.pin_room_owner(account, room_jid_str, ((!) st.owner_fp).down());
        } else if (pin != null && st.owner_fp == null) {
            warning("x3dhpq: v2 fold for %s produced no genesis signed by the pinned owner %s; membership left unchanged (§13.1a.1)",
                room_jid_str, (!) pin);
        }
        return st;
    }

    private void rebuild_group_session_from_dag(Account account, string room_jid_str,
            Protocol.GroupSession gs) {
        Protocol.MembershipDag? dag = get_dag(account, room_jid_str);
        if (dag == null) return;
        Protocol.DagState st = recompute_dag_pinned(account, room_jid_str, dag);

        // Build the target set keyed by the session's display fingerprint.
        var target = new Gee.HashMap<string, Protocol.GroupMember>();
        foreach (string fp_hex in st.members) {
            Bytes ed_b, ml_b;
            if (!resolve_aik(account, fp_hex, out ed_b, out ml_b)) continue;
            uint8[] aik_ed = bytes_to_uint8_array(ed_b);
            uint8[] aik_mldsa = bytes_to_uint8_array(ml_b);
            uint8[] canonical = Manager.build_canonical_aik_bytes_static(aik_ed, aik_mldsa);
            var m = new Protocol.GroupMember();
            m.aik_pub_bytes = canonical;
            try {
                target.set(m.fingerprint(), m);
            } catch (GLib.Error e) {
                warning("rebuild dag: fingerprint failed in %s: %s", room_jid_str, e.message);
            }
        }
        // Additions.
        foreach (var en in target.entries) {
            if (!gs.get_members().has_key(en.key)) {
                try {
                    gs.add_initial_member(en.value);
                } catch (GLib.Error e) {
                    warning("rebuild dag: add member failed in %s: %s", room_jid_str, e.message);
                }
            }
        }
        // Removals (rotates the epoch on the way out).
        var to_remove = new Gee.ArrayList<string>();
        foreach (string fp in gs.get_members().keys) {
            if (!target.has_key(fp)) to_remove.add(fp);
        }
        foreach (string fp in to_remove) {
            try {
                gs.remove_member_by_fp(fp);
            } catch (GLib.Error e) {
                warning("rebuild dag: remove member failed in %s: %s", room_jid_str, e.message);
            }
        }
    }

    // Bundle-table fallback for AIK lookup when peer_account_identity hasn't
    // been populated yet. The bundle row stores the peer AIK halves verbatim
    // and is written by handle_inbound_bundle just before peer_account_identity.
    private bool find_peer_aik_in_bundles(Account account, uint8[] aik_fp_raw_20,
            out uint8[] out_aik_ed, out uint8[] out_aik_mldsa) {
        out_aik_ed = {};
        out_aik_mldsa = {};
        if (aik_fp_raw_20.length != 20) return false;
        var rows = db.bundle.select().with(db.bundle.account_id, "=", account.id);
        foreach (Row r in rows) {
            string? ed_b64 = r[db.bundle.aik_pub_ed25519_base64];
            string? ml_b64 = r[db.bundle.aik_pub_mldsa_base64];
            if (ed_b64 == null || ml_b64 == null) continue;
            try {
                Bytes ed = bytes_from_base64(ed_b64);
                Bytes ml = bytes_from_base64(ml_b64);
                uint8[] ed_arr = bytes_to_uint8_array(ed);
                uint8[] ml_arr = bytes_to_uint8_array(ml);
                int total = 3 + ed_arr.length + ml_arr.length;
                uint8[] enc = new uint8[total];
                enc[0] = 0; enc[1] = 1; enc[2] = 1;
                Memory.copy((uint8*) enc + 3, ed_arr, ed_arr.length);
                Memory.copy((uint8*) enc + 3 + ed_arr.length, ml_arr, ml_arr.length);
                Bytes digest = global::X3dhpq.Crypto.blake2b160(new Bytes(enc));
                unowned uint8[] dig = digest.get_data();
                bool match = true;
                for (int i = 0; i < 20; i++) {
                    if (dig[i] != aik_fp_raw_20[i]) { match = false; break; }
                }
                if (match) {
                    out_aik_ed = ed_arr;
                    out_aik_mldsa = ml_arr;
                    return true;
                }
            } catch (Error e) {
                continue;
            }
        }
        return false;
    }

    // Local account's raw AIK halves and canonical pub bytes + fingerprint.
    private bool local_aik(Account account, out uint8[] ed, out uint8[] mldsa,
            out uint8[] canonical, out uint8[] fp_raw) {
        ed = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_ed25519_base64));
        mldsa = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_mldsa_base64));
        canonical = Manager.build_canonical_aik_bytes_static(ed, mldsa);
        fp_raw = new uint8[0];
        try {
            fp_raw = bytes_to_uint8_array(global::X3dhpq.Crypto.blake2b160(new Bytes(canonical)));
        } catch (GLib.Error e) {
            return false;
        }
        return fp_raw.length == 20;
    }

    // Resolve an AIK signer's raw public-key halves from its 40-char hex
    // fingerprint, mirroring rebuild_group_session_from_journal's lookup order:
    // self, then peer_account_identity, then the bundle table fallback. Used as
    // the AikResolver for MembershipDag.recompute so v2 entries can be verified
    // against the signer's own AIK (any owner/admin may author).
    private bool resolve_aik(Account account, string fp_hex, out Bytes ed_out, out Bytes ml_out) {
        ed_out = new Bytes(new uint8[0]);
        ml_out = new Bytes(new uint8[0]);
        uint8[] fp_raw = hex_to_bytes_20(fp_hex);
        if (fp_raw.length != 20) return false;

        uint8[] my_ed, my_ml, my_canon, my_fp;
        if (local_aik(account, out my_ed, out my_ml, out my_canon, out my_fp)) {
            bool is_self = true;
            for (int i = 0; i < 20; i++) if (my_fp[i] != fp_raw[i]) { is_self = false; break; }
            if (is_self) { ed_out = new Bytes(my_ed); ml_out = new Bytes(my_ml); return true; }
        }
        uint8[] aik_ed, aik_ml;
        if (db.find_peer_account_identity_by_aik_fp(account, fp_raw, out aik_ed, out aik_ml)) {
            ed_out = new Bytes(aik_ed); ml_out = new Bytes(aik_ml); return true;
        }
        if (find_peer_aik_in_bundles(account, fp_raw, out aik_ed, out aik_ml)) {
            ed_out = new Bytes(aik_ed); ml_out = new Bytes(aik_ml); return true;
        }
        return false;
    }

    private Protocol.AikResolver make_aik_resolver(Account account) {
        return (fp_hex, out ed, out ml) => {
            return resolve_aik(account, fp_hex, out ed, out ml);
        };
    }

    // Author (sign) a v2 journal entry with the LOCAL account's AIK Ed25519 +
    // ML-DSA-65 private keys. parents = current DAG heads, lamport = next_lamport.
    // Mirrors the v1 signing pattern (ensure_private_group_bootstrapped etc.).
    private Protocol.JournalEntryV2? build_signed_v2(Account account, string room_jid_str,
            uint8 action, uint8[] payload) {
        uint8[] my_ed, my_ml, my_canon, my_fp;
        if (!local_aik(account, out my_ed, out my_ml, out my_canon, out my_fp)) return null;
        Protocol.MembershipDag dag = get_or_create_dag(account, room_jid_str);
        var entry = new Protocol.JournalEntryV2();
        entry.lamport = dag.next_lamport();
        entry.signer_fp = my_fp;
        entry.parents = dag.current_heads();
        entry.action = action;
        entry.payload = payload;
        entry.timestamp = new DateTime.now_utc().to_unix();
        try {
            uint8[] sp = entry.signed_part();
            Bytes aik_priv_ed = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_ed25519_base64));
            Bytes aik_priv_mldsa = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_mldsa_base64));
            entry.signature = bytes_to_uint8_array(global::X3dhpq.Crypto.ed25519_sign(aik_priv_ed, new Bytes(sp)));
            entry.mldsa_signature = bytes_to_uint8_array(global::X3dhpq.Crypto.mldsa65_sign(aik_priv_mldsa, new Bytes(sp)));
        } catch (GLib.Error e) {
            warning("x3dhpq v2 sign failed in %s: %s", room_jid_str, e.message);
            return null;
        }
        return entry;
    }

    public async bool ensure_get_keys_for_jid(Account account, Jid jid) {
        XmppStream? stream = app.stream_interactor.get_stream(account);
        if (stream == null) {
            return false;
        }
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (module == null) {
            return false;
        }

        ArrayList<int> devices = yield module.request_device_list((!) stream, jid);
        if (devices.size == 0) {
            return false;
        }
        foreach (int device_id in devices) {
            if (db.get_remote_bundle(account, jid.bare_jid.to_string(), device_id) == null) {
                // force=true: this is a deliberate, on-demand key fetch (group-send
                // gate / accept flow), not a hot loop — the anti-flood cooldown
                // must not suppress it, otherwise a just-verified peer reports
                // "no usable bundle data" until the cooldown lapses.
                StanzaNode? bundle = yield module.request_bundle((!) stream, jid, device_id, true);
                if (bundle == null) {
                    return false;
                }
            }
        }
        return true;
    }

    // Whether we hold a peer AIK for this contact that is in the rotated /
    // needs-review state (changed from a previously-observed one). Drives the
    // "review & accept identity" UI action.
    public bool peer_aik_needs_review(Account account, Jid jid) {
        Row? identity = db.get_peer_account_identity_row(account, jid.bare_jid.to_string());
        if (identity == null) return false;
        return ((!) identity)[db.peer_account_identity.trust_state] == "rotated";
    }

    // The spaced-hex fingerprint of the peer's currently-observed AIK, for the
    // review dialog. Null if unknown.
    public string? peer_aik_fingerprint(Account account, Jid jid) {
        return db.get_peer_aik_fingerprint(account, jid.bare_jid.to_string());
    }

    // Explicit user action (contact details) to accept a peer's CHANGED AIK after
    // reviewing the new fingerprint out-of-band. Re-pins the currently-observed
    // AIK as verified, clears the rollback/version state that was rejecting the
    // peer's post-reset devicelist (§8.5), and re-fetches the fresh devicelist +
    // bundles so capability and group membership recover. NEVER called
    // automatically — accepting an unverified AIK is the user's deliberate,
    // impersonation-aware decision.
    public async bool accept_peer_aik(Account account, Jid jid) {
        string bare = jid.bare_jid.to_string();
        XmppStream? stream = app.stream_interactor.get_stream(account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (stream == null || module == null) {
            return false;
        }
        // A peer's AIK is learned ONLY from their bundle, and their (new-AIK-
        // signed) devicelist is rejected against our STALE stored AIK — so we
        // can never fetch the new bundle to learn the new AIK: a deadlock.
        // Forget everything for this peer and re-learn their CURRENT identity
        // fresh (first-contact: devicelist accepted unverified, bundle fetched,
        // new AIK stored). Safe because this is an explicit user accept.
        db.forget_peer(account, bare);
        // The anti-flood bundle cooldown would otherwise suppress the deliberate
        // re-fetch below (the peer's bundle was almost certainly auto-requested
        // within the cooldown window), leaving accept_peer_aik unable to learn
        // the new keys — the "try again when online" dead end.
        module.clear_bundle_cooldown(jid);
        yield module.request_device_list((!) stream, jid);
        bool ok = yield ensure_get_keys_for_jid(account, jid);
        if (ok) {
            // Pin the freshly-learned AIK as user-verified (the user vouched by
            // accepting). They should still compare the now-correct fingerprint.
            db.set_peer_aik_verified(account, bare);
        }
        return ok;
    }

    // A private channel is x3dhpq-encrypted iff it has a membership journal/DAG.
    // The CREATOR sets Encryption.X3DHPQ when creating the room, but an INVITED
    // member only learns the room is encrypted once it ingests the journal (via a
    // group-sync payload or MAM). Until then its conversation keeps the default
    // (no) encryption, so the composer sends PLAINTEXT into an encrypted channel.
    // Once we hold journal state for a room, default its conversation to x3dhpq.
    // Only ever flips an unencrypted conversation on — never overrides a different
    // encryption the user may have chosen.
    public void default_group_to_x3dhpq(Account account, string room_jid_str) {
        if (!db.has_membership_journal(account, room_jid_str)
                && !db.has_membership_dag_entries(account, room_jid_str)) {
            return;
        }
        Jid room_jid;
        try {
            room_jid = new Jid(room_jid_str);
        } catch (Xmpp.InvalidJidError e) {
            return;
        }
        Conversation? conversation = app.stream_interactor.get_module(ConversationManager.IDENTITY)
            .get_conversation(room_jid.bare_jid, account, Conversation.Type.GROUPCHAT);
        if (conversation == null) {
            return;
        }
        if (conversation.encryption == Encryption.NONE) {
            conversation.encryption = Encryption.X3DHPQ;
        }
    }

    public async void prefetch_for_conversation(Conversation conversation) {
        if (conversation.type_ == Conversation.Type.GROUPCHAT_PM) {
            return;
        }

        if (conversation.type_ == Conversation.Type.CHAT) {
            yield ensure_get_keys_for_jid(conversation.account, conversation.counterpart.bare_jid);
            return;
        }

        if (conversation.type_ == Conversation.Type.GROUPCHAT) {
            // If this room is x3dhpq-backed (has a journal), make sure the
            // conversation defaults to x3dhpq before the user can type plaintext.
            default_group_to_x3dhpq(conversation.account, conversation.counterpart.bare_jid.to_string());
            Gee.List<Jid>? members = app.stream_interactor.get_module(MucManager.IDENTITY).get_offline_members(conversation.counterpart, conversation.account);
            if (members == null) {
                return;
            }
            foreach (Jid member in members) {
                if (member.equals(conversation.account.bare_jid)) {
                    continue;
                }
                yield ensure_get_keys_for_jid(conversation.account, member.bare_jid);
            }
        }
    }

    private void on_account_added(Account account) {
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (module == null) {
            return;
        }
        // One-shot recovery: if Conversations (or any peer) wiped its
        // pairwise sessions for our JID, our cached session blob points at
        // a peer-side state that no longer exists. Subsequent outbound
        // messages aren't prekey envelopes, so the peer drops them and
        // group SenderChainAnnouncements get stranded. Wipe our pairwise
        // session table once per install so the very next outgoing
        // pairwise envelope re-runs initiate_session and the peer
        // re-runs respond_session.
        wipe_sessions_once(account);
        module.device_list_loaded.connect((jid, devices) => {
            retry_pending(account);
        });
        module.bundle_fetched.connect((jid, device_id, bundle) => {
            retry_pending(account);
        });
        // Wire the membership-journal handler so PEP +notify (and explicit
        // fetch_group_items) results land in the local journal table. Without
        // this connection the room stays "not yet x3dhpq-enabled" and
        // outbound group messages get refused with WONTSEND.
        module.membership_entry_received.connect((room_jid, item_id, b64_payload) => {
            on_membership_entry_received(account, room_jid, item_id, b64_payload);
        });
    }

    // Verify and persist a membership-journal entry received via PEP. The
    // owner AIK is resolved by matching the entry payload's aik_fp against
    // peers we already trust (TOFU on first AddMember). Subsequent entries
    // are verified against the same owner AIK.
    private void on_membership_entry_received(Account account, Jid room_jid, string? item_id, string b64_payload) {
        uint8[] entry_bytes;
        try {
            entry_bytes = Base64.decode(b64_payload);
        } catch (Error e) {
            warning("membership-entry: bad base64 from %s: %s", room_jid.to_string(), e.message);
            return;
        }
        Protocol.MemberAuditEntry? entry = Protocol.MemberAuditEntry.unmarshal(entry_bytes);
        if (entry == null) {
            // Diagnostic: show first 16 bytes so we can confirm whether the
            // wire prefix is the canonical 16-byte "X3DHPQ-Audit-v1\0".
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < entry_bytes.length && i < 80; i++) {
                hex.append_printf("%02x", entry_bytes[i]);
            }
            // Also dump the trailing bytes so we can see the sig-length framing.
            StringBuilder tail = new StringBuilder();
            for (int i = int.max(0, entry_bytes.length - 16); i < entry_bytes.length; i++) {
                tail.append_printf("%02x", entry_bytes[i]);
            }
            warning("membership-entry: unmarshal failed for %s (len=%d, head80=%s, tail16=%s)",
                room_jid.to_string(), entry_bytes.length, hex.str, tail.str);
            return;
        }
        uint8[] aik_fp_raw;
        uint32 epoch_after;
        if (!Protocol.MemberAuditEntry.parse_member_payload(entry.payload, out aik_fp_raw, out epoch_after)) {
            warning("membership-entry: bad payload for %s", room_jid.to_string());
            return;
        }
        // Per XEP §13.8 the owner's AIK signs every entry; resolve it from
        // the genesis (seq=0) entry's own fp via TOFU.
        uint8[] owner_aik_ed;
        uint8[] owner_aik_mldsa;
        if (entry.seq == 0 && entry.action == (uint8) Protocol.MemberAuditAction.ADD_MEMBER) {
            // Genesis adds the owner themselves: aik_fp_raw IS the owner's fp.
            if (!db.find_peer_account_identity_by_aik_fp(account, aik_fp_raw,
                    out owner_aik_ed, out owner_aik_mldsa)) {
                warning("membership-entry seq=0 in %s references unknown AIK fp; storing unverified",
                    room_jid.to_string());
                // Best-effort store anyway so subsequent rebuild can proceed.
                db.store_membership_journal_entry(account, room_jid.bare_jid.to_string(), entry);
                return;
            }
        } else {
            // Non-genesis: the owner is whoever published seq=0. Look it up
            // from any prior stored entry's payload.
            uint8[]? prior_owner_fp = first_stored_owner_fp(account, room_jid.bare_jid.to_string());
            if (prior_owner_fp == null) {
                warning("membership-entry seq=%llu arrived before genesis in %s; skipping",
                    entry.seq, room_jid.to_string());
                return;
            }
            if (!db.find_peer_account_identity_by_aik_fp(account, prior_owner_fp,
                    out owner_aik_ed, out owner_aik_mldsa)) {
                warning("membership-entry seq=%llu in %s: prior owner fp not resolvable",
                    entry.seq, room_jid.to_string());
                return;
            }
        }
        bool ok;
        try {
            ok = entry.verify(new Bytes(owner_aik_ed), new Bytes(owner_aik_mldsa));
        } catch (Error e) {
            warning("membership-entry verify error for %s: %s", room_jid.to_string(), e.message);
            return;
        }
        if (!ok) {
            warning("membership-entry signature INVALID for %s seq=%llu",
                room_jid.to_string(), entry.seq);
            return;
        }
        db.store_membership_journal_entry(account, room_jid.bare_jid.to_string(), entry);
        // Now that this room is known x3dhpq-encrypted, default the joiner's
        // conversation to x3dhpq so it never sends plaintext into the channel.
        default_group_to_x3dhpq(account, room_jid.bare_jid.to_string());
    }

    // Ingest a raw MemberAuditEntry (bytes) delivered inside a group-sync payload
    // (bundled with the sender-chain announcement over the pairwise channel).
    private void on_membership_entry_bytes(Account account, string room_jid_str, uint8[] entry_bytes) {
        Jid room_jid;
        try {
            room_jid = new Jid(room_jid_str);
        } catch (Xmpp.InvalidJidError e) {
            return;
        }
        // v2 (multi-admin DAG) and v1 (linear owner-signed) entries are
        // self-describing by their domain-separator prefix and share the one
        // flat group-sync entry list. Route each to the right engine. Signature
        // verification for v2 happens in the fold (MembershipDag.recompute) via
        // the AIK resolver, so ingest here just dedups by content hash.
        if (Protocol.JournalEntryV2.is_v2(entry_bytes)) {
            ingest_and_store_v2(account, room_jid_str, entry_bytes);
            default_group_to_x3dhpq(account, room_jid_str);
            return;
        }
        on_membership_entry_received(account, room_jid, null, Base64.encode(entry_bytes));
    }

    // Frame a group-sync payload (see PAYLOAD_TYPE_GROUP_SYNC): the sender-chain
    // announcement bytes followed by the current membership journal entries.
    // entries is a FLAT list of already-marshaled journal entry blobs; each blob
    // may be a v1 MemberAuditEntry.marshal() OR a v2 JournalEntryV2.marshal()
    // (they self-describe by domain-separator prefix). The outer framing
    // (version|ann_len|ann|n|{len|entry}*) is a cross-client contract and is
    // unchanged — only the fact that an entry can now be v1-or-v2 is new.
    private static uint8[] build_group_sync_bytes(uint8[] ann_bytes, Gee.List<Bytes> entries) {
        var marshalled = new Gee.ArrayList<Bytes>();
        int total = 2 + 4 + ann_bytes.length + 4;
        foreach (Bytes eb in entries) {
            marshalled.add(eb);
            total += 4 + (int) eb.get_size();
        }
        uint8[] buf = new uint8[total];
        int off = 0;
        buf[off++] = 0; buf[off++] = 1;   // version = 1
        gs_put_u32(buf, ref off, (uint32) ann_bytes.length);
        Memory.copy((uint8*) buf + off, ann_bytes, ann_bytes.length); off += ann_bytes.length;
        gs_put_u32(buf, ref off, (uint32) marshalled.size);
        foreach (Bytes eb in marshalled) {
            unowned uint8[] d = eb.get_data();
            gs_put_u32(buf, ref off, (uint32) d.length);
            Memory.copy((uint8*) buf + off, d, d.length); off += d.length;
        }
        return buf;
    }

    // Gather the entries to redistribute for a room: every persisted v1 entry
    // PLUS (once the room is v2-active) every v2 DAG entry. Both v1 and v2 blobs
    // ride the same flat list; the receiver routes each by prefix. Sending both
    // keeps a legacy v1-only peer working while a bridged room's fresh joiner
    // bootstraps from the v2 Snapshot (virtual genesis).
    private Gee.ArrayList<Bytes> gather_group_sync_entries(Account account, string room_jid_str) {
        var list = new Gee.ArrayList<Bytes>();
        foreach (Protocol.MemberAuditEntry e in db.list_membership_journal_entries(account, room_jid_str)) {
            list.add(new Bytes(e.marshal()));
        }
        if (is_v2_active(account, room_jid_str)) {
            foreach (Bytes b in db.list_membership_dag_entry_blobs(account, room_jid_str)) {
                list.add(b);
            }
        }
        return list;
    }

    // Parse a group-sync payload into the announcement bytes and journal entries.
    private static bool parse_group_sync_bytes(uint8[] b, out uint8[] ann_bytes, out Gee.ArrayList<Bytes> entries) {
        ann_bytes = new uint8[0];
        entries = new Gee.ArrayList<Bytes>();
        if (b.length < 6) return false;
        int off = 0;
        int ver = (b[0] << 8) | b[1]; off += 2;
        if (ver != 1) return false;
        int64 ann_len = gs_read_u32(b, off); off += 4;
        if ((int64) off + ann_len + 4 > (int64) b.length) return false;
        ann_bytes = new uint8[(int) ann_len];
        Memory.copy(ann_bytes, (uint8*) b + off, (int) ann_len); off += (int) ann_len;
        int64 n = gs_read_u32(b, off); off += 4;
        for (int64 i = 0; i < n; i++) {
            if ((int64) off + 4 > (int64) b.length) return false;
            int64 el = gs_read_u32(b, off); off += 4;
            if ((int64) off + el > (int64) b.length) return false;
            uint8[] eb = new uint8[(int) el];
            Memory.copy(eb, (uint8*) b + off, (int) el); off += (int) el;
            entries.add(new Bytes(eb));
        }
        return true;
    }

    private static void gs_put_u32(uint8[] b, ref int off, uint32 v) {
        b[off++] = (uint8)(v >> 24); b[off++] = (uint8)(v >> 16);
        b[off++] = (uint8)(v >> 8); b[off++] = (uint8) v;
    }
    private static int64 gs_read_u32(uint8[] b, int off) {
        return ((int64) b[off] << 24) | ((int64) b[off+1] << 16) | ((int64) b[off+2] << 8) | (int64) b[off+3];
    }

    // Decode a 40-char lowercase/uppercase hex fingerprint into 20 raw bytes.
    private static uint8[] hex_to_bytes_20(string hex) {
        unowned uint8[] d = hex.data;
        if (d.length < 40) return new uint8[0];
        uint8[] b = new uint8[20];
        for (int i = 0; i < 20; i++) {
            int hi = hex_nibble(d[i * 2]);
            int lo = hex_nibble(d[i * 2 + 1]);
            if (hi < 0 || lo < 0) return new uint8[0];
            b[i] = (uint8) ((hi << 4) | lo);
        }
        return b;
    }
    private static int hex_nibble(uint8 c) {
        if (c >= '0' && c <= '9') return (int) (c - '0');
        if (c >= 'a' && c <= 'f') return (int) (c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return (int) (c - 'A' + 10);
        return -1;
    }

    // Returns the AIK fp (raw 20 bytes) embedded in the seq=0 AddMember entry
    // already stored for the given room, or null if not yet seen.
    private uint8[]? first_stored_owner_fp(Account account, string room_jid_str) {
        Row? r = db.membership_journal.select()
            .with(db.membership_journal.account_id, "=", account.id)
            .with(db.membership_journal.room_jid, "=", room_jid_str)
            .with(db.membership_journal.seq, "=", 0)
            .single().row().inner;
        if (r == null) return null;
        string? payload_b64 = ((!) r)[db.membership_journal.payload_base64];
        if (payload_b64 == null) return null;
        try {
            uint8[] payload = Base64.decode(payload_b64);
            uint8[] fp;
            uint32 ep;
            if (!Protocol.MemberAuditEntry.parse_member_payload(payload, out fp, out ep)) return null;
            return fp;
        } catch (Error e) {
            return null;
        }
    }

    private void on_stream_negotiated(Account account, XmppStream stream) {
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (module != null) {
            // Fetch our own devicelist on connect. Device trust is derived entirely
            // from the Trust Manifest fold (trustmanifest:0) plus the devtracker
            // snapshot — the retired account-audit chain no longer gates it.
            module.request_device_list.begin(stream, account.bare_jid);
        }
    }

    private Gee.List<Jid> get_recipients(Conversation conversation, Xmpp.MessageStanza message_stanza) {
        ArrayList<Jid> recipients = new ArrayList<Jid>(Jid.equals_bare_func);
        if (conversation.type_ == Conversation.Type.GROUPCHAT) {
            Gee.List<Jid>? occupants = app.stream_interactor.get_module(MucManager.IDENTITY).get_offline_members(conversation.counterpart, conversation.account);
            if (occupants == null) {
                return recipients;
            }
            foreach (Jid occupant in occupants) {
                if (!occupant.equals(conversation.account.bare_jid)) {
                    recipients.add(occupant.bare_jid);
                }
            }
        } else {
            recipients.add(message_stanza.to.bare_jid);
        }
        // Include our own bare JID so sent carbons / archived copies contain a
        // decryptable key for this account's OTHER devices (sibling sync) — UNLESS
        // the copy we hold of our own account identity is a superseded genesis
        // (rotated: a lost or independently-reset sibling under a DIFFERENT AIK).
        // Per the genesis-supersedes rule that stale device is no longer a valid
        // sibling, and including it would only block/fail the send. This device's
        // own genesis prevails; the message still goes to the peer.
        if (!peer_aik_needs_review(conversation.account, conversation.account.bare_jid)) {
            recipients.add(conversation.account.bare_jid);
        }
        return recipients;
    }

    private void mark_pending(Entities.Message message, Conversation conversation) {
        pending_messages[message] = conversation;
        message.marked = Entities.Message.Marked.UNSENT;
    }

    private void retry_pending(Account account) {
        ArrayList<Entities.Message> retry_list = new ArrayList<Entities.Message>();
        foreach (Entities.Message message in pending_messages.keys) {
            if (message.account.equals(account) && message.marked == Entities.Message.Marked.UNSENT) {
                retry_list.add(message);
            }
        }
        foreach (Entities.Message message in retry_list) {
            Conversation? conversation = pending_messages[message];
            if (conversation == null) {
                pending_messages.unset(message);
                continue;
            }
            app.stream_interactor.get_module(MessageProcessor.IDENTITY).send_xmpp_message(message, conversation, true);
        }
    }

    private void on_pre_message_send(Entities.Message message, Xmpp.MessageStanza message_stanza, Conversation conversation) {
        if (message.encryption != Encryption.X3DHPQ) {
            return;
        }
        // §10.6.6: a disabled/pending device MUST NOT send as the account —
        // peers would reject its unverifiable DC (it has no valid AddDevice-
        // covered certificate yet). This is the last-resort send gate; the
        // composer-level gate (EncryptionListEntry.encryption_activated_async)
        // normally catches this earlier with a NO_SEND input-field status, so
        // reaching here at all means a message was already queued before this
        // device became disabled (e.g. a live revocation mid-compose). An
        // AUTHORIZED device is completely unaffected — is_authorized() is true
        // for every confirmed device holding AIK_priv, exactly the population
        // that already sent normally before this change.
        if (!db.is_authorized(conversation.account)) {
            warning("x3dhpq on_pre_message_send: this device is disabled/pending — refusing to send as %s",
                conversation.account.bare_jid.to_string());
            message.marked = Message.Marked.WONTSEND;
            return;
        }
        if (conversation.type_ == Conversation.Type.GROUPCHAT_PM) {
            message.marked = Message.Marked.WONTSEND;
            return;
        }

        XmppStream? stream = app.stream_interactor.get_stream(conversation.account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(conversation.account, StreamModule.IDENTITY);
        if (stream == null || module == null) {
            message.marked = Message.Marked.UNSENT;
            return;
        }

        // GROUPCHAT path: use sender-chain group encryption.
        if (conversation.type_ == Conversation.Type.GROUPCHAT) {
            string room_jid_str = conversation.counterpart.bare_jid.to_string();
            if (!db.has_membership_journal(conversation.account, room_jid_str)
                    && !db.has_membership_dag_entries(conversation.account, room_jid_str)) {
                // No membership journal — room is not yet x3dhpq-enabled. Refuse.
                warning("x3dhpq group send refused for %s: no membership journal", room_jid_str);
                message.marked = Message.Marked.WONTSEND;
                return;
            }
            try {
                build_group_encrypted_message(message, message_stanza, conversation);
                pending_messages.unset(message);
            } catch (Error e) {
                warning("Unable to group-encrypt x3dhpq message for %s: %s", room_jid_str, e.message);
                mark_pending(message, conversation);
            }
            return;
        }

        Gee.List<Jid> recipients = get_recipients(conversation, message_stanza);
        if (recipients.size == 0) {
            message.marked = Message.Marked.WONTSEND;
            return;
        }

        bool waiting = false;
        foreach (Jid recipient in recipients) {
            string bare = recipient.bare_jid.to_string();
            if (!db.has_remote_device_list(conversation.account, bare)) {
                module.request_device_list.begin((!) stream, recipient);
                waiting = true;
                continue;
            }
            Gee.List<int> device_ids = db.get_remote_device_ids(conversation.account, bare);
            if (device_ids.size == 0) {
                module.request_device_list.begin((!) stream, recipient);
                waiting = true;
                continue;
            }
            foreach (int device_id in device_ids) {
                if (db.get_remote_bundle(conversation.account, bare, device_id) == null) {
                    module.request_bundle.begin((!) stream, recipient, device_id);
                    waiting = true;
                }
            }
        }
        if (waiting) {
            mark_pending(message, conversation);
            return;
        }

        try {
            build_encrypted_message(message, message_stanza, conversation, recipients);
            pending_messages.unset(message);
        } catch (Error e) {
            warning("Unable to encrypt x3dhpq message for %s: %s", conversation.counterpart.to_string(), e.message);
            mark_pending(message, conversation);
        }
    }

    // Per-room dedup of "we have already broadcast our sender chain to this
    // (peer_bare_jid, peer_device_id)". Without this, every encrypt would
    // fan out duplicate announcements.
    private HashMap<string, Gee.Set<string>> announced_to = new HashMap<string, Gee.Set<string>>();

    // Slide the group send-chain checkpoint forward at most once per this window
    // (24h) so re-shared history — and the option-1 intra-epoch forward-secrecy
    // loss — is bounded to ~24h rather than the whole (membership-driven, possibly
    // unbounded) epoch. See GroupSession.maybe_advance_checkpoint.
    private const int64 EPOCH_MAX_AGE_SECONDS = 24 * 3600;

    private void broadcast_sender_chain(Conversation conversation, Protocol.GroupSession gs,
            string room_jid_str, uint8[] aik_ed, uint8[] aik_mldsa, Jid? exclude_bare = null) {
        XmppStream? stream = app.stream_interactor.get_stream(conversation.account);
        if (stream == null) return;

        // Bound the re-shareable history / forward-secrecy window: slide the send
        // chain checkpoint forward to the current position once EPOCH_MAX_AGE has
        // elapsed since it was last set. Persist immediately if it moved so the
        // new window survives a restart regardless of which caller we came from.
        if (gs.maybe_advance_checkpoint(new DateTime.now_utc().to_unix(), EPOCH_MAX_AGE_SECONDS)) {
            db.store_group_session(conversation.account, room_jid_str, gs);
        }

        Protocol.SenderChainAnnouncement ann;
        try {
            ann = gs.announce_sender_chain();
        } catch (GLib.Error e) {
            warning("announce_sender_chain failed for %s: %s", room_jid_str, e.message);
            return;
        }
        // Bundle the current membership journal with the announcement (group-sync).
        // The journal thus rides the pairwise rekey fan-out that epoch rotation
        // already requires, so members receive it reliably over the 1:1 channel
        // without depending on MUC MAM.
        uint8[] ann_bytes = build_group_sync_bytes(ann.marshal(),
            gather_group_sync_entries(conversation.account, room_jid_str));

        Gee.Set<string> already = announced_to.get(room_jid_str);
        if (already == null) {
            already = new Gee.HashSet<string>();
            announced_to.set(room_jid_str, already);
        }

        // Recipients = MUC occupants UNION crypto members from the journal. A
        // freshly-added member (just granted + added to the journal) may not yet
        // be in the MUC affiliation cache, but must still receive the sender
        // chain + bundled journal (group-sync) over the 1:1 channel. Resolving
        // journal member AIK fingerprints to JIDs makes delivery independent of
        // MUC occupancy (and of the MUC being reachable at all).
        Gee.List<Jid>? occupants = app.stream_interactor.get_module(MucManager.IDENTITY)
            .get_offline_members(conversation.counterpart, conversation.account);
        var recipients = new Gee.ArrayList<Jid>();
        if (occupants != null) {
            foreach (Jid occ in occupants) recipients.add(occ);
        }
        // Resolve crypto members from the journal's raw 20-byte AIK fingerprints
        // (gs.get_members() keys are the spaced display form, unusable for lookup).
        var active_fps = new Gee.HashSet<string>();
        foreach (Protocol.MemberAuditEntry je in db.list_membership_journal_entries(conversation.account, room_jid_str)) {
            uint8[] fp; uint32 ep;
            if (!Protocol.MemberAuditEntry.parse_member_payload(je.payload, out fp, out ep)) continue;
            string fph = Protocol.hex_of(fp);
            if (je.action == (uint8) Protocol.MemberAuditAction.ADD_MEMBER) active_fps.add(fph);
            else if (je.action == (uint8) Protocol.MemberAuditAction.REMOVE_MEMBER) active_fps.remove(fph);
        }
        // Once the room is v2-active, the folded DagState is authoritative for
        // membership — union its members so v2-added members receive the bundle
        // over the pairwise channel even before they appear as MUC occupants.
        if (is_v2_active(conversation.account, room_jid_str)) {
            Protocol.DagState st = recompute_dag_pinned(conversation.account, room_jid_str,
                (!) get_dag(conversation.account, room_jid_str));
            active_fps.clear();
            foreach (string fph in st.members) active_fps.add(fph);
        }
        foreach (string fph in active_fps) {
            uint8[] fp_raw = hex_to_bytes_20(fph);
            if (fp_raw.length != 20) continue;
            string? jid_str = db.find_peer_jid_by_aik_fp(conversation.account, fp_raw);
            if (jid_str == null) continue;
            try {
                Jid mj = new Jid(jid_str);
                bool present = false;
                foreach (Jid r in recipients) { if (r.equals_bare(mj)) { present = true; break; } }
                if (!present) recipients.add(mj);
            } catch (Xmpp.InvalidJidError err) { }
        }

        // Include our own bare JID so this account's SIBLING devices (same AIK,
        // different device_id) also receive the sender-chain announcement over
        // the 1:1 channel — mirrors the 1:1 self-fanout. The inner per-device
        // loop below still skips THIS device. Without this, siblings never get
        // our group recv chain and silently drop our group messages.
        {
            bool own_present = false;
            foreach (Jid r in recipients) { if (r.equals_bare(conversation.account.bare_jid)) { own_present = true; break; } }
            if (!own_present) recipients.add(conversation.account.bare_jid);
        }

        int? local_device_id = db.get_local_device_id(conversation.account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(conversation.account, StreamModule.IDENTITY);
        int sent = 0;
        foreach (Jid occ in recipients) {
            // Never hand a freshly rotated sender chain to a member we just
            // removed (epoch rotation would be pointless otherwise).
            if (exclude_bare != null && occ.equals_bare((!) exclude_bare)) continue;
            string peer_bare = occ.bare_jid.to_string();
            Gee.List<int> device_ids = db.get_remote_device_ids(conversation.account, peer_bare);
            if (device_ids.size == 0) {
                if (module != null) {
                    module.request_device_list.begin((!) stream, occ.bare_jid);
                }
                continue;
            }
            foreach (int device_id in device_ids) {
                // Skip only THIS device — a sender never announces to itself.
                // Own-account siblings (same bare jid, different device_id) are
                // NOT skipped: they need our recv chain.
                if (occ.equals_bare(conversation.account.bare_jid)
                        && local_device_id != null
                        && device_id == (int) (!) local_device_id) continue;
                string key = "%s/%d".printf(peer_bare, device_id);
                Protocol.PeerBundle? bundle = db.get_remote_bundle(conversation.account, peer_bare, device_id);
                if (bundle == null || !bundle.verify()) {
                    if (module != null) {
                        module.request_bundle.begin((!) stream, occ.bare_jid, device_id);
                    }
                    continue;
                }
                // Re-broadcast on every encrypt. The dedup ("already
                // announced") set was masking failed deliveries: if the
                // first announcement got lost on the wire (e.g. server-side
                // CSI hold or Conversations-side parser miss), we'd never
                // retry. Until we have a positive ACK that the peer
                // installed the chain, every send re-announces — peers
                // dedup on (sender_aik_fp, device, epoch) when accepting
                // and reinstalling the same recv chain is a no-op.
                bool ok_send = send_sender_chain_to_device(conversation, occ.bare_jid, device_id, bundle, ann_bytes);
                if (ok_send) {
                    already.add(key);
                    sent++;
                }
            }
        }
    }

    private bool send_sender_chain_to_device(Conversation conversation, Jid peer_bare,
            int device_id, Protocol.PeerBundle bundle, uint8[] ann_bytes) {
        int? local_device_id = db.get_local_device_id(conversation.account);
        if (local_device_id == null) return false;

        try {
            // Random transport key (32 + 12 = 44 bytes), used to AES-GCM the
            // announcement bytes; the transport key itself is then sealed
            // pairwise via the existing X3DHPQ session.
            Bytes payload_key = global::X3dhpq.Crypto.random_bytes(32);
            Bytes payload_nonce = global::X3dhpq.Crypto.random_bytes(12);
            Bytes payload_transport_key = bytes_from_uint8_array(
                concat_byte_arrays(bytes_to_uint8_array(payload_key), bytes_to_uint8_array(payload_nonce)));
            Bytes payload_ciphertext = Protocol.encrypt_payload_bytes(new Bytes(ann_bytes), payload_transport_key);

            Protocol.SessionState? state = db.get_session(conversation.account, peer_bare.to_string(), device_id);
            if (state != null && (state.chain_send_key == null
                    || bytes_to_uint8_array((!) state.chain_send_key).length == 0)) {
                db.delete_session(conversation.account, peer_bare.to_string(), device_id);
                state = null;
            }
            Protocol.SessionBootstrap? bootstrap = null;
            if (state == null) {
                bootstrap = Protocol.initiate_session(
                    db.get_local_identity_bytes(conversation.account, db.account_identity.dik_priv_x25519_base64),
                    db.get_local_identity_bytes(conversation.account, db.account_identity.dik_pub_x25519_base64),
                    bundle
                );
                state = bootstrap.state;
            }
            Protocol.MessageHeader header;
            Bytes encrypted_transport_key;
            Protocol.encrypt_transport_key((!) state, payload_transport_key, out header, out encrypted_transport_key);
            db.store_session(conversation.account, peer_bare.to_string(), device_id, (!) state);

            // Build the wire message. <x3dhpq><key rid=...><hdr/><emk/>{<prekey/>}</key>
            //   <payload type='sender-chain'>BASE64(ct)</payload></x3dhpq>
            StanzaNode envelope = new StanzaNode.build("x3dhpq", Protocol.NS_ENVELOPE)
                .add_self_xmlns()
                .put_attribute("sender-device", ((!) local_device_id).to_string())
                .put_attribute("sender-jid", conversation.account.bare_jid.to_string())
                .put_attribute("ts", new DateTime.now_utc().format_iso8601());

            StanzaNode key_node = new StanzaNode.build("key", Protocol.NS_ENVELOPE)
                .put_attribute("rid", device_id.to_string())
                .put_node(new StanzaNode.build("hdr", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(bytes_to_base64(header.marshal()))))
                .put_node(new StanzaNode.build("emk", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(bytes_to_base64(encrypted_transport_key))));

            if (bootstrap != null) {
                StanzaNode prekey_node = new StanzaNode.build("prekey", Protocol.NS_ENVELOPE)
                    .put_attribute("ek", bytes_to_base64((!) bootstrap.prekey_ephemeral_pub))
                    .put_attribute("opk-id", bootstrap.opk_id.to_string())
                    .put_attribute("kemkey-id", bootstrap.kem_key_id.to_string())
                    .put_attribute("kem-ct", bytes_to_base64((!) bootstrap.kem_ciphertext))
                    .put_node(new StanzaNode.build("dc", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(db.ensure_local_device_certificate(conversation.account))))
                    .put_node(new StanzaNode.build("aik-ed25519", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(db.get_local_identity_string(conversation.account, db.account_identity.aik_pub_ed25519_base64))))
                    .put_node(new StanzaNode.build("aik-mldsa", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(db.get_local_identity_string(conversation.account, db.account_identity.aik_pub_mldsa_base64))));
                key_node.put_node(prekey_node);
            }
            envelope.put_node(key_node);
            envelope.put_node(new StanzaNode.build("payload", Protocol.NS_ENVELOPE)
                .put_attribute("type", Protocol.PAYLOAD_TYPE_GROUP_SYNC)
                .put_node(new StanzaNode.text(bytes_to_base64(payload_ciphertext))));

            Xmpp.MessageStanza msg = new Xmpp.MessageStanza();
            msg.to = peer_bare;
            msg.type_ = Xmpp.MessageStanza.TYPE_CHAT;
            msg.stanza.put_node(envelope);
            // Tell the server: don't store, don't carbon (XEP-0334 / XEP-0280).
            Xmpp.Xep.MessageProcessingHints.set_message_hint(msg, Xmpp.Xep.MessageProcessingHints.HINT_NO_STORE);
            Xmpp.Xep.MessageProcessingHints.set_message_hint(msg, Xmpp.Xep.MessageProcessingHints.HINT_NO_COPY);

            XmppStream? stream = app.stream_interactor.get_stream(conversation.account);
            if (stream == null) return false;
            stream.get_module(Xmpp.MessageModule.IDENTITY).send_message.begin(stream, msg);
            return true;
        } catch (Error e) {
            warning("send_sender_chain_to_device(%s/%d) failed: %s",
                peer_bare.to_string(), device_id, e.message);
            return false;
        }
    }

    // Per-(peer/device) cooldown so a persistently-failing peer can't cause a
    // rekey storm.
    private HashMap<string, int64?> rekey_at = new HashMap<string, int64?>();
    private const int64 REKEY_COOLDOWN_US = 30 * 1000000;

    // Re-negotiate the pairwise session after a decrypt failure (a stale or
    // mismatched session — typically our cached bundle predates the peer's key
    // regeneration, e.g. after the peer reset). Drop the stale session, refetch a
    // fresh bundle, and send a prekey "rekey" heartbeat: on the peer,
    // prekey_overrides_orphan replaces its own stale session, so both sides
    // converge on a fresh session and subsequent messages decrypt. Rate-limited.
    private async void trigger_session_rekey(Account account, Jid peer_jid, int device_id) {
        string key = "%s/%d".printf(peer_jid.bare_jid.to_string(), device_id);
        int64 now = get_monotonic_time();
        int64? last = rekey_at.has_key(key) ? rekey_at.get(key) : null;
        if (last != null && now - (!) last < REKEY_COOLDOWN_US) {
            return;
        }
        rekey_at.set(key, now);

        XmppStream? stream = app.stream_interactor.get_stream(account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (stream == null || module == null) {
            return;
        }
        string peer_bare = peer_jid.bare_jid.to_string();
        // Drop the stale local session and force a genuinely fresh bundle fetch
        // (bypassing the anti-flood cooldown) before re-initiating.
        db.delete_session(account, peer_bare, device_id);
        module.clear_bundle_cooldown(peer_jid);
        yield module.request_bundle((!) stream, peer_jid, device_id, true);

        Protocol.PeerBundle? bundle = db.get_remote_bundle(account, peer_bare, device_id);
        if (bundle == null || !((!) bundle).verify()) {
            warning("x3dhpq rekey: no usable fresh bundle for %s/%d — cannot renegotiate", peer_bare, device_id);
            return;
        }
        send_session_rekey(account, peer_jid, device_id, (!) bundle);
    }

    // Establish a fresh outbound session from `bundle` and send an (empty) prekey
    // heartbeat with a PAYLOAD_TYPE_REKEY payload. Mirrors send_sender_chain_to_device
    // but carries no announcement — its only purpose is to hand the peer a fresh
    // prekey so it re-establishes the session.
    private void send_session_rekey(Account account, Jid peer_bare, int device_id, Protocol.PeerBundle bundle) {
        int? local_device_id = db.get_local_device_id(account);
        if (local_device_id == null) return;
        try {
            Bytes payload_key = global::X3dhpq.Crypto.random_bytes(32);
            Bytes payload_nonce = global::X3dhpq.Crypto.random_bytes(12);
            Bytes payload_transport_key = bytes_from_uint8_array(
                concat_byte_arrays(bytes_to_uint8_array(payload_key), bytes_to_uint8_array(payload_nonce)));
            Bytes payload_ciphertext = Protocol.encrypt_payload_bytes(new Bytes(new uint8[0]), payload_transport_key);

            // Always a fresh session (caller deleted the stale one).
            Protocol.SessionBootstrap bootstrap = Protocol.initiate_session(
                db.get_local_identity_bytes(account, db.account_identity.dik_priv_x25519_base64),
                db.get_local_identity_bytes(account, db.account_identity.dik_pub_x25519_base64),
                bundle);
            Protocol.SessionState state = bootstrap.state;
            Protocol.MessageHeader header;
            Bytes encrypted_transport_key;
            Protocol.encrypt_transport_key(state, payload_transport_key, out header, out encrypted_transport_key);
            db.store_session(account, peer_bare.to_string(), device_id, state);

            StanzaNode envelope = new StanzaNode.build("x3dhpq", Protocol.NS_ENVELOPE)
                .add_self_xmlns()
                .put_attribute("sender-device", ((!) local_device_id).to_string())
                .put_attribute("sender-jid", account.bare_jid.to_string())
                .put_attribute("ts", new DateTime.now_utc().format_iso8601());
            StanzaNode key_node = new StanzaNode.build("key", Protocol.NS_ENVELOPE)
                .put_attribute("rid", device_id.to_string())
                .put_node(new StanzaNode.build("hdr", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(bytes_to_base64(header.marshal()))))
                .put_node(new StanzaNode.build("emk", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(bytes_to_base64(encrypted_transport_key))));
            StanzaNode prekey_node = new StanzaNode.build("prekey", Protocol.NS_ENVELOPE)
                .put_attribute("ek", bytes_to_base64((!) bootstrap.prekey_ephemeral_pub))
                .put_attribute("opk-id", bootstrap.opk_id.to_string())
                .put_attribute("kemkey-id", bootstrap.kem_key_id.to_string())
                .put_attribute("kem-ct", bytes_to_base64((!) bootstrap.kem_ciphertext))
                .put_node(new StanzaNode.build("dc", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(db.ensure_local_device_certificate(account))))
                .put_node(new StanzaNode.build("aik-ed25519", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(db.get_local_identity_string(account, db.account_identity.aik_pub_ed25519_base64))))
                .put_node(new StanzaNode.build("aik-mldsa", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(db.get_local_identity_string(account, db.account_identity.aik_pub_mldsa_base64))));
            key_node.put_node(prekey_node);
            envelope.put_node(key_node);
            envelope.put_node(new StanzaNode.build("payload", Protocol.NS_ENVELOPE)
                .put_attribute("type", Protocol.PAYLOAD_TYPE_REKEY)
                .put_node(new StanzaNode.text(bytes_to_base64(payload_ciphertext))));

            Xmpp.MessageStanza msg = new Xmpp.MessageStanza();
            msg.to = peer_bare;
            msg.type_ = Xmpp.MessageStanza.TYPE_CHAT;
            msg.stanza.put_node(envelope);
            Xmpp.Xep.MessageProcessingHints.set_message_hint(msg, Xmpp.Xep.MessageProcessingHints.HINT_NO_STORE);
            Xmpp.Xep.MessageProcessingHints.set_message_hint(msg, Xmpp.Xep.MessageProcessingHints.HINT_NO_COPY);
            XmppStream? stream = app.stream_interactor.get_stream(account);
            if (stream == null) return;
            stream.get_module(Xmpp.MessageModule.IDENTITY).send_message.begin((!) stream, msg);
            warning("x3dhpq: sent rekey heartbeat to %s/%d", peer_bare.to_string(), device_id);
        } catch (Error e) {
            warning("send_session_rekey(%s/%d) failed: %s", peer_bare.to_string(), device_id, e.message);
        }
    }

    // Build a responder SessionState from an inbound prekey envelope (the X3DH
    // answer to a peer's initiate_session). Returns null if any required local
    // key material is missing or respond_session throws. Reports whether a
    // one-time prekey was referenced, so the caller only marks it consumed AFTER
    // the message actually decrypts. Shared by the primary no-session/orphan path
    // and the stale-live-session retry in decrypt_message.
    private Protocol.SessionState? respond_session_from_prekey(Conversation conversation, StanzaNode prekey_node, string sender_jid_value, int sender_device_id, out bool consumed, out int consumed_opk_id) {
        consumed = false;
        consumed_opk_id = 0;
        Protocol.DeviceCertificate? peer_cert = Protocol.DeviceCertificate.unmarshal(bytes_from_base64(prekey_node.get_deep_string_content("dc")));
        if (peer_cert == null) {
            return null;
        }
        // §9.2.1: a first-message prekey is SELF-CONTAINED — it carries the sender's DC
        // and both AIK halves inline, all attacker-controlled. respond_session below
        // checks that the DC verifies under the AIK carried WITH it (step 3), which
        // only proves internal consistency: anyone can mint a fresh AIK and issue
        // themselves a DC under it. The two checks that actually bind the material to a
        // real identity are here.
        //
        // Step 2 — the certificate must belong to the device we key the session by.
        // Without this, one device's certificate is replayable to open a session as a
        // different device of the same account.
        if ((int) peer_cert.device_id != sender_device_id) {
            warning("x3dhpq: prekey DC device id %u does not match sender device %d for %s — rejecting (§9.2.1)",
                peer_cert.device_id, sender_device_id, sender_jid_value);
            return null;
        }
        // Step 4 — the carried AIK must equal the identity we have pinned for this
        // account. A mismatch is an apparent identity reconstruction and must go
        // through the §12.2 re-trust gate, never be silently adopted; without it a
        // malicious relay simply presents its own AIK and impersonates the contact,
        // because a successful PQXDH proves only that the sender chose the key
        // material, not who they are.
        Bytes carried_aik_ed = bytes_from_base64(prekey_node.get_deep_string_content("aik-ed25519"));
        Bytes carried_aik_mldsa = bytes_from_base64(prekey_node.get_deep_string_content("aik-mldsa"));
        Bytes pinned_aik_ed, pinned_aik_mldsa;
        if (db.get_peer_aik_pubs(conversation.account, sender_jid_value, out pinned_aik_ed, out pinned_aik_mldsa)) {
            if (pinned_aik_ed.compare(carried_aik_ed) != 0 || pinned_aik_mldsa.compare(carried_aik_mldsa) != 0) {
                warning("x3dhpq: prekey from %s/%d carries an AIK that differs from the pinned identity — refusing to open a session (§9.2.1, §12.2)",
                    sender_jid_value, sender_device_id);
                return null;
            }
        }
        Row local_bundle = db.get_required_local_bundle(conversation.account);
        Row? local_spk = db.get_local_signed_pre_key(conversation.account, local_bundle[db.bundle.signed_pre_key_id]);
        Row? local_kem = db.get_local_kem_pre_key(conversation.account, prekey_node.get_attribute_int("kemkey-id"));
        if (local_spk == null || local_kem == null) {
            return null;
        }
        Row? local_opk = null;
        int opk_id = prekey_node.get_attribute_int("opk-id");
        if (opk_id > 0) {
            local_opk = db.get_local_one_time_pre_key(conversation.account, opk_id);
        }
        try {
            Protocol.SessionState st = Protocol.respond_session(
                db.get_local_identity_bytes(conversation.account, db.account_identity.dik_priv_x25519_base64),
                db.get_local_identity_bytes(conversation.account, db.account_identity.dik_pub_x25519_base64),
                bytes_from_base64(((!) local_spk)[db.signed_pre_key.private_base64]),
                bytes_from_base64(((!) local_spk)[db.signed_pre_key.public_base64]),
                local_opk != null ? bytes_from_base64(((!) local_opk)[db.one_time_pre_key.private_base64]) : null,
                bytes_from_base64(((!) local_kem)[db.kem_pre_key.private_base64]),
                peer_cert,
                bytes_from_base64(prekey_node.get_deep_string_content("aik-ed25519")),
                bytes_from_base64(prekey_node.get_deep_string_content("aik-mldsa")),
                bytes_from_base64(prekey_node.get_attribute("ek")),
                bytes_from_base64(prekey_node.get_attribute("kem-ct"))
            );
            if (local_opk != null) {
                consumed = true;
                consumed_opk_id = opk_id;
            }
            return st;
        } catch (Error e) {
            warning("Unable to respond to x3dhpq prekey message from %s/%d: %s", sender_jid_value, sender_device_id, e.message);
            return null;
        }
    }

    private void build_group_encrypted_message(Entities.Message message, Xmpp.MessageStanza message_stanza, Conversation conversation) throws Error {
        int? local_device_id = db.get_local_device_id(conversation.account);
        if (local_device_id == null || message_stanza.body == null) {
            throw new IOError.FAILED("Missing local device or body");
        }
        string room_jid_str = conversation.counterpart.bare_jid.to_string();
        // Build canonical aik pub bytes (version | has_mldsa | ed25519 | mldsa).
        uint8[] aik_ed = bytes_to_uint8_array(db.get_local_identity_bytes(conversation.account, db.account_identity.aik_pub_ed25519_base64));
        uint8[] aik_mldsa = bytes_to_uint8_array(db.get_local_identity_bytes(conversation.account, db.account_identity.aik_pub_mldsa_base64));
        uint8[] canonical_aik = Manager.build_canonical_aik_bytes_static(aik_ed, aik_mldsa);

        Protocol.GroupSession? gs = db.load_group_session(conversation.account, room_jid_str, canonical_aik, (uint32)(!) local_device_id);
        if (gs == null) {
            gs = Protocol.GroupSession.new_session(room_jid_str, canonical_aik, (uint32)(!) local_device_id);
        }

        // Replay the persisted journal so members map is up to date. Without
        // this, the local session has empty members and announce_sender_chain
        // can't tell who to address.
        rebuild_group_session_from_journal(conversation.account, room_jid_str, (!) gs);

        // Broadcast our sender chain to every member device that hasn't yet
        // received it. Without this, peers see "no recv chain for ..." and
        // drop our group messages. Idempotent via announced_to.
        broadcast_sender_chain(conversation, (!) gs, room_jid_str, aik_ed, aik_mldsa);

        uint8[] plaintext = string_to_bytes((!) message_stanza.body);
        Protocol.GroupMessageHeader hdr;
        uint8[] ciphertext;
        gs.encrypt(plaintext, out hdr, out ciphertext);

        db.store_group_session(conversation.account, room_jid_str, (!) gs);

        // Compute sender AIK fingerprint for the envelope attribute.
        string sender_aik_fp = db.get_aik_fingerprint(conversation.account) ?? "";

        StanzaNode group_env = new StanzaNode.build("x3dhpq-group", Protocol.NS_ENVELOPE)
            .add_self_xmlns()
            .put_attribute("sender-aik-fp", sender_aik_fp)
            .put_node(new StanzaNode.build("hdr", Protocol.NS_ENVELOPE)
                .put_node(new StanzaNode.text(Base64.encode(hdr.marshal()))))
            .put_node(new StanzaNode.build("ct", Protocol.NS_ENVELOPE)
                .put_node(new StanzaNode.text(Base64.encode(ciphertext))));

        // §13.1b anti-withholding: advertise our observed v2 journal DAG heads
        // so peers can detect a withholding relay (or their own gap) over the
        // authenticated group channel. Omitted when the room has no v2
        // frontier yet (v1-only or not yet bootstrapped).
        if (is_v2_active(conversation.account, room_jid_str)) {
            Protocol.MembershipDag? dag = get_dag(conversation.account, room_jid_str);
            if (dag != null) {
                Gee.ArrayList<Bytes> heads = dag.current_heads();
                if (heads.size > 0) {
                    group_env.put_node(new StanzaNode.build("heads", Protocol.NS_ENVELOPE)
                        .put_node(new StanzaNode.text(Base64.encode(Protocol.GroupHeads.encode(heads)))));
                }
            }
        }

        message_stanza.stanza.put_node(group_env);
        ExplicitEncryption.add_encryption_tag_to_message(message_stanza, Protocol.NS_X3DHPQ, "x3dhpq");
        message_stanza.body = "[This message is x3dhpq group encrypted]";
    }


    private void build_encrypted_message(Entities.Message message, Xmpp.MessageStanza message_stanza, Conversation conversation, Gee.List<Jid> recipients) throws Error {
        int? local_device_id = db.get_local_device_id(conversation.account);
        if (local_device_id == null || message_stanza.body == null) {
            throw new IOError.FAILED("Missing local device or body");
        }

        Bytes payload_key = global::X3dhpq.Crypto.random_bytes(32);
        Bytes payload_nonce = global::X3dhpq.Crypto.random_bytes(12);
        Bytes payload_transport_key = bytes_from_uint8_array(concat_byte_arrays(bytes_to_uint8_array(payload_key), bytes_to_uint8_array(payload_nonce)));
        Bytes payload_ciphertext = global::X3dhpq.Crypto.aes256gcm_encrypt(payload_key, payload_nonce, new Bytes((uint8[]) message_stanza.body.data));
        StanzaNode envelope = new StanzaNode.build("x3dhpq", Protocol.NS_ENVELOPE)
            .add_self_xmlns()
            .put_attribute("sender-device", ((!) local_device_id).to_string())
            .put_attribute("sender-jid", conversation.account.bare_jid.to_string())
            .put_attribute("ts", new DateTime.now_utc().format_iso8601());

        foreach (Jid recipient in recipients) {
            foreach (int device_id in db.get_remote_device_ids(conversation.account, recipient.bare_jid.to_string())) {
                Protocol.PeerBundle? bundle = db.get_remote_bundle(conversation.account, recipient.bare_jid.to_string(), device_id);
                if (bundle == null || !bundle.verify()) {
                    continue;
                }

                Protocol.SessionState? state = db.get_session(conversation.account, recipient.bare_jid.to_string(), device_id);
                if (state != null && (state.chain_send_key == null || bytes_to_uint8_array((!) state.chain_send_key).length == 0)) {
                    warning("x3dhpq dropping corrupt local session for %s/%d: empty send chain key",
                        recipient.to_string(),
                        device_id);
                    db.delete_session(conversation.account, recipient.bare_jid.to_string(), device_id);
                    state = null;
                }
                Protocol.SessionBootstrap? bootstrap = null;
                if (state == null) {
                    bootstrap = Protocol.initiate_session(
                        db.get_local_identity_bytes(conversation.account, db.account_identity.dik_priv_x25519_base64),
                        db.get_local_identity_bytes(conversation.account, db.account_identity.dik_pub_x25519_base64),
                        bundle
                    );
                    state = bootstrap.state;
                }

                Protocol.MessageHeader header;
                Bytes encrypted_transport_key;
                Protocol.encrypt_transport_key((!) state, payload_transport_key, out header, out encrypted_transport_key);
                db.store_session(conversation.account, recipient.bare_jid.to_string(), device_id, (!) state);

                StanzaNode key_node = new StanzaNode.build("key", Protocol.NS_ENVELOPE)
                    .put_attribute("rid", device_id.to_string())
                    .put_node(new StanzaNode.build("hdr", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(bytes_to_base64(header.marshal()))))
                    .put_node(new StanzaNode.build("emk", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(bytes_to_base64(encrypted_transport_key))));

                if (bootstrap != null) {
                    StanzaNode prekey_node = new StanzaNode.build("prekey", Protocol.NS_ENVELOPE)
                        .put_attribute("ek", bytes_to_base64((!) bootstrap.prekey_ephemeral_pub))
                        .put_attribute("opk-id", bootstrap.opk_id.to_string())
                        .put_attribute("kemkey-id", bootstrap.kem_key_id.to_string())
                        .put_attribute("kem-ct", bytes_to_base64((!) bootstrap.kem_ciphertext))
                        .put_node(new StanzaNode.build("dc", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(db.ensure_local_device_certificate(conversation.account))))
                        .put_node(new StanzaNode.build("aik-ed25519", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(db.get_local_identity_string(conversation.account, db.account_identity.aik_pub_ed25519_base64))))
                        .put_node(new StanzaNode.build("aik-mldsa", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(db.get_local_identity_string(conversation.account, db.account_identity.aik_pub_mldsa_base64))));
                    key_node.put_node(prekey_node);
                }
                envelope.put_node(key_node);
            }
        }

        envelope.put_node(new StanzaNode.build("payload", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(bytes_to_base64(payload_ciphertext))));
        message_stanza.stanza.put_node(envelope);
        ExplicitEncryption.add_encryption_tag_to_message(message_stanza, Protocol.NS_X3DHPQ, "x3dhpq");
        message_stanza.body = "[This message is x3dhpq encrypted]";
    }

    private class DecryptMessageListener : MessageListener {
        private Manager manager;
        public string[] after_actions_const = new string[]{ };
        public override string action_group { get { return "DECRYPT"; } }
        public override string[] after_actions { get { return after_actions_const; } }

        public DecryptMessageListener(Manager manager) {
            this.manager = manager;
        }

        public override async bool run(Entities.Message message, Xmpp.MessageStanza stanza, Conversation conversation) {
            // A <journal-entry> is a group membership-journal record riding the MUC
            // groupchat channel (WS1). It carries no user-visible content, so if we
            // handle one we consume the message (return true) to keep it out of the
            // conversation. Live delivery and MUC MAM catch-up both reach here.
            if (manager.try_handle_journal_entry(stanza, conversation)) {
                return true;
            }
            // decrypt_message returns "abort pipeline?" — true only when it stashed
            // a group message that can't be decrypted yet (no recv chain), so the
            // unreadable message is NOT stored/deduped and can be re-decrypted once
            // the sender chain arrives. Decrypted (or non-ours) messages return
            // false and flow on to be stored.
            return manager.decrypt_message(message, stanza, conversation);
        }
    }

    // Detect and ingest a <journal-entry> membership record carried in a
    // type='groupchat' message (WS1 transport). Returns true if the stanza was a
    // journal entry (and was fed to the verifier), so the caller suppresses it.
    private bool try_handle_journal_entry(Xmpp.MessageStanza stanza, Conversation conversation) {
        StanzaNode? entry = stanza.stanza.get_subnode("journal-entry", Protocol.NS_ENVELOPE);
        if (entry == null) {
            return false;
        }
        string? payload = entry.get_string_content();
        if (payload != null && payload.strip() != "") {
            try {
                uint8[] entry_bytes = Base64.decode(payload);
                on_membership_entry_bytes(conversation.account,
                    conversation.counterpart.bare_jid.to_string(), entry_bytes);
            } catch (Error e) {
                warning("journal-entry: bad base64 from %s: %s",
                    conversation.counterpart.bare_jid.to_string(), e.message);
            }
        }
        return true;
    }

    private bool decrypt_message(Entities.Message message, Xmpp.MessageStanza stanza, Conversation conversation) {
        // Check for group envelope first.
        StanzaNode? group_env = stanza.stanza.get_subnode("x3dhpq-group", Protocol.NS_ENVELOPE);
        if (group_env != null) {
            return decrypt_group_message(message, stanza, conversation, group_env);
        }

        StanzaNode? envelope = stanza.stanza.get_subnode("x3dhpq", Protocol.NS_ENVELOPE);
        if (envelope == null) {
            return false;
        }
        int? local_device_id = db.get_local_device_id(conversation.account);
        if (local_device_id == null) {
            return false;
        }

        string? sender_jid_value = envelope.get_attribute("sender-jid", Protocol.NS_ENVELOPE) ?? envelope.get_attribute("sender-jid");
        if (sender_jid_value == null && stanza.from != null) {
            sender_jid_value = stanza.from.bare_jid.to_string();
        }
        if (sender_jid_value == null) {
            return false;
        }

        int sender_device_id = envelope.get_attribute_int("sender-device");
        StanzaNode? payload_node = envelope.get_subnode("payload", Protocol.NS_ENVELOPE);
        if (payload_node == null || payload_node.get_string_content() == null) {
            return false;
        }

        StanzaNode? key_node = null;
        foreach (StanzaNode node in envelope.get_subnodes("key", Protocol.NS_ENVELOPE)) {
            if (node.get_attribute_int("rid") == (!) local_device_id) {
                key_node = node;
                break;
            }
        }
        if (key_node == null) {
            return false;
        }

        Protocol.SessionState? state = db.get_session(conversation.account, sender_jid_value, sender_device_id);
        Protocol.SessionState? state_to_commit = null;
        bool consume_one_time_prekey = false;
        int consumed_opk_id = 0;

        StanzaNode? prekey_node = ((!) key_node).get_subnode("prekey", Protocol.NS_ENVELOPE);

        // Both sides may initiate near-simultaneously; whichever envelope arrives
        // first finds an existing self-initiated session whose chain_recv_key is
        // null because we never received from the peer. The cached session is
        // useless for decrypting the peer's incoming prekey envelope — its
        // sending_dh_priv is our own ephemeral, not our SPK priv. Treat that
        // case as if no session existed and run respond_session, which derives
        // the canonical responder state and replaces the orphan. Our previously
        // queued outbound (encrypted under the orphan) is acceptable to drop —
        // the peer never set up a session that could decrypt it anyway.
        bool prekey_overrides_orphan = state != null
            && prekey_node != null
            && (state.chain_recv_key == null
                || bytes_to_uint8_array((!) state.chain_recv_key).length == 0);

        // Did we build state_to_commit as a FRESH responder (respond_session) vs
        // reuse the cached session? Drives the one-shot stale-live-session retry
        // in the catch below.
        bool responded_from_prekey = false;

        if (state == null || prekey_overrides_orphan) {
            if (prekey_node == null) {
                // No session and no prekey to build one from — we cannot decrypt
                // this at all (the peer holds a live session and isn't sending us
                // prekeys). Ask it to re-initiate so we converge, instead of
                // leaving the message stuck as "[x3dhpq encrypted]".
                try {
                    trigger_session_rekey.begin(conversation.account, new Jid(sender_jid_value), sender_device_id);
                } catch (InvalidJidError je) {
                }
                return false;
            }
            state_to_commit = respond_session_from_prekey(conversation, (!) prekey_node,
                sender_jid_value, sender_device_id, out consume_one_time_prekey, out consumed_opk_id);
            if (state_to_commit == null) {
                return false;
            }
            responded_from_prekey = true;
        } else {
            state_to_commit = Protocol.SessionState.deserialize((!) state.serialize());
            if (state_to_commit == null) {
                db.delete_session(conversation.account, sender_jid_value, sender_device_id);
                return false;
            }
        }

        // Decrypt-and-handle, with one retry: if we used the cached session but
        // it fails to decrypt an envelope that CARRIES a fresh prekey, the peer
        // re-initiated (e.g. after a reset/forget). Rebuild as responder from that
        // prekey and retry once — converges in a single round trip instead of
        // requiring a mutual rekey exchange.
        for (int attempt = 0; attempt < 2; attempt++) {
        try {
            StanzaNode? hdr_node = ((!) key_node).get_subnode("hdr", Protocol.NS_ENVELOPE);
            StanzaNode? emk_node = ((!) key_node).get_subnode("emk", Protocol.NS_ENVELOPE);
            if (hdr_node == null || emk_node == null || hdr_node.get_string_content() == null || emk_node.get_string_content() == null) {
                return false;
            }
            Protocol.MessageHeader? header = Protocol.MessageHeader.unmarshal(bytes_from_base64(hdr_node.get_string_content()));
            if (header == null) {
                return false;
            }
            Bytes transport_key = Protocol.decrypt_transport_key((!) state_to_commit, header, bytes_from_base64(emk_node.get_string_content()));

            // Check for a sender-chain typed payload in place of a chat message payload.
            StanzaNode? typed_payload = envelope.get_subnode("payload", Protocol.NS_ENVELOPE);
            if (typed_payload != null) {
                string? ptype = typed_payload.get_attribute("type");
                if (ptype == Protocol.PAYLOAD_TYPE_REKEY) {
                    // Session re-negotiation heartbeat: the prekey in this message
                    // already (re)established the session above (prekey_overrides_orphan
                    // replaced any stale/orphan one). Nothing to display — just persist
                    // the fresh session so subsequent traffic uses matching keys.
                    db.store_session(conversation.account, sender_jid_value, sender_device_id, (!) state_to_commit);
                    if (consume_one_time_prekey) {
                        db.mark_local_one_time_pre_key_consumed(conversation.account, consumed_opk_id);
                    }
                    warning("x3dhpq: re-established session with %s/%d via rekey heartbeat", sender_jid_value, sender_device_id);
                    return false;
                }
                if (ptype == Protocol.PAYLOAD_TYPE_SENDER_CHAIN || ptype == Protocol.PAYLOAD_TYPE_GROUP_SYNC) {
                    // Decrypt and route the sender chain announcement (and, for a
                    // group-sync payload, the bundled membership journal).
                    string? sc_b64 = typed_payload.get_string_content();
                    if (sc_b64 != null) {
                        try {
                            Bytes sc_bytes_decrypted = Protocol.decrypt_payload_bytes(transport_key, bytes_from_base64(sc_b64));
                            uint8[] decrypted = bytes_to_uint8_array(sc_bytes_decrypted);
                            uint8[] ann_only = decrypted;
                            Gee.ArrayList<Bytes>? journal_entries = null;
                            if (ptype == Protocol.PAYLOAD_TYPE_GROUP_SYNC) {
                                Gee.ArrayList<Bytes> je;
                                if (parse_group_sync_bytes(decrypted, out ann_only, out je)) {
                                    journal_entries = je;
                                }
                            }
                            Protocol.SenderChainAnnouncement? ann = Protocol.SenderChainAnnouncement.unmarshal(ann_only);
                            if (ann != null) {
                                // Ingest the bundled journal BEFORE accepting the
                                // sender chain, so rebuild_group_session_from_journal
                                // sees the members and accept_sender_chain succeeds.
                                if (journal_entries != null) {
                                    foreach (Bytes eb in journal_entries) {
                                        on_membership_entry_bytes(conversation.account,
                                            ann.room_jid, bytes_to_uint8_array(eb));
                                    }
                                }
                                // Pass the AUTHENTICATED outer sender through: the
                                // pairwise envelope proves who sent this, and §13.4.1
                                // requires the announcement's self-claimed identity to
                                // be checked against it.
                                on_sender_chain_announcement(conversation.account, ann,
                                    sender_jid_value, sender_device_id);
                            } else {
                                warning("x3dhpq sender-chain unmarshal returned null from %s/%d",
                                    sender_jid_value, sender_device_id);
                            }
                        } catch (GLib.Error e) {
                            warning("x3dhpq sender-chain payload decrypt failed: %s", e.message);
                        }
                    }
                    db.store_session(conversation.account, sender_jid_value, sender_device_id, (!) state_to_commit);
                    if (consume_one_time_prekey) {
                        db.mark_local_one_time_pre_key_consumed(conversation.account, consumed_opk_id);
                    }
                    // Do not set message.body — this is a control message, not visible.
                    return false;
                }
            }

            string plaintext;
            Protocol.decrypt_payload(transport_key, bytes_from_base64((!) payload_node.get_string_content()), out plaintext);
            db.store_session(conversation.account, sender_jid_value, sender_device_id, (!) state_to_commit);
            if (consume_one_time_prekey) {
                db.mark_local_one_time_pre_key_consumed(conversation.account, consumed_opk_id);
            }
            message.body = plaintext;
            message.encryption = Encryption.X3DHPQ;
            // Record sibling authorship for a 1:1 message: authored by our own
            // bare JID but by a DIFFERENT device than this install. Lets the UI
            // attribute it ("from Device N"). Never recorded for peer messages or
            // this device's own echoes (sender_device_id == local).
            if (conversation.type_ == Conversation.Type.CHAT
                    && message.stanza_id != null
                    && sender_jid_value == conversation.account.bare_jid.to_string()
                    && sender_device_id != (int) (!) local_device_id) {
                db.store_message_source_device(conversation.account, (!) message.stanza_id, sender_device_id);
            }
            if (conversation.type_ == Conversation.Type.GROUPCHAT) {
                try {
                    message.real_jid = new Jid(sender_jid_value);
                } catch (InvalidJidError e) {
                    warning("Invalid x3dhpq sender jid in group message: %s", e.message);
                }
            }
            // Decrypted → continue the pipeline so it is stored (return value is
            // now "abort pipeline?", see DecryptMessageListener).
            return false;
        } catch (Error e) {
            // First failure with a cached session but a fresh prekey present:
            // the peer re-initiated (reset/forget). Rebuild as responder from the
            // prekey and retry the decrypt once before giving up — no side effects
            // ran yet (the failure is at transport-key/payload decrypt, before any
            // store), so re-running is safe.
            if (attempt == 0 && !responded_from_prekey && prekey_node != null) {
                Protocol.SessionState? rebuilt = respond_session_from_prekey(conversation, (!) prekey_node,
                    sender_jid_value, sender_device_id, out consume_one_time_prekey, out consumed_opk_id);
                if (rebuilt != null) {
                    state_to_commit = rebuilt;
                    responded_from_prekey = true;
                    continue;
                }
            }
            warning("Unable to decrypt x3dhpq message from %s/%d: %s", sender_jid_value, sender_device_id, e.message);
            // Stale/mismatched session (e.g. our cached bundle predated the peer's
            // key regeneration after a reset). Auto-renegotiate rather than staying
            // wedged: drop the session, refetch a fresh bundle, and hand the peer a
            // fresh prekey so both sides converge. Rate-limited inside. The message
            // that just failed is lost (resend/retransmit picks it up).
            try {
                trigger_session_rekey.begin(conversation.account, new Jid(sender_jid_value), sender_device_id);
            } catch (InvalidJidError je) {
                // sender_jid_value came off the wire; ignore if unparseable.
            }
            return false;
        }
        }
        return false;
    }

    // True iff a sender-chain announcement's self-claimed identity matches the
    // (jid, device) that the authenticated pairwise session proves actually sent it
    // (§13.4.1).
    //
    // The announcement is NOT signed: its authenticity comes entirely from the pairwise
    // channel, which proves only the sending device. `SenderAIKPub` and
    // `sender_device_id` inside it are plaintext claims chosen by whoever composed it.
    // Checking merely that the claimed AIK is a room member is useless, because every
    // member satisfies that for every OTHER member's fingerprint — so any member could
    // install its own chain key under a second member's recvKey and then author group
    // messages attributed to that member. Group messages carry no per-message sender
    // signature (§13.3), so attribution rests entirely on which chain is installed under
    // which key: this check is what makes in-room impersonation impossible.
    private bool announcement_matches_outer_sender(Dino.Entities.Account account,
                                                   Protocol.SenderChainAnnouncement ann,
                                                   string sender_jid_value,
                                                   int sender_device_id) {
        if (ann.sender_device_id != (uint32) sender_device_id) {
            warning("x3dhpq: rejecting sender-chain announcement from %s/%d — it claims device %u (§13.4.1)",
                sender_jid_value, sender_device_id, ann.sender_device_id);
            return false;
        }
        uint8[] claimed = ann.sender_aik_pub_bytes;
        uint8[] authoritative;
        if (sender_jid_value == account.bare_jid.to_string()) {
            // Our own sibling devices: the authoritative AIK is this account's own.
            uint8[] aik_ed = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_ed25519_base64));
            uint8[] aik_ml = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_mldsa_base64));
            authoritative = Manager.build_canonical_aik_bytes_static(aik_ed, aik_ml);
        } else {
            Bytes pinned_ed, pinned_ml;
            if (!db.get_peer_aik_pubs(account, sender_jid_value, out pinned_ed, out pinned_ml)) {
                // Nothing pinned yet: we cannot attribute this chain to anyone, and
                // installing an unattributable chain is exactly what this rule prevents.
                // Announcements are re-broadcast on every send, so a legitimate one is
                // retried once the identity is known.
                warning("x3dhpq: rejecting sender-chain announcement from %s — no pinned AIK to bind the claimed identity to (§13.4.1)",
                    sender_jid_value);
                return false;
            }
            authoritative = Manager.build_canonical_aik_bytes_static(
                bytes_to_uint8_array(pinned_ed), bytes_to_uint8_array(pinned_ml));
        }
        if (claimed.length != authoritative.length
                || Memory.cmp(claimed, authoritative, claimed.length) != 0) {
            warning("x3dhpq: rejecting sender-chain announcement from %s/%d — the AIK it claims is not that sender's identity (impersonation attempt, §13.4.1)",
                sender_jid_value, sender_device_id);
            return false;
        }
        return true;
    }

    private void on_sender_chain_announcement(Dino.Entities.Account account, Protocol.SenderChainAnnouncement ann,
                                              string sender_jid_value, int sender_device_id) {
        if (!announcement_matches_outer_sender(account, ann, sender_jid_value, sender_device_id)) {
            return;
        }
        // Look up or create the group session for this room.
        string room_jid_str = ann.room_jid;
        int? local_device_id = db.get_local_device_id(account);
        if (local_device_id == null) return;
        uint8[] aik_ed = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_ed25519_base64));
        uint8[] aik_mldsa = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_mldsa_base64));
        uint8[] canonical_aik = Manager.build_canonical_aik_bytes_static(aik_ed, aik_mldsa);
        Protocol.GroupSession? gs = db.load_group_session(account, room_jid_str, canonical_aik, (uint32)(!) local_device_id);
        if (gs == null) {
            try {
                gs = Protocol.GroupSession.new_session(room_jid_str, canonical_aik, (uint32)(!) local_device_id);
            } catch (GLib.Error e) {
                warning("x3dhpq new_session failed for %s: %s", room_jid_str, e.message);
                return;
            }
        }
        // Replay journal so the members map is non-empty before accept.
        rebuild_group_session_from_journal(account, room_jid_str, (!) gs);
        try {
            gs.accept_sender_chain(ann);
            db.store_group_session(account, room_jid_str, gs);
            // A sender chain was just installed. Re-decrypt any group messages we
            // stashed while lacking this recv chain (they were kept OUT of the
            // store precisely so we could re-run them now — history_sync would
            // otherwise treat a re-fetch as a server-id duplicate and never
            // re-deliver). Then also trigger a MUC MAM catch-up for anything we
            // never fetched at all.
            drain_pending_group_messages(account, room_jid_str);
            trigger_group_mam_catchup(account, room_jid_str);
        } catch (GLib.Error e) {
            warning("x3dhpq accept_sender_chain failed for %s: %s", room_jid_str, e.message);
        }
    }

    // Per-room guard so we don't fan out overlapping MAM catch-up queries when
    // several sender-chain announcements land in quick succession.
    private Gee.HashSet<string> group_mam_catchup_in_flight = new Gee.HashSet<string>();

    // §13.1b anti-withholding: rooms where a peer advertised journal heads we
    // lack. In-memory only — the durable truth is the journal itself; this
    // set exists so the UI can show a warning until the frontiers converge.
    private Gee.HashSet<string> divergent_rooms = new Gee.HashSet<string>();
    // Rate limit for divergence-triggered MAM catch-ups, per room.
    private HashMap<string, int64?> divergence_last_catchup = new HashMap<string, int64?>();
    private const int64 DIVERGENCE_CATCHUP_INTERVAL_US = 30 * 1000 * 1000; // 30 s

    private string divergent_key(Conversation conversation) {
        return "%d/%s".printf(conversation.account.id, conversation.counterpart.bare_jid.to_string());
    }

    /** @return true if the given room currently has an unresolved §13.1b divergence. */
    public bool is_frontier_divergent(Conversation conversation) {
        return divergent_rooms.contains(divergent_key(conversation));
    }

    /** Clears the §13.1b divergence flag for a room (converged or dismissed). */
    public void clear_frontier_divergent(Conversation conversation) {
        string k = divergent_key(conversation);
        if (divergent_rooms.remove(k)) {
            warning("x3dhpq: journal frontier converged for %s", k);
        }
    }

    // Kick off a MUC (XEP-0313) MAM catch-up for the given room via Dino core's
    // HistorySync. Idempotent per (account, room): a query already in flight is
    // not re-issued.
    private void trigger_group_mam_catchup(Dino.Entities.Account account, string room_jid_str) {
        string key = "%d/%s".printf(account.id, room_jid_str);
        if (group_mam_catchup_in_flight.contains(key)) {
            return;
        }
        Jid room_jid;
        try {
            room_jid = new Jid(room_jid_str);
        } catch (InvalidJidError e) {
            return;
        }
        MessageProcessor? mp = app.stream_interactor.get_module(MessageProcessor.IDENTITY);
        if (mp == null || mp.history_sync == null) {
            return;
        }
        unowned HistorySync history_sync = mp.history_sync;
        Conversation? conversation = app.stream_interactor.get_module(ConversationManager.IDENTITY)
            .get_conversation(room_jid.bare_jid, account, Conversation.Type.GROUPCHAT);
        DateTime until = (conversation != null && conversation.active_last_changed != null)
            ? conversation.active_last_changed.add(-TimeSpan.DAY * 5)
            : new DateTime.from_unix_utc(0);
        group_mam_catchup_in_flight.add(key);
        history_sync.fetch_everything.begin(account, room_jid.bare_jid, null, until, (_, res) => {
            history_sync.fetch_everything.end(res);
            group_mam_catchup_in_flight.remove(key);
        });
    }

    // ── Deferred group-history decryption ──────────────────────────────────────
    // A group ciphertext that arrives before we hold the sender's recv chain (its
    // checkpoint announcement hasn't landed yet — e.g. a MUC MAM catch-up on join
    // races ahead of it) is stashed here, keyed by "account/room", and re-run
    // through the receive pipeline once accept_sender_chain installs the chain.
    // Bounded so a persistently-unresolvable room can't grow without limit.
    private class PendingGroupMessage {
        public Entities.Message message;
        public Xmpp.MessageStanza stanza;
        public Conversation conversation;
        public string dedup_key;
        public PendingGroupMessage(Entities.Message m, Xmpp.MessageStanza s, Conversation c, string k) {
            message = m; stanza = s; conversation = c; dedup_key = k;
        }
    }
    private HashMap<string, Gee.ArrayList<PendingGroupMessage>> pending_group_msgs =
        new HashMap<string, Gee.ArrayList<PendingGroupMessage>>();
    private const int MAX_PENDING_GROUP_MSGS_PER_ROOM = 500;

    private void queue_undecryptable_group_message(Conversation conversation, Entities.Message message, Xmpp.MessageStanza stanza) {
        string key = "%d/%s".printf(conversation.account.id, conversation.counterpart.bare_jid.to_string());
        string dedup = message.server_id ?? (message.stanza_id ?? "");
        Gee.ArrayList<PendingGroupMessage>? q = pending_group_msgs.has_key(key) ? pending_group_msgs.get(key) : null;
        if (q == null) {
            q = new Gee.ArrayList<PendingGroupMessage>();
            pending_group_msgs.set(key, q);
        }
        if (dedup != "") {
            foreach (PendingGroupMessage p in q) {
                if (p.dedup_key == dedup) return;   // already stashed
            }
        }
        if (q.size >= MAX_PENDING_GROUP_MSGS_PER_ROOM) {
            q.remove_at(0);   // drop oldest
        }
        q.add(new PendingGroupMessage(message, stanza, conversation, dedup));
    }

    // Re-run every stashed group message for a room through the receive pipeline
    // now that a sender chain was installed. Ones whose sender chain is now present
    // decrypt and store (the archive delivers oldest-first, so the stash order
    // ratchets in order); any still missing a chain (a different sender) are
    // re-stashed by the normal path and wait for that sender's announcement.
    private void drain_pending_group_messages(Account account, string room_jid_str) {
        string key = "%d/%s".printf(account.id, room_jid_str);
        if (!pending_group_msgs.has_key(key)) return;
        Gee.ArrayList<PendingGroupMessage> q = pending_group_msgs.get(key);
        pending_group_msgs.unset(key);
        if (q.size == 0) return;
        MessageProcessor? mp = app.stream_interactor.get_module(MessageProcessor.IDENTITY);
        if (mp == null) return;
        foreach (PendingGroupMessage p in q) {
            mp.received_pipeline.run.begin(p.message, p.stanza, p.conversation);
        }
    }

    private bool decrypt_group_message(Entities.Message message, Xmpp.MessageStanza stanza, Conversation conversation, StanzaNode group_env) {
        StanzaNode? hdr_node = group_env.get_subnode("hdr", Protocol.NS_ENVELOPE);
        StanzaNode? ct_node = group_env.get_subnode("ct", Protocol.NS_ENVELOPE);
        if (hdr_node == null || ct_node == null) return false;
        string? hdr_b64 = hdr_node.get_string_content();
        string? ct_b64 = ct_node.get_string_content();
        if (hdr_b64 == null || ct_b64 == null) return false;

        Protocol.GroupMessageHeader? hdr = Protocol.GroupMessageHeader.unmarshal(
            bytes_to_uint8_array(bytes_from_base64(hdr_b64)));
        if (hdr == null) return false;

        string? sender_aik_fp = group_env.get_attribute("sender-aik-fp");
        if (sender_aik_fp == null) return false;

        string room_jid_str = conversation.counterpart.bare_jid.to_string();
        int? local_device_id = db.get_local_device_id(conversation.account);
        if (local_device_id == null) return false;
        uint8[] aik_ed = bytes_to_uint8_array(db.get_local_identity_bytes(conversation.account, db.account_identity.aik_pub_ed25519_base64));
        uint8[] aik_mldsa = bytes_to_uint8_array(db.get_local_identity_bytes(conversation.account, db.account_identity.aik_pub_mldsa_base64));
        uint8[] canonical_aik = Manager.build_canonical_aik_bytes_static(aik_ed, aik_mldsa);

        // Compute our own account fingerprint once; reused below to attribute a
        // sibling's group message as our own outgoing.
        string my_fp = "";
        try {
            my_fp = account_fingerprint(new Bytes(aik_ed), new Bytes(aik_mldsa));
        } catch (Error e) {
            // leave my_fp empty; the guard below simply won't match.
        }
        // MUC echoes THIS device's own groupchat messages back to us. We don't
        // have a recv chain for ourselves (we have the send chain), so decrypt
        // would always fail with "no recv chain". Suppress ONLY this device's own
        // reflection — the local UI already shows it from when we sent it. A
        // SIBLING device (same AIK, different device_id) falls through and is
        // decrypted normally via the recv chain announced over the 1:1 channel.
        if (my_fp == sender_aik_fp && hdr.sender_device_id == (uint32) (!) local_device_id) {
            return false;
        }

        Protocol.GroupSession? gs = db.load_group_session(conversation.account, room_jid_str, canonical_aik, (uint32)(!) local_device_id);
        if (gs == null) {
            try {
                gs = Protocol.GroupSession.new_session(room_jid_str, canonical_aik, (uint32)(!) local_device_id);
            } catch (GLib.Error e) {
                return false;
            }
        }
        // Replay journal so members + removed_aiks are populated before
        // gs.decrypt does its sender-membership check.
        rebuild_group_session_from_journal(conversation.account, room_jid_str, (!) gs);

        try {
            uint8[] plaintext = gs.decrypt((!) sender_aik_fp, hdr, bytes_to_uint8_array(bytes_from_base64(ct_b64)));
            db.store_group_session(conversation.account, room_jid_str, gs);
            message.body = (string) plaintext;
            message.encryption = Encryption.X3DHPQ;
            // If this group message was authored by one of our OWN account's
            // devices — given the Gap-2 guard above, necessarily a SIBLING, not
            // this device — render it as our own outgoing message and attribute
            // the authoring device ("from Device N", task #45 infra).
            if (my_fp == sender_aik_fp) {
                message.direction = Dino.Entities.Message.DIRECTION_SENT;
                message.real_jid = conversation.account.bare_jid;
                if (message.stanza_id != null) {
                    db.store_message_source_device(conversation.account, (!) message.stanza_id, (int) hdr.sender_device_id);
                }
            }
            // §13.1b: check the sender's advertised journal heads against our
            // frontier (never fails the message — the payload is already
            // authenticated; a missing/malformed element is just ignored).
            check_advertised_heads(conversation, room_jid_str, group_env);
            // Decrypted → let the pipeline continue and store it (return value is
            // "abort pipeline?", see DecryptMessageListener).
            return false;
        } catch (Protocol.GroupSessionError.UNKNOWN_SENDER e) {
            // We do not have this sender's recv chain YET — their sender-chain
            // announcement (checkpoint) hasn't arrived, e.g. a MUC MAM catch-up on
            // join raced ahead of it. Stash the message and re-decrypt it once the
            // chain is installed, instead of storing it unreadable: Dino's
            // history_sync dedupes by server id and would never re-deliver it. We
            // ABORT the pipeline (return true) so it is not stored/deduped now.
            warning("x3dhpq group decrypt deferred (no recv chain yet) from %s in %s", sender_aik_fp, room_jid_str);
            queue_undecryptable_group_message(conversation, message, stanza);
            return true;
        } catch (GLib.Error e) {
            warning("x3dhpq group decrypt failed from %s in %s: %s", sender_aik_fp, room_jid_str, e.message);
            return false;
        }
    }

    // §13.1b anti-withholding: compare the heads advertised in the envelope
    // with our current v2 DAG frontier. An advertised head we do not hold
    // means the peer's frontier extends past ours — a withholding relay,
    // or our own gap. Surface it (UI flag + log) and re-fetch via MAM,
    // rate-limited per room. The flag clears automatically once a later
    // message confirms all advertised heads are local.
    private void check_advertised_heads(Conversation conversation, string room_jid_str, StanzaNode group_env) {
        StanzaNode? heads_node = group_env.get_subnode("heads", Protocol.NS_ENVELOPE);
        if (heads_node == null || !is_v2_active(conversation.account, room_jid_str)) {
            return; // no advertisement (pre-upgrade sender) or no v2 frontier to compare
        }
        string? heads_b64 = heads_node.get_string_content();
        if (heads_b64 == null || heads_b64.strip() == "") return;
        Gee.ArrayList<Bytes> advertised;
        try {
            advertised = Protocol.GroupHeads.decode(bytes_to_uint8_array(bytes_from_base64(heads_b64)));
        } catch (Error e) {
            warning("x3dhpq: malformed <heads> in group message for %s: %s", room_jid_str, e.message);
            return;
        }
        Protocol.MembershipDag? dag = get_dag(conversation.account, room_jid_str);
        if (dag == null) return;
        // current_heads() walks the whole DAG — compute it once.
        Gee.ArrayList<Bytes> local = dag.current_heads();
        if (Protocol.GroupHeads.covers(advertised, local)) {
            // We hold every head the peer advertised — converged (or the peer
            // is simply behind us, which is not withholding).
            clear_frontier_divergent(conversation);
            return;
        }
        string key = divergent_key(conversation);
        divergent_rooms.add(key);
        // Count the missing heads for the log (they are not otherwise derivable).
        var local_hex = new Gee.HashSet<string>();
        foreach (Bytes h in local) local_hex.add(Protocol.hex_of(bytes_to_uint8_array(h)));
        int missing = 0;
        foreach (Bytes h in advertised) {
            if (!local_hex.contains(Protocol.hex_of(bytes_to_uint8_array(h)))) missing++;
        }
        warning("x3dhpq: journal frontier divergence in %s: peer advertises %d head(s) we do not have; requesting MAM catch-up (§13.1b)",
            room_jid_str, missing);
        int64 now = GLib.get_monotonic_time();
        int64 last = divergence_last_catchup.has_key(key) ? divergence_last_catchup.get(key) : 0;
        if (now - last >= DIVERGENCE_CATCHUP_INTERVAL_US) {
            divergence_last_catchup.set(key, now);
            trigger_group_mam_catchup(conversation.account, room_jid_str);
        }
    }

    // Static helper so on_sender_chain_announcement and build_group_encrypted_message share logic.
    private static uint8[] build_canonical_aik_bytes_static(uint8[] ed25519_pub, uint8[] mldsa_pub) {
        bool has_mldsa = mldsa_pub.length > 0;
        int total = 2 + 1 + 32 + mldsa_pub.length;
        uint8[] buf = new uint8[total];
        buf[0] = 0; buf[1] = 1;
        buf[2] = has_mldsa ? 1 : 0;
        Memory.copy((uint8*) buf + 3, ed25519_pub, 32);
        if (has_mldsa) {
            Memory.copy((uint8*) buf + 35, mldsa_pub, mldsa_pub.length);
        }
        return buf;
    }

    // Bootstrap x3dhpq on a newly created private group.
    // Publishes the genesis journal entry (seq=0 AddMember[self]) so that
    // has_membership_journal() returns true immediately and the first
    // outbound group message is not refused.
    public async bool ensure_private_group_bootstrapped(Dino.Entities.Account account, Jid room_jid) {
        XmppStream? stream = app.stream_interactor.get_stream(account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (stream == null || module == null) {
            return false;
        }
        string room_jid_str = room_jid.bare_jid.to_string();
        if (db.has_membership_journal(account, room_jid_str)
                || db.has_membership_dag_entries(account, room_jid_str)) {
            return true;
        }
        db.ensure_local_identity(account);
        db.ensure_local_prekeys(account);
        uint8[] aik_ed = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_ed25519_base64));
        uint8[] aik_mldsa = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_mldsa_base64));
        uint8[] canonical_aik = Manager.build_canonical_aik_bytes_static(aik_ed, aik_mldsa);
        uint8[] aik_fp_raw = null;
        try {
            Bytes fp_bytes = global::X3dhpq.Crypto.blake2b160(new Bytes(canonical_aik));
            aik_fp_raw = bytes_to_uint8_array(fp_bytes);
        } catch (GLib.Error e) {
            return false;
        }
        try {
            Protocol.MemberAuditEntry entry = new Protocol.MemberAuditEntry();
            entry.seq = 0;
            entry.prev_hash = new uint8[32];
            entry.action = (uint8) Protocol.MemberAuditAction.ADD_MEMBER;
            // Genesis AddMember establishes epoch 0 and does NOT rotate (§13.1a).
            entry.payload = Protocol.MemberAuditEntry.build_member_payload(aik_fp_raw, 0);
            entry.timestamp = new DateTime.now_utc().to_unix();
            try {
                uint8[] sp = entry.signed_part();
                Bytes aik_priv_ed = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_ed25519_base64));
                Bytes aik_priv_mldsa = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_mldsa_base64));
                entry.signature = bytes_to_uint8_array(
                    global::X3dhpq.Crypto.ed25519_sign(aik_priv_ed, new Bytes(sp)));
                entry.mldsa_signature = bytes_to_uint8_array(
                    global::X3dhpq.Crypto.mldsa65_sign(aik_priv_mldsa, new Bytes(sp)));
            } catch (GLib.Error e) {
                return false;
            }
            // WS1: broadcast genesis as a <journal-entry> groupchat message; the
            // room archives it (MAM) for every future joiner. We also store it
            // locally so the owner's own session has the member set immediately.
            if (!yield module.publish_membership_audit_entry(stream, room_jid.bare_jid, entry)) {
                return false;
            }
            db.store_membership_journal_entry(account, room_jid_str, entry);
            return true;
        } catch (GLib.Error e) {
            return false;
        }
    }

    // Whether the JID publishes a usable x3dhpq devicelist (at least one active
    // device). Used by the member-management UI to distinguish "can be added"
    // from "not a post-quantum client".
    public bool member_has_x3dhpq(Dino.Entities.Account account, Jid member_jid) {
        string bare = member_jid.bare_jid.to_string();
        return db.has_remote_device_list(account, bare)
            && db.get_remote_device_ids(account, bare).size > 0;
    }

    // A room is a secret PQ group iff we hold its membership journal locally
    // (written by ensure_private_group_bootstrapped at creation/first add). This
    // is a reliable local fact, unlike MucManager.is_private_room()'s offline
    // disco cache — see the interface doc.
    public bool is_secret_pq_group(Dino.Entities.Account account, Jid room_jid) {
        string room_jid_str = room_jid.bare_jid.to_string();
        return db.has_membership_journal(account, room_jid_str)
            || db.has_membership_dag_entries(account, room_jid_str);
    }

    // Map the persisted peer AIK trust_state to the UI-facing enum.
    public global::Dino.Plugins.MemberTrustState get_member_trust_state(Dino.Entities.Account account, Jid member_jid) {
        string bare = member_jid.bare_jid.to_string();
        Row? identity = db.get_peer_account_identity_row(account, bare);
        if (identity == null) {
            return global::Dino.Plugins.MemberTrustState.UNKNOWN;
        }
        string trust_state = ((!) identity)[db.peer_account_identity.trust_state];
        switch (trust_state) {
            case "verified": return global::Dino.Plugins.MemberTrustState.VERIFIED;
            case "rotated": return global::Dino.Plugins.MemberTrustState.ROTATED;
            default: return global::Dino.Plugins.MemberTrustState.UNVERIFIED;
        }
    }

    public async bool add_private_group_member(Dino.Entities.Account account, Jid room_jid, Jid member_jid) {
        XmppStream? stream = app.stream_interactor.get_stream(account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (stream == null || module == null) {
            return false;
        }
        if (!yield ensure_private_group_bootstrapped(account, room_jid)) {
            return false;
        }
        // Room already runs the v2 multi-admin engine → author a v2 AddMember.
        if (is_v2_active(account, room_jid.bare_jid.to_string())) {
            return yield v2_add_member(account, room_jid, member_jid);
        }
        if (!(yield ensure_get_keys_for_jid(account, member_jid.bare_jid))) {
            warning("x3dhpq member add failed for %s in %s: peer bundle unavailable",
                member_jid.bare_jid.to_string(), room_jid.bare_jid.to_string());
            return false;
        }

        uint8[] member_aik_fp_raw;
        if (!db.get_peer_aik_fingerprint_raw(account, member_jid.bare_jid.to_string(), out member_aik_fp_raw)) {
            warning("x3dhpq member add failed for %s in %s: peer AIK unavailable",
                member_jid.bare_jid.to_string(), room_jid.bare_jid.to_string());
            return false;
        }

        var entries = db.list_membership_journal_entries(account, room_jid.bare_jid.to_string());
        bool is_active_member = false;
        foreach (Protocol.MemberAuditEntry entry in entries) {
            uint8[] aik_fp_raw;
            uint32 epoch_after;
            if (!Protocol.MemberAuditEntry.parse_member_payload(entry.payload, out aik_fp_raw, out epoch_after)) {
                continue;
            }
            bool same_member = aik_fp_raw.length == member_aik_fp_raw.length;
            for (int i = 0; same_member && i < aik_fp_raw.length; i++) {
                if (aik_fp_raw[i] != member_aik_fp_raw[i]) same_member = false;
            }
            if (!same_member) continue;
            if (entry.action == (uint8) Protocol.MemberAuditAction.ADD_MEMBER) {
                is_active_member = true;
            } else if (entry.action == (uint8) Protocol.MemberAuditAction.REMOVE_MEMBER) {
                is_active_member = false;
            }
        }
        if (is_active_member) {
            // Even if already a member, (re)announce so the member receives the
            // current journal + sender chain over the pairwise channel.
            announce_group_to_members(account, room_jid.bare_jid);
            return true;
        }

        uint64 next_seq = 0;
        uint8[] prev_hash = new uint8[32];
        // Derive the post-application epoch per XEP §13.1a/§13.5: the genesis
        // AddMember establishes epoch 0 and does NOT rotate; every subsequent
        // add/remove rotates exactly once, so epoch_after = previousEpoch + 1
        // (== seq for a strictly linear journal). MUST NOT be hardcoded.
        uint32 epoch_after = 0;
        if (entries.size > 0) {
            Protocol.MemberAuditEntry last_entry = entries[entries.size - 1];
            next_seq = last_entry.seq + 1;
            prev_hash = last_entry.compute_hash();
            uint8[] last_fp;
            uint32 last_epoch;
            if (Protocol.MemberAuditEntry.parse_member_payload(last_entry.payload, out last_fp, out last_epoch)) {
                epoch_after = last_epoch + 1;
            } else {
                epoch_after = (uint32) next_seq;
            }
        }

        Bytes owner_aik_priv_ed = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_ed25519_base64));
        Bytes owner_aik_priv_mldsa = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_mldsa_base64));
        Protocol.MemberAuditEntry stored_entry = new Protocol.MemberAuditEntry();
        stored_entry.seq = next_seq;
        stored_entry.prev_hash = prev_hash;
        stored_entry.action = (uint8) Protocol.MemberAuditAction.ADD_MEMBER;
        stored_entry.payload = Protocol.MemberAuditEntry.build_member_payload(member_aik_fp_raw, epoch_after);
        stored_entry.timestamp = new DateTime.now_utc().to_unix();
        try {
            uint8[] sp = stored_entry.signed_part();
            stored_entry.signature = bytes_to_uint8_array(
                global::X3dhpq.Crypto.ed25519_sign(owner_aik_priv_ed, new Bytes(sp)));
            stored_entry.mldsa_signature = bytes_to_uint8_array(
                global::X3dhpq.Crypto.mldsa65_sign(owner_aik_priv_mldsa, new Bytes(sp)));
        } catch (GLib.Error e) {
            warning("x3dhpq member add local signing failed for %s in %s: %s",
                member_jid.bare_jid.to_string(), room_jid.bare_jid.to_string(), e.message);
            return false;
        }
        if (!yield module.publish_membership_audit_entry(stream, room_jid.bare_jid, stored_entry)) {
            warning("x3dhpq member add publish failed for %s in %s",
                member_jid.bare_jid.to_string(), room_jid.bare_jid.to_string());
            return false;
        }
        db.store_membership_journal_entry(account, room_jid.bare_jid.to_string(), stored_entry);
        // Proactively push the sender chain + updated journal (group-sync) to all
        // members over the 1:1 channel, so the newly-added member becomes a crypto
        // member immediately — without waiting for the next group message and
        // without depending on MUC MAM or MUC occupancy.
        announce_group_to_members(account, room_jid.bare_jid);
        return true;
    }

    // Rebuild the group session from the journal and broadcast the sender chain +
    // bundled journal (group-sync) to every crypto member over the 1:1 channel.
    private void announce_group_to_members(Account account, Jid room_jid, Jid? exclude_bare = null) {
        Conversation? conversation = app.stream_interactor.get_module(ConversationManager.IDENTITY)
            .get_conversation(room_jid.bare_jid, account, Conversation.Type.GROUPCHAT);
        if (conversation == null) return;
        int? local_device_id = db.get_local_device_id(account);
        if (local_device_id == null) return;
        string room_jid_str = room_jid.bare_jid.to_string();
        uint8[] aik_ed = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_ed25519_base64));
        uint8[] aik_mldsa = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_mldsa_base64));
        uint8[] canonical_aik = Manager.build_canonical_aik_bytes_static(aik_ed, aik_mldsa);
        Protocol.GroupSession? gs = db.load_group_session(account, room_jid_str, canonical_aik, (uint32)(!) local_device_id);
        if (gs == null) {
            try {
                gs = Protocol.GroupSession.new_session(room_jid_str, canonical_aik, (uint32)(!) local_device_id);
            } catch (GLib.Error e) {
                return;
            }
        }
        rebuild_group_session_from_journal(account, room_jid_str, (!) gs);
        db.store_group_session(account, room_jid_str, (!) gs);
        broadcast_sender_chain(conversation, (!) gs, room_jid_str, aik_ed, aik_mldsa, exclude_bare);
    }

    // Publish a hybrid-signed RemoveMember (action=6) journal entry to the
    // room's group:0 node, then locally rotate our group epoch away from the
    // removed member and re-announce our fresh sender chain to the remaining
    // members. Structure mirrors add_private_group_member exactly so the
    // hash-chain (seq = last.seq + 1, prev_hash = last.compute_hash()) and the
    // BLAKE2b-160 fingerprint payload stay canonical.
    public async bool remove_private_group_member(Dino.Entities.Account account, Jid room_jid, Jid member_jid) {
        XmppStream? stream = app.stream_interactor.get_stream(account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (stream == null || module == null) {
            return false;
        }
        string room_jid_str = room_jid.bare_jid.to_string();
        if (!db.has_membership_journal(account, room_jid_str)
                && !db.has_membership_dag_entries(account, room_jid_str)) {
            // Room was never x3dhpq-bootstrapped; nothing to remove from.
            return false;
        }
        // Room already runs the v2 multi-admin engine → author a v2 RemoveMember
        // (kick: no ban flag). Banning uses group_ban_member (ban flag set).
        if (is_v2_active(account, room_jid_str)) {
            return yield v2_remove_member(account, room_jid, member_jid, false);
        }

        uint8[] member_aik_fp_raw;
        if (!db.get_peer_aik_fingerprint_raw(account, member_jid.bare_jid.to_string(), out member_aik_fp_raw)) {
            warning("x3dhpq member remove failed for %s in %s: peer AIK unavailable",
                member_jid.bare_jid.to_string(), room_jid_str);
            return false;
        }

        // Replay the journal to decide whether the member is currently active.
        var entries = db.list_membership_journal_entries(account, room_jid_str);
        bool is_active_member = false;
        foreach (Protocol.MemberAuditEntry entry in entries) {
            uint8[] aik_fp_raw;
            uint32 epoch_after;
            if (!Protocol.MemberAuditEntry.parse_member_payload(entry.payload, out aik_fp_raw, out epoch_after)) {
                continue;
            }
            bool same_member = aik_fp_raw.length == member_aik_fp_raw.length;
            for (int i = 0; same_member && i < aik_fp_raw.length; i++) {
                if (aik_fp_raw[i] != member_aik_fp_raw[i]) same_member = false;
            }
            if (!same_member) continue;
            if (entry.action == (uint8) Protocol.MemberAuditAction.ADD_MEMBER) {
                is_active_member = true;
            } else if (entry.action == (uint8) Protocol.MemberAuditAction.REMOVE_MEMBER) {
                is_active_member = false;
            }
        }
        if (!is_active_member) {
            // Already not a member — nothing to publish.
            return true;
        }

        uint64 next_seq = 0;
        uint8[] prev_hash = new uint8[32];
        // Derive the post-application epoch per XEP §13.1a/§13.5: the genesis
        // AddMember establishes epoch 0 and does NOT rotate; every subsequent
        // add/remove rotates exactly once, so epoch_after = previousEpoch + 1
        // (== seq for a strictly linear journal). MUST NOT be hardcoded.
        uint32 epoch_after = 0;
        if (entries.size > 0) {
            Protocol.MemberAuditEntry last_entry = entries[entries.size - 1];
            next_seq = last_entry.seq + 1;
            prev_hash = last_entry.compute_hash();
            uint8[] last_fp;
            uint32 last_epoch;
            if (Protocol.MemberAuditEntry.parse_member_payload(last_entry.payload, out last_fp, out last_epoch)) {
                epoch_after = last_epoch + 1;
            } else {
                epoch_after = (uint32) next_seq;
            }
        }

        Bytes owner_aik_priv_ed = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_ed25519_base64));
        Bytes owner_aik_priv_mldsa = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_mldsa_base64));
        Protocol.MemberAuditEntry stored_entry = new Protocol.MemberAuditEntry();
        stored_entry.seq = next_seq;
        stored_entry.prev_hash = prev_hash;
        stored_entry.action = (uint8) Protocol.MemberAuditAction.REMOVE_MEMBER;
        stored_entry.payload = Protocol.MemberAuditEntry.build_member_payload(member_aik_fp_raw, epoch_after);
        stored_entry.timestamp = new DateTime.now_utc().to_unix();
        try {
            uint8[] sp = stored_entry.signed_part();
            stored_entry.signature = bytes_to_uint8_array(
                global::X3dhpq.Crypto.ed25519_sign(owner_aik_priv_ed, new Bytes(sp)));
            stored_entry.mldsa_signature = bytes_to_uint8_array(
                global::X3dhpq.Crypto.mldsa65_sign(owner_aik_priv_mldsa, new Bytes(sp)));
        } catch (GLib.Error e) {
            warning("x3dhpq member remove local signing failed for %s in %s: %s",
                member_jid.bare_jid.to_string(), room_jid_str, e.message);
            return false;
        }
        if (!yield module.publish_membership_audit_entry(stream, room_jid.bare_jid, stored_entry)) {
            warning("x3dhpq member remove publish failed for %s in %s",
                member_jid.bare_jid.to_string(), room_jid_str);
            return false;
        }
        db.store_membership_journal_entry(account, room_jid_str, stored_entry);

        // Apply the removal locally: rebuild the group session from the journal
        // (the REMOVE entry runs remove_member_by_fp -> rotate_epoch), persist,
        // then re-announce the new send chain to the remaining members. The
        // removed member is excluded from the broadcast so the rotation holds.
        int? local_device_id = db.get_local_device_id(account);
        if (local_device_id != null) {
            uint8[] aik_ed = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_ed25519_base64));
            uint8[] aik_mldsa = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_mldsa_base64));
            uint8[] canonical_aik = Manager.build_canonical_aik_bytes_static(aik_ed, aik_mldsa);
            Protocol.GroupSession? gs = db.load_group_session(account, room_jid_str, canonical_aik, (uint32)(!) local_device_id);
            if (gs == null) {
                try {
                    gs = Protocol.GroupSession.new_session(room_jid_str, canonical_aik, (uint32)(!) local_device_id);
                } catch (GLib.Error e) {
                    gs = null;
                }
            }
            if (gs != null) {
                rebuild_group_session_from_journal(account, room_jid_str, (!) gs);
                db.store_group_session(account, room_jid_str, (!) gs);
                Conversation? conversation = app.stream_interactor.get_module(ConversationManager.IDENTITY)
                    .get_conversation(room_jid.bare_jid, account, Conversation.Type.GROUPCHAT);
                if (conversation != null) {
                    broadcast_sender_chain((!) conversation, (!) gs, room_jid_str, aik_ed, aik_mldsa, member_jid.bare_jid);
                }
            }
        }
        return true;
    }

    // ---- WS2: v2 multi-admin emit path ------------------------------------

    // Fold the persisted v1 journal to its final active member set (raw 20-byte
    // AIK fingerprints), for the v1->v2 bridge Snapshot import.
    private Gee.ArrayList<Bytes> compute_v1_member_fps(Account account, string room_jid_str) {
        var active = new Gee.HashSet<string>();          // fp_hex -> present
        var order = new Gee.ArrayList<string>();          // preserve first-seen order
        foreach (Protocol.MemberAuditEntry e in db.list_membership_journal_entries(account, room_jid_str)) {
            uint8[] fp; uint32 ep;
            if (!Protocol.MemberAuditEntry.parse_member_payload(e.payload, out fp, out ep)) continue;
            string h = Protocol.hex_of(fp);
            if (e.action == (uint8) Protocol.MemberAuditAction.ADD_MEMBER) {
                if (!active.contains(h)) { active.add(h); order.add(h); }
            } else if (e.action == (uint8) Protocol.MemberAuditAction.REMOVE_MEMBER) {
                active.remove(h);
            }
        }
        var res = new Gee.ArrayList<Bytes>();
        foreach (string h in order) {
            if (!active.contains(h)) continue;
            uint8[] raw = hex_to_bytes_20(h);
            if (raw.length == 20) res.add(new Bytes(raw));
        }
        return res;
    }

    // v1->v2 bridge: emit a virtual-genesis Snapshot (action=10, empty parents)
    // importing the v1 final member set with the local owner as the sole admin,
    // then switch the room to the v2 engine. Only the v1 owner may bridge. No-op
    // if the room is already v2-active. Returns false if we are not the owner.
    private async bool ensure_v2_bridged(Account account, Jid room_jid) {
        string room_jid_str = room_jid.bare_jid.to_string();
        if (is_v2_active(account, room_jid_str)) return true;
        XmppStream? stream = app.stream_interactor.get_stream(account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (stream == null || module == null) return false;
        uint8[] my_ed, my_ml, my_canon, my_fp;
        if (!local_aik(account, out my_ed, out my_ml, out my_canon, out my_fp)) return false;
        uint8[]? owner_fp = first_stored_owner_fp(account, room_jid_str);
        if (owner_fp == null) return false;
        for (int i = 0; i < 20; i++) if (owner_fp[i] != my_fp[i]) return false; // owner only

        var sp = new Protocol.SnapshotPayload();
        sp.owner_fp = my_fp;
        sp.epoch = 0;
        foreach (Bytes fp in compute_v1_member_fps(account, room_jid_str)) {
            string h = Protocol.hex_of(fp.get_data());
            bool is_owner = true;
            unowned uint8[] fpd = fp.get_data();
            for (int i = 0; i < 20; i++) if (fpd[i] != my_fp[i]) { is_owner = false; break; }
            if (is_owner) continue; // owner is imported as admin by the fold
            sp.member_fps.add(fp);
            sp.member_is_admin.add(false);
        }
        uint8[] payload = Protocol.JournalEntryV2.build_snapshot_payload(sp);
        Protocol.JournalEntryV2? entry = build_signed_v2(account, room_jid_str,
            (uint8) Protocol.MemberAuditActionV2.SNAPSHOT, payload);
        if (entry == null) return false;
        uint8[] entry_bytes = entry.marshal();
        if (!yield module.publish_membership_blob((!) stream, room_jid.bare_jid, entry.hash_hex(), entry_bytes)) {
            return false;
        }
        ingest_and_store_v2(account, room_jid_str, entry_bytes);
        return true;
    }

    // Author a v2 entry, apply it locally (rebuild the group session from the
    // updated fold), persist, and broadcast the whole journal (v1+v2) + fresh
    // sender chain over the group-sync bundle. exclude_bare is dropped from the
    // broadcast (used when the entry removes/bans that member).
    private async bool emit_v2(Account account, Jid room_jid, uint8 action, uint8[] payload, Jid? exclude_bare) {
        string room_jid_str = room_jid.bare_jid.to_string();
        XmppStream? stream = app.stream_interactor.get_stream(account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (stream == null || module == null) return false;
        Protocol.JournalEntryV2? entry = build_signed_v2(account, room_jid_str, action, payload);
        if (entry == null) return false;
        uint8[] entry_bytes = entry.marshal();
        if (!yield module.publish_membership_blob((!) stream, room_jid.bare_jid, entry.hash_hex(), entry_bytes)) {
            return false;
        }
        ingest_and_store_v2(account, room_jid_str, entry_bytes);
        announce_group_to_members(account, room_jid, exclude_bare);
        return true;
    }

    private async bool v2_add_member(Account account, Jid room_jid, Jid member_jid) {
        if (!(yield ensure_get_keys_for_jid(account, member_jid.bare_jid))) {
            warning("x3dhpq v2 add failed for %s: peer bundle unavailable", member_jid.to_string());
            return false;
        }
        uint8[] fp;
        if (!db.get_peer_aik_fingerprint_raw(account, member_jid.bare_jid.to_string(), out fp)) {
            return false;
        }
        uint8[] payload = Protocol.JournalEntryV2.build_member_payload(fp, 0);
        return yield emit_v2(account, room_jid, (uint8) Protocol.MemberAuditActionV2.ADD_MEMBER, payload, null);
    }

    private async bool v2_remove_member(Account account, Jid room_jid, Jid member_jid, bool ban) {
        uint8[] fp;
        if (!db.get_peer_aik_fingerprint_raw(account, member_jid.bare_jid.to_string(), out fp)) {
            return false;
        }
        uint8[] payload = Protocol.JournalEntryV2.build_remove_payload(fp, 0, ban);
        return yield emit_v2(account, room_jid, (uint8) Protocol.MemberAuditActionV2.REMOVE_MEMBER,
            payload, member_jid.bare_jid);
    }

    // Promote a member to admin (action=7). Bridges a v1 room to v2 on first use
    // (owner-only). Once v2, any admin may promote/demote another admin; the
    // authorization is enforced in the fold (signer_fp must be an admin), so a
    // non-admin author's entry is signed+relayed but ignored by every client.
    public async bool group_add_admin(Dino.Entities.Account account, Jid room_jid, Jid member_jid) {
        string room_jid_str = room_jid.bare_jid.to_string();
        if (!yield ensure_private_group_bootstrapped(account, room_jid)) return false;
        if (!yield ensure_v2_bridged(account, room_jid)) {
            warning("x3dhpq make-admin refused in %s: only the owner can enable multi-admin", room_jid_str);
            return false;
        }
        if (!(yield ensure_get_keys_for_jid(account, member_jid.bare_jid))) return false;
        uint8[] fp;
        if (!db.get_peer_aik_fingerprint_raw(account, member_jid.bare_jid.to_string(), out fp)) return false;
        uint8[] payload = Protocol.JournalEntryV2.build_member_payload(fp, 0);
        return yield emit_v2(account, room_jid, (uint8) Protocol.MemberAuditActionV2.ADD_ADMIN, payload, null);
    }

    // Demote an admin back to plain member (action=8). The owner is undemotable
    // (guarded in the fold). Bridges a v1 room to v2 (owner-only) on first use.
    public async bool group_remove_admin(Dino.Entities.Account account, Jid room_jid, Jid member_jid) {
        string room_jid_str = room_jid.bare_jid.to_string();
        if (!yield ensure_private_group_bootstrapped(account, room_jid)) return false;
        if (!yield ensure_v2_bridged(account, room_jid)) {
            warning("x3dhpq remove-admin refused in %s: only the owner can enable multi-admin", room_jid_str);
            return false;
        }
        uint8[] fp;
        if (!db.get_peer_aik_fingerprint_raw(account, member_jid.bare_jid.to_string(), out fp)) return false;
        uint8[] payload = Protocol.JournalEntryV2.build_member_payload(fp, 0);
        return yield emit_v2(account, room_jid, (uint8) Protocol.MemberAuditActionV2.REMOVE_ADMIN, payload, null);
    }

    // Ban (RemoveMember + ban flag). A banned AIK is never re-added without an
    // explicit causal path. On a still-v1 room, bridge to v2 first so the ban
    // semantics are preserved instead of degrading to a plain v1 removal.
    public async bool group_ban_member(Dino.Entities.Account account, Jid room_jid, Jid member_jid) {
        string room_jid_str = room_jid.bare_jid.to_string();
        if (!db.has_membership_journal(account, room_jid_str)
                && !db.has_membership_dag_entries(account, room_jid_str)) return false;
        if (is_v2_active(account, room_jid_str)) {
            return yield v2_remove_member(account, room_jid, member_jid, true);
        }
        if (!yield ensure_v2_bridged(account, room_jid)) {
            warning("x3dhpq ban refused in %s: only the owner can bridge v1 to v2", room_jid_str);
            return false;
        }
        return yield v2_remove_member(account, room_jid, member_jid, true);
    }

    // Whether the LOCAL account may perform admin/member ops in this room, per
    // the crypto authority (NOT the MUC affiliation): the folded v2 admin set if
    // the room is v2-active, else the v1 owner (creator). Consumed by the GUI to
    // relax the owner-only gates to owner-OR-admin. A not-yet-bootstrapped room
    // returns true (the creator is about to become owner).
    public bool local_is_group_admin(Dino.Entities.Account account, Jid room_jid) {
        string room_jid_str = room_jid.bare_jid.to_string();
        uint8[] my_ed, my_ml, my_canon, my_fp;
        if (!local_aik(account, out my_ed, out my_ml, out my_canon, out my_fp)) return false;
        string my_hex = Protocol.hex_of(my_fp);
        if (is_v2_active(account, room_jid_str)) {
            Protocol.DagState st = recompute_dag_pinned(account, room_jid_str, (!) get_dag(account, room_jid_str));
            return st.admins.contains(my_hex);
        }
        uint8[]? owner_fp = first_stored_owner_fp(account, room_jid_str);
        if (owner_fp == null) return true; // not bootstrapped yet → creator/owner-to-be
        for (int i = 0; i < 20; i++) if (owner_fp[i] != my_fp[i]) return false;
        return true;
    }

    // Whether a specific member is currently an admin in the folded v2 state
    // (false for a v1 room, which has no admin set beyond the owner). Lets the
    // GUI choose between "Make admin" and "Remove admin".
    public bool member_is_group_admin(Dino.Entities.Account account, Jid room_jid, Jid member_jid) {
        string room_jid_str = room_jid.bare_jid.to_string();
        if (!is_v2_active(account, room_jid_str)) return false;
        uint8[] fp;
        if (!db.get_peer_aik_fingerprint_raw(account, member_jid.bare_jid.to_string(), out fp)) return false;
        Protocol.DagState st = recompute_dag_pinned(account, room_jid_str, (!) get_dag(account, room_jid_str));
        return st.admins.contains(Protocol.hex_of(fp));
    }

    // Revoke one of the account's own devices (§8.6). Appends a DIK-signed REMOVE
    // entry to the account's trust manifest (the live trust source), tears down
    // local session/bundle/prekey state for that device, drops it from the
    // account's own persisted device set, and republishes our signed devicelist
    // with the shrink explicitly permitted so the new, versioned list omits the
    // revoked id.
    //
    // The publish is now union-based (StreamModule.publish_device_list lists
    // every device under the account's AIK), so omitting the revoked id is a
    // genuine content change that bumps the version and propagates to peers. A
    // publish-time guard refuses accidental shrinks, so the removal is routed
    // through republish_device_list_removing, which whitelists exactly this id.
    public async bool remove_own_device(Dino.Entities.Account account, uint32 device_id) {
        // HARD GUARD: never revoke the device we are running on. Self-revoke
        // tombstones the account's own root and republishes a devicelist without
        // any real device, orphaning the identity (observed: this device revoked
        // its own primary 1239182299 → genesis at seq=1, everything fails).
        // Removing THIS device is what "Account reset" is for.
        int? local_id_guard = db.get_local_device_id(account);
        if (local_id_guard != null && (uint32) ((!) local_id_guard) == device_id) {
            warning("x3dhpq remove_own_device: REFUSING to revoke this device (%u) — self-revoke orphans the account; use Account reset instead", device_id);
            return false;
        }
        // Trust Manifest Phase 2 (task #54): revocation is a DIK-signed REMOVE
        // entry (see StreamModule.append_device_remove_to_manifest), so authorship
        // needs only that the LOCAL device is present in the current manifest fold
        // (a trusted member holding its own DIK) — NOT the account AIK_priv. This
        // lets any folded device revoke, not just the genesis/primary. A device
        // that is not in the fold (disabled/pending, or already revoked) cannot
        // author a valid REMOVE, so refuse up front for a clear failure. Falls back
        // to is_authorized() only before the account has migrated to a manifest.
        if (!db.is_local_device_trusted_member(account)) {
            warning("x3dhpq remove_own_device: this device is not a trusted member (not in the manifest fold) — refusing to revoke device %u", device_id);
            return false;
        }
        XmppStream? stream = app.stream_interactor.get_stream(account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (stream == null || module == null) {
            // Offline: still tombstone + drop locally so the UI clears and the id
            // can't be re-seeded; the RemoveDevice audit entry + republish happen
            // on next connect via the normal bootstrap.
            db.store_revoked_device(account, (int) device_id);
            db.remove_peer_device(account, account.bare_jid.to_string(), (int) device_id);
            db.delete_own_device(account, device_id);
            return false;
        }

        // Trust Manifest Phase 2 (§D4): revocation rebuilds the account's trust
        // manifest — the LIVE and only trust source — without the target, and records
        // a durable local tombstone. The snapshot's omission alone is NOT binding on a
        // receiver (any publisher can put the device back); the tombstone consulted by
        // fold_with_tombstones is what actually keeps it out. The derived devicelist
        // cache is republished below.
        if (!yield module.append_device_remove_to_manifest(stream, device_id)) {
            warning("x3dhpq remove_own_device: manifest REMOVE publish failed for device %u", device_id);
            return false;
        }

        // §8.6 tombstone: remember this id as revoked so no inbound devicelist
        // (including a stale, old-AIK-signed one the server still serves) or peer
        // can ever re-seed it — the phantom "previous master" case.
        db.store_revoked_device(account, (int) device_id);

        // §11.4 manifest tombstone, scoped to this owner. Omission from the republished
        // snapshot is not binding on a receiver — a snapshot's contents are chosen by
        // whoever publishes it, so a device holding AIK_priv could simply republish
        // itself back in. This is what actually keeps it out, and it is consulted by
        // fold_with_tombstones on every subsequent manifest.
        db.store_manifest_revoked_device(account, account.bare_jid.to_string(), device_id);

        // Local teardown: drop the removed device's session/bundle/prekey state.
        db.remove_peer_device(account, account.bare_jid.to_string(), (int) device_id);

        // Drop the device from the account's own persisted device set so the
        // union rebuilt by publish_device_list no longer lists it.
        db.delete_own_device(account, device_id);

        // Republish our signed devicelist, permitting the shrink guard to drop
        // exactly this id (§8.6). The removed device is now absent from the
        // union, so the content changes and the version bumps (§8.2).
        yield module.republish_device_list_removing(stream, device_id);
        return true;
    }
}

}
