using Qlite;
using Dino.Entities;
using Xmpp;

namespace Dino.Plugins.X3dhpq {

public class Database : Qlite.Database {
    private const int VERSION = 15;

    public class AccountIdentityTable : Table {
        public Column<int> id = new Column.Integer("id") { primary_key = true, auto_increment = true };
        public Column<int> account_id = new Column.Integer("account_id") { unique = true, not_null = true };
        public Column<int> device_id = new Column.Integer("device_id") { not_null = true };
        public Column<bool> is_primary = new Column.BoolInt("is_primary") { default = "1" };
        public Column<string> aik_pub_ed25519_base64 = new Column.NonNullText("aik_pub_ed25519_base64");
        public Column<string> aik_priv_ed25519_base64 = new Column.NonNullText("aik_priv_ed25519_base64");
        public Column<string> aik_pub_mldsa_base64 = new Column.NonNullText("aik_pub_mldsa_base64");
        public Column<string> aik_priv_mldsa_base64 = new Column.NonNullText("aik_priv_mldsa_base64");
        public Column<string> dik_pub_ed25519_base64 = new Column.NonNullText("dik_pub_ed25519_base64");
        public Column<string> dik_priv_ed25519_base64 = new Column.NonNullText("dik_priv_ed25519_base64");
        public Column<string> dik_pub_x25519_base64 = new Column.NonNullText("dik_pub_x25519_base64");
        public Column<string> dik_priv_x25519_base64 = new Column.NonNullText("dik_priv_x25519_base64");
        public Column<string> dik_pub_mldsa_base64 = new Column.NonNullText("dik_pub_mldsa_base64");
        public Column<string> dik_priv_mldsa_base64 = new Column.NonNullText("dik_priv_mldsa_base64");
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };
        // §10.6.1/§10.6.4 enrollment-state flag, distinct from is_primary: true
        // once THIS device's local identity has been resolved — either it was
        // confirmed as genuinely primary/first-device (promote_to_primary) or it
        // was admitted as a secondary via CPace pairing (apply_paired_identity).
        // False for a freshly generated (ensure_local_identity) row that has not
        // yet been resolved either way — the pending-enrollment window the
        // account-settings banner surfaces. Added at schema v8.
        public Column<bool> confirmed = new Column.BoolInt("confirmed") { min_version = 8, default = "0" };
        // §11.8 sealed device-state tracker: true once this device has successfully
        // decrypted its own <emk> copy of the tracker at least once. Used solely to
        // distinguish "never authorized" from "revoked" the next time decryption
        // fails (StreamModule.interpret_device_tracker) — losing the ability to
        // decrypt after having had it is how revocation reaches an offline device.
        // Added at schema v10.
        public Column<bool> tracker_last_decryptable = new Column.BoolInt("tracker_last_decryptable") { min_version = 10, default = "0" };
        // §11.8: set alongside clearing tracker_last_decryptable / confirmed when a
        // previously-decryptable tracker copy stops decrypting — lets the pending-
        // enrollment banner show a distinct "you were revoked" message instead of
        // the generic "never confirmed" one. Added at schema v10.
        public Column<bool> tracker_revoked = new Column.BoolInt("tracker_revoked") { min_version = 10, default = "0" };
        // §11.8 canonical wire format: "Monotonic per-account counter (§8.2-style
        // rollback guard), advanced on every republish" — mirrors
        // X3dhpqService.nextTrackerVersion. Distinct from the devicelist's own
        // list_version (device_list table); this one only guards the devtracker
        // item. Added at schema v11.
        public Column<long> tracker_version = new Column.Long("tracker_version") { min_version = 11, default = "0" };

        internal AccountIdentityTable(Database db) {
            base(db, "account_identity");
            init({ id, account_id, device_id, is_primary, aik_pub_ed25519_base64, aik_priv_ed25519_base64, aik_pub_mldsa_base64, aik_priv_mldsa_base64, dik_pub_ed25519_base64, dik_priv_ed25519_base64, dik_pub_x25519_base64, dik_priv_x25519_base64, dik_pub_mldsa_base64, dik_priv_mldsa_base64, created_at, confirmed, tracker_last_decryptable, tracker_revoked, tracker_version });
            index("x3dhpq_account_identity_account_idx", { account_id }, true);
        }
    }

    public class PeerAccountIdentityTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> bare_jid = new Column.NonNullText("bare_jid");
        public Column<string?> aik_fingerprint = new Column.Text("aik_fingerprint");
        public Column<string?> aik_pub_ed25519_base64 = new Column.Text("aik_pub_ed25519_base64");
        public Column<string?> aik_pub_mldsa_base64 = new Column.Text("aik_pub_mldsa_base64");
        public Column<string> trust_state = new Column.NonNullText("trust_state") { default = "unverified" };
        public Column<bool> downgraded = new Column.BoolInt("downgraded") { default = "0" };
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };
        public Column<long> updated_at = new Column.Long("updated_at") { not_null = true };

        internal PeerAccountIdentityTable(Database db) {
            base(db, "peer_account_identity");
            init({ account_id, bare_jid, aik_fingerprint, aik_pub_ed25519_base64, aik_pub_mldsa_base64, trust_state, downgraded, created_at, updated_at });
            unique({ account_id, bare_jid });
        }
    }

    public class PeerDeviceTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> bare_jid = new Column.NonNullText("bare_jid");
        public Column<int> device_id = new Column.Integer("device_id") { not_null = true };
        public Column<string?> dik_pub_ed25519_base64 = new Column.Text("dik_pub_ed25519_base64");
        public Column<string?> dik_pub_x25519_base64 = new Column.Text("dik_pub_x25519_base64");
        public Column<string?> dik_pub_mldsa_base64 = new Column.Text("dik_pub_mldsa_base64");
        public Column<string?> certificate_base64 = new Column.Text("certificate_base64");
        public Column<bool> active = new Column.BoolInt("active") { default = "1" };
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };
        public Column<long> updated_at = new Column.Long("updated_at") { not_null = true };
        // First-seen device added_at (unix seconds) as carried on the signed
        // devicelist wire (XEP §8.4). Needed so the receiver can reconstruct the
        // exact SignedPart (§8.3). Added at schema v5.
        public Column<long> added_at = new Column.Long("added_at") { min_version = 5, default = "0" };
        // Per-device flags byte as carried on the signed devicelist wire (XEP
        // §8.3/§8.4; bit 0 = primary, mirrors DeviceCertificate.flags). Needed
        // so publish_device_list can reconstruct the exact SignedPart for the
        // account's own multi-device union (§8.2). Added at schema v7.
        public Column<int> flags = new Column.Integer("flags") { min_version = 7, default = "1" };

        internal PeerDeviceTable(Database db) {
            base(db, "peer_device");
            init({ account_id, bare_jid, device_id, dik_pub_ed25519_base64, dik_pub_x25519_base64, dik_pub_mldsa_base64, certificate_base64, active, created_at, updated_at, added_at, flags });
            unique({ account_id, bare_jid, device_id });
        }
    }

    public class DeviceListTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> bare_jid = new Column.NonNullText("bare_jid");
        public Column<string?> item_id = new Column.Text("item_id");
        public Column<string?> signed_payload_base64 = new Column.Text("signed_payload_base64");
        public Column<long> updated_at = new Column.Long("updated_at") { not_null = true };
        // Monotonic devicelist version (XEP §8.2). For the account's own row this
        // is the persisted per-account counter; for a peer row it is the highest
        // version accepted so far (rollback guard). Added at schema v6.
        public Column<long> list_version = new Column.Long("list_version") { min_version = 6, default = "0" };
        // Whether a hybrid-SIGNED list has ever been accepted for this jid. Once
        // true, unsigned/older lists MUST be rejected (transitional rule §8.5).
        public Column<bool> signed_accepted = new Column.BoolInt("signed_accepted") { min_version = 6, default = "0" };
        // Canonical device-set key (id|added_at|flags|cert per device, sorted).
        // Excludes issued_at/version so we can tell whether the *content* changed
        // (own version bump; §8.2) and detect same-version forks (§8.5). Added v6.
        public Column<string?> content_key = new Column.Text("content_key") { min_version = 6 };

        internal DeviceListTable(Database db) {
            base(db, "device_list");
            init({ account_id, bare_jid, item_id, signed_payload_base64, updated_at, list_version, signed_accepted, content_key });
            unique({ account_id, bare_jid });
        }
    }

    // Trust Manifest Phase 2: the last accepted manifest blob per owner (own bare
    // JID or a contact). manifest_version is the monotonic per-owner rollback
    // guard (§C.3); blob_hash_hex is SHA-256(m.marshal()) at that version, used to
    // detect same-version equivocation/forks. payload_base64 is base64(m.marshal())
    // of the last good manifest (kept so we never wipe trust on a bad update).
    public class TrustManifestTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> bare_jid = new Column.NonNullText("bare_jid");
        public Column<string?> item_id = new Column.Text("item_id");
        public Column<string?> payload_base64 = new Column.Text("payload_base64");
        public Column<long> manifest_version = new Column.Long("manifest_version") { default = "-1" };
        public Column<string?> blob_hash_hex = new Column.Text("blob_hash_hex");
        public Column<long> updated_at = new Column.Long("updated_at") { not_null = true };

        internal TrustManifestTable(Database db) {
            base(db, "trust_manifest");
            init({ account_id, bare_jid, item_id, payload_base64, manifest_version, blob_hash_hex, updated_at });
            unique({ account_id, bare_jid });
        }
    }

    public class BundleTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> bare_jid = new Column.NonNullText("bare_jid");
        public Column<int> device_id = new Column.Integer("device_id") { not_null = true };
        public Column<string?> aik_pub_ed25519_base64 = new Column.Text("aik_pub_ed25519_base64");
        public Column<string?> aik_pub_mldsa_base64 = new Column.Text("aik_pub_mldsa_base64");
        public Column<string?> identity_pub_ed25519_base64 = new Column.Text("identity_pub_ed25519_base64");
        public Column<string?> identity_pub_x25519_base64 = new Column.Text("identity_pub_x25519_base64");
        public Column<string?> identity_pub_mldsa_base64 = new Column.Text("identity_pub_mldsa_base64");
        public Column<int> signed_pre_key_id = new Column.Integer("signed_pre_key_id") { default = "-1" };
        public Column<string?> signed_pre_key_public_base64 = new Column.Text("signed_pre_key_public_base64");
        public Column<string?> signed_pre_key_signature_ed25519_base64 = new Column.Text("signed_pre_key_signature_ed25519_base64");
        public Column<string?> signed_pre_key_signature_mldsa_base64 = new Column.Text("signed_pre_key_signature_mldsa_base64");
        public Column<string?> kem_pre_keys_base64 = new Column.Text("kem_pre_keys_base64");
        public Column<string?> one_time_pre_keys_base64 = new Column.Text("one_time_pre_keys_base64");
        public Column<string?> device_certificate_base64 = new Column.Text("device_certificate_base64");
        public Column<string?> bundle_payload_base64 = new Column.Text("bundle_payload_base64");
        public Column<long> updated_at = new Column.Long("updated_at") { not_null = true };

        internal BundleTable(Database db) {
            base(db, "bundle");
            init({ account_id, bare_jid, device_id, aik_pub_ed25519_base64, aik_pub_mldsa_base64, identity_pub_ed25519_base64, identity_pub_x25519_base64, identity_pub_mldsa_base64, signed_pre_key_id, signed_pre_key_public_base64, signed_pre_key_signature_ed25519_base64, signed_pre_key_signature_mldsa_base64, kem_pre_keys_base64, one_time_pre_keys_base64, device_certificate_base64, bundle_payload_base64, updated_at });
            unique({ account_id, bare_jid, device_id });
        }
    }

    public class SignedPreKeyTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<int> key_id = new Column.Integer("key_id") { not_null = true };
        public Column<string> public_base64 = new Column.NonNullText("public_base64");
        public Column<string> private_base64 = new Column.NonNullText("private_base64");
        public Column<string> signature_ed25519_base64 = new Column.NonNullText("signature_ed25519_base64");
        public Column<string> signature_mldsa_base64 = new Column.NonNullText("signature_mldsa_base64");
        public Column<bool> published = new Column.BoolInt("published") { default = "0" };
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };

        internal SignedPreKeyTable(Database db) {
            base(db, "signed_pre_key");
            init({ account_id, key_id, public_base64, private_base64, signature_ed25519_base64, signature_mldsa_base64, published, created_at });
            unique({ account_id, key_id });
        }
    }

    public class KemPreKeyTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<int> key_id = new Column.Integer("key_id") { not_null = true };
        public Column<string> public_base64 = new Column.NonNullText("public_base64");
        public Column<string> private_base64 = new Column.NonNullText("private_base64");
        public Column<bool> published = new Column.BoolInt("published") { default = "0" };
        public Column<bool> consumed = new Column.BoolInt("consumed") { default = "0" };
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };

        internal KemPreKeyTable(Database db) {
            base(db, "kem_pre_key");
            init({ account_id, key_id, public_base64, private_base64, published, consumed, created_at });
            unique({ account_id, key_id });
        }
    }

    public class OneTimePreKeyTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<int> key_id = new Column.Integer("key_id") { not_null = true };
        public Column<string> public_base64 = new Column.NonNullText("public_base64");
        public Column<string> private_base64 = new Column.NonNullText("private_base64");
        public Column<bool> published = new Column.BoolInt("published") { default = "0" };
        public Column<bool> consumed = new Column.BoolInt("consumed") { default = "0" };
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };

        internal OneTimePreKeyTable(Database db) {
            base(db, "one_time_pre_key");
            init({ account_id, key_id, public_base64, private_base64, published, consumed, created_at });
            unique({ account_id, key_id });
        }
    }

    public class PairwiseSessionTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> bare_jid = new Column.NonNullText("bare_jid");
        public Column<int> device_id = new Column.Integer("device_id") { not_null = true };
        public Column<string?> session_state_base64 = new Column.Text("session_state_base64");
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };
        public Column<long> updated_at = new Column.Long("updated_at") { not_null = true };

        internal PairwiseSessionTable(Database db) {
            base(db, "pairwise_session");
            init({ account_id, bare_jid, device_id, session_state_base64, created_at, updated_at });
            unique({ account_id, bare_jid, device_id });
        }
    }

    public class GroupSessionTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> room_jid = new Column.NonNullText("room_jid");
        public Column<int> epoch = new Column.Integer("epoch") { not_null = true };
        public Column<string?> sender_state_base64 = new Column.Text("sender_state_base64");
        public Column<string?> member_state_base64 = new Column.Text("member_state_base64");
        public Column<string?> removed_aiks_json = new Column.Text("removed_aiks_json");
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };
        public Column<long> updated_at = new Column.Long("updated_at") { not_null = true };

        internal GroupSessionTable(Database db) {
            base(db, "group_session");
            init({ account_id, room_jid, epoch, sender_state_base64, member_state_base64, removed_aiks_json, created_at, updated_at });
            unique({ account_id, room_jid, epoch });
        }
    }

    public class MembershipJournalTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> room_jid = new Column.NonNullText("room_jid");
        public Column<int> seq = new Column.Integer("seq") { not_null = true };
        public Column<string?> prev_hash_hex = new Column.Text("prev_hash_hex");
        public Column<int> action = new Column.Integer("action") { not_null = true };
        public Column<string?> payload_base64 = new Column.Text("payload_base64");
        public Column<string?> sig_ed_base64 = new Column.Text("sig_ed_base64");
        public Column<string?> sig_mldsa_base64 = new Column.Text("sig_mldsa_base64");
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };

        internal MembershipJournalTable(Database db) {
            base(db, "membership_journal");
            init({ account_id, room_jid, seq, prev_hash_hex, action, payload_base64, sig_ed_base64, sig_mldsa_base64, created_at });
            unique({ account_id, room_jid, seq });
        }
    }

    // §11.7 device-audit DAG (device_dag.vala): local persisted store of every
    // known DeviceAuditEntryV2 for the account, keyed by its own content hash
    // so re-ingesting the same entry (e.g. re-deriving the genesis Snapshot on
    // a later publish attempt) is a harmless no-op. Mirrors MembershipJournalTable's
    // keying style exactly: a plain (not_null) account_id INTEGER with NO SQL
    // FOREIGN KEY — this codebase never declares one (see MembershipJournalTable,
    // AuditEntryTable, etc.) — so a row can never fail to insert because of a
    // dangling/late-created accounts-table reference. entry_blob_base64 stores
    // DeviceAuditEntryV2.marshal() the same way every other binary payload in
    // this schema is stored (base64 TEXT; Qlite has no native BLOB column type —
    // see AuditEntryTable.entry_base64 / MembershipJournalTable.payload_base64).
    // Added at schema v9.
    public class DeviceAuditTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> entry_hash_hex = new Column.NonNullText("entry_hash_hex");
        public Column<string> entry_blob_base64 = new Column.NonNullText("entry_blob_base64");
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };

        internal DeviceAuditTable(Database db) {
            base(db, "device_audit");
            init({ account_id, entry_hash_hex, entry_blob_base64, created_at });
            unique({ account_id, entry_hash_hex });
        }
    }

    // §11.8 queued enrollment request: a local cache of the most recently seen
    // <enroll-request> item on our own pair:0 node (StreamModule.
    // handle_enroll_request_node), so the pairing UI can surface "device X wants
    // to join" without an authorized device having to keep the "Confirm a
    // device" dialog open at the exact moment the request was published. Keyed
    // by a plain (not_null) account_id INTEGER with NO SQL FOREIGN KEY, mirroring
    // DeviceAuditTable/MembershipJournalTable — this codebase never declares one.
    // One row per account (unique account_id); a fresh request overwrites the
    // previous one via upsert. Added at schema v10.
    public class PendingEnrollmentRequestTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<int> device_id = new Column.Integer("device_id") { not_null = true };
        public Column<string> full_jid = new Column.NonNullText("full_jid");
        public Column<string> sid_base64 = new Column.NonNullText("sid_base64");
        public Column<string?> dik_ed25519_base64 = new Column.Text("dik_ed25519_base64");
        public Column<string?> dik_x25519_base64 = new Column.Text("dik_x25519_base64");
        public Column<string?> dik_mldsa_base64 = new Column.Text("dik_mldsa_base64");
        public Column<long> received_at = new Column.Long("received_at") { not_null = true };

        internal PendingEnrollmentRequestTable(Database db) {
            base(db, "pending_enrollment_request");
            init({ account_id, device_id, full_jid, sid_base64, dik_ed25519_base64, dik_x25519_base64, dik_mldsa_base64, received_at });
            unique({ account_id });
        }
    }

    // Purely-local, never-published friendly names for devices (this device and
    // siblings), keyed by (account, device_id). Absent → the UI shows a default
    // "Device N" ordinal. Added at schema v12; local-only, so never signed or
    // synced (§10.6 device labels are a client-side convenience).
    public class DeviceNicknameTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<int> device_id = new Column.Integer("device_id") { not_null = true };
        public Column<string> nickname = new Column.NonNullText("nickname");

        internal DeviceNicknameTable(Database db) {
            base(db, "device_nickname");
            init({ account_id, device_id, nickname });
            unique({ account_id, device_id });
        }
    }

    // Locally-authoritative revocation tombstones (§8.6): a device the user (or
    // any authorized device) has explicitly revoked. Persisted so an inbound
    // devicelist — including a stale, old-AIK-signed one the server still serves,
    // or a peer/pair-hello — can never RE-SEED a revoked device (the phantom
    // "previous master" case). Keyed by (account, device_id). Added at schema v13.
    public class RevokedDeviceTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<int> device_id = new Column.Integer("device_id") { not_null = true };
        public Column<long> revoked_at = new Column.Long("revoked_at") { default = "0" };

        internal RevokedDeviceTable(Database db) {
            base(db, "revoked_device");
            init({ account_id, device_id, revoked_at });
            unique({ account_id, device_id });
        }
    }

    // Records which of the account's OWN devices authored a decrypted 1:1
    // message, keyed by (account, stanza_id). Written at decrypt time only for
    // sibling-authored messages (sender bare JID == account, source device_id !=
    // this device). Local-only, never signed or synced; used purely to render a
    // "from Device N" attribution. Added at schema v15.
    public class MessageDeviceTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> stanza_id = new Column.NonNullText("stanza_id");
        public Column<int> device_id = new Column.Integer("device_id") { not_null = true };

        internal MessageDeviceTable(Database db) {
            base(db, "message_device");
            init({ account_id, stanza_id, device_id });
            unique({ account_id, stanza_id });
        }
    }

    public class AuditEntryTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> bare_jid = new Column.NonNullText("bare_jid");
        public Column<string> item_id = new Column.NonNullText("item_id");
        public Column<string?> entry_base64 = new Column.Text("entry_base64");
        public Column<string?> previous_hash_hex = new Column.Text("previous_hash_hex");
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };

        internal AuditEntryTable(Database db) {
            base(db, "audit_entry");
            init({ account_id, bare_jid, item_id, entry_base64, previous_hash_hex, created_at });
            unique({ account_id, bare_jid, item_id });
        }
    }

    public class RecoveryBlobTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> blob_id = new Column.NonNullText("blob_id");
        public Column<string?> blob_base64 = new Column.Text("blob_base64");
        public Column<string?> paper_key = new Column.Text("paper_key");
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };
        public Column<long> updated_at = new Column.Long("updated_at") { not_null = true };

        internal RecoveryBlobTable(Database db) {
            base(db, "recovery_blob");
            init({ account_id, blob_id, blob_base64, paper_key, created_at, updated_at });
            unique({ account_id, blob_id });
        }
    }

    public class PairingSessionTable : Table {
        // Columns retired at schema version 4; kept for migration bookkeeping only.
        public Column<int> _v3_account_id = new Column.Integer("account_id") { not_null = true, max_version = 3 };
        public Column<string> _v3_session_id = new Column.NonNullText("session_id") { max_version = 3 };
        public Column<string?> _v3_peer_resource = new Column.Text("peer_resource") { max_version = 3 };
        public Column<string> _v3_state = new Column.NonNullText("state") { default = "created", max_version = 3 };
        public Column<string?> _v3_transcript_base64 = new Column.Text("transcript_base64") { max_version = 3 };
        public Column<long> _v3_created_at = new Column.Long("created_at") { not_null = true, max_version = 3 };
        public Column<long> _v3_updated_at = new Column.Long("updated_at") { not_null = true, max_version = 3 };

        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> sid = new Column.NonNullText("sid") { primary_key = true };
        public Column<int> role = new Column.Integer("role") { not_null = true };
        public Column<string> peer_full_jid = new Column.NonNullText("peer_full_jid");
        public Column<string> code = new Column.NonNullText("code");
        public Column<long> started_at = new Column.Long("started_at") { not_null = true };
        public Column<string?> state_blob = new Column.Text("state_blob");

        internal PairingSessionTable(Database db) {
            base(db, "pairing_session");
            init({ _v3_account_id, _v3_session_id, _v3_peer_resource, _v3_state, _v3_transcript_base64, _v3_created_at, _v3_updated_at,
                   account_id, sid, role, peer_full_jid, code, started_at, state_blob });
        }
    }

    public class PairingSessionRow {
        public int account_id;
        public uint8[] sid;
        public int role;
        public string peer_full_jid;
        public string code;
        public int64 started_at;
        public uint8[]? state_blob;
    }

    public AccountIdentityTable account_identity { get; private set; }
    public PeerAccountIdentityTable peer_account_identity { get; private set; }
    public PeerDeviceTable peer_device { get; private set; }
    public DeviceListTable device_list { get; private set; }
    public TrustManifestTable trust_manifest { get; private set; }
    public BundleTable bundle { get; private set; }
    public SignedPreKeyTable signed_pre_key { get; private set; }
    public KemPreKeyTable kem_pre_key { get; private set; }
    public OneTimePreKeyTable one_time_pre_key { get; private set; }
    public PairwiseSessionTable pairwise_session { get; private set; }
    public GroupSessionTable group_session { get; private set; }
    public MembershipJournalTable membership_journal { get; private set; }
    public DeviceAuditTable device_audit { get; private set; }
    public AuditEntryTable audit_entry { get; private set; }
    public RecoveryBlobTable recovery_blob { get; private set; }
    public PairingSessionTable pairing_session { get; private set; }
    public PendingEnrollmentRequestTable pending_enrollment_request { get; private set; }
    public DeviceNicknameTable device_nickname { get; private set; }
    public RevokedDeviceTable revoked_device { get; private set; }
    public MessageDeviceTable message_device { get; private set; }

    public Database(string file_name) {
        base(file_name, VERSION);
        account_identity = new AccountIdentityTable(this);
        peer_account_identity = new PeerAccountIdentityTable(this);
        peer_device = new PeerDeviceTable(this);
        device_list = new DeviceListTable(this);
        trust_manifest = new TrustManifestTable(this);
        bundle = new BundleTable(this);
        signed_pre_key = new SignedPreKeyTable(this);
        kem_pre_key = new KemPreKeyTable(this);
        one_time_pre_key = new OneTimePreKeyTable(this);
        pairwise_session = new PairwiseSessionTable(this);
        group_session = new GroupSessionTable(this);
        membership_journal = new MembershipJournalTable(this);
        device_audit = new DeviceAuditTable(this);
        audit_entry = new AuditEntryTable(this);
        recovery_blob = new RecoveryBlobTable(this);
        pairing_session = new PairingSessionTable(this);
        pending_enrollment_request = new PendingEnrollmentRequestTable(this);
        device_nickname = new DeviceNicknameTable(this);
        revoked_device = new RevokedDeviceTable(this);
        message_device = new MessageDeviceTable(this);
        init({ account_identity, peer_account_identity, peer_device, device_list, trust_manifest, bundle, signed_pre_key, kem_pre_key, one_time_pre_key, pairwise_session, group_session, membership_journal, device_audit, audit_entry, recovery_blob, pairing_session, pending_enrollment_request, device_nickname, revoked_device, message_device });
    }

    public Row? get_local_identity(int account_id) {
        return account_identity.row_with(account_identity.account_id, account_id).inner;
    }

    public int? get_local_device_id(Account account) {
        Row? row = get_local_identity(account.id);
        if (row == null) {
            return null;
        }
        return ((!) row)[account_identity.device_id];
    }

    public bool has_local_identity(Account account) {
        return get_local_identity(account.id) != null;
    }

    public int count_signed_pre_keys(Account account) {
        return (int) signed_pre_key.select().with(signed_pre_key.account_id, "=", account.id).count();
    }

    public int count_kem_pre_keys(Account account) {
        return (int) kem_pre_key.select().with(kem_pre_key.account_id, "=", account.id).count();
    }

    public int count_one_time_pre_keys(Account account) {
        return (int) one_time_pre_key.select().with(one_time_pre_key.account_id, "=", account.id).count();
    }

    private int next_key_id(Table table, Column<int> account_id_column, Column<int> key_id_column, int account_id) {
        return (int) table.select().with(account_id_column, "=", account_id).count() + 1;
    }

    private Row get_required_local_identity(Account account) {
        Row? row = get_local_identity(account.id);
        assert(row != null);
        return (!) row;
    }

    public string ensure_local_device_certificate(Account account) throws GLib.Error {
        Row row = get_required_local_identity(account);
        RowOption bundle_row = bundle.select()
            .with(bundle.account_id, "=", account.id)
            .with(bundle.bare_jid, "=", account.bare_jid.to_string())
            .with(bundle.device_id, "=", row[account_identity.device_id])
            .single().row();
        // Treat an empty cached cert as "not yet issued"; a previous run that
        // failed mid-issue could have persisted "" and the != null check would
        // happily return it forever, causing publish_device_list to emit
        // <cert/> empty and peers to skip our device. See log analysis 2026-05-03.
        if (bundle_row.is_present()) {
            string? cached = bundle_row[bundle.device_certificate_base64];
            if (cached != null && cached != "") {
                return cached;
            }
        }
        Protocol.DeviceCertificate cert = Protocol.DeviceCertificate.issue(
            (uint32) row[account_identity.device_id],
            bytes_from_base64(row[account_identity.dik_pub_ed25519_base64]),
            bytes_from_base64(row[account_identity.dik_pub_x25519_base64]),
            bytes_from_base64(row[account_identity.dik_pub_mldsa_base64]),
            bytes_from_base64(row[account_identity.aik_priv_ed25519_base64]),
            bytes_from_base64(row[account_identity.aik_priv_mldsa_base64]),
            1
        );
        string certificate = Base64.encode(cert.marshal());
        if (certificate == "") {
            // Defensive: should never happen because Base64.encode of a non-empty
            // marshal is non-empty. If it ever does, throw rather than persist.
            throw new IOError.FAILED("DeviceCertificate marshal produced empty base64");
        }
        bundle.upsert()
            .value(bundle.account_id, account.id, true)
            .value(bundle.bare_jid, account.bare_jid.to_string(), true)
            .value(bundle.device_id, row[account_identity.device_id], true)
            .value(bundle.aik_pub_ed25519_base64, row[account_identity.aik_pub_ed25519_base64])
            .value(bundle.aik_pub_mldsa_base64, row[account_identity.aik_pub_mldsa_base64])
            .value(bundle.identity_pub_ed25519_base64, row[account_identity.dik_pub_ed25519_base64])
            .value(bundle.identity_pub_x25519_base64, row[account_identity.dik_pub_x25519_base64])
            .value(bundle.identity_pub_mldsa_base64, row[account_identity.dik_pub_mldsa_base64])
            .value(bundle.device_certificate_base64, certificate)
            .value(bundle.updated_at, (long) new DateTime.now_utc().to_unix())
            .perform();
        return certificate;
    }

    // Cache a DeviceCertificate that was handed to us by the pairing primary
    // (rather than self-issued, which requires an aik_priv this device may not
    // have). Mirrors the upsert in ensure_local_device_certificate() so
    // publish_device_list / bundle fetches can serve it the same way, keyed by
    // (account_id, our own bare_jid, device_id).
    public void store_local_device_certificate(Account account, int device_id, string cert_base64) {
        bundle.upsert()
            .value(bundle.account_id, account.id, true)
            .value(bundle.bare_jid, account.bare_jid.to_string(), true)
            .value(bundle.device_id, device_id, true)
            .value(bundle.device_certificate_base64, cert_base64)
            .value(bundle.updated_at, (long) new DateTime.now_utc().to_unix())
            .perform();
    }

    public void ensure_local_prekeys(Account account) {
        ensure_local_identity(account);
        Row row = get_required_local_identity(account);
        string cert;
        try {
            cert = ensure_local_device_certificate(account);
        } catch (GLib.Error e) {
            warning("Unable to issue x3dhpq device certificate for %s: %s — skipping prekey generation; will retry on next stream",
                account.bare_jid.to_string(), e.message);
            return;
        }

        try {
            if (count_signed_pre_keys(account) == 0) {
                Bytes spk_pub;
                Bytes spk_priv;
                global::X3dhpq.Crypto.generate_x25519(out spk_pub, out spk_priv);
                Bytes spk_sig_ed25519 = global::X3dhpq.Crypto.ed25519_sign(bytes_from_base64(row[account_identity.dik_priv_ed25519_base64]), spk_pub);
                Bytes spk_sig_mldsa = global::X3dhpq.Crypto.mldsa65_sign(bytes_from_base64(row[account_identity.dik_priv_mldsa_base64]), spk_pub);
                int key_id = next_key_id(signed_pre_key, signed_pre_key.account_id, signed_pre_key.key_id, account.id);
                signed_pre_key.insert()
                    .value(signed_pre_key.account_id, account.id)
                    .value(signed_pre_key.key_id, key_id)
                    .value(signed_pre_key.public_base64, bytes_to_base64(spk_pub))
                    .value(signed_pre_key.private_base64, bytes_to_base64(spk_priv))
                    .value(signed_pre_key.signature_ed25519_base64, bytes_to_base64(spk_sig_ed25519))
                    .value(signed_pre_key.signature_mldsa_base64, bytes_to_base64(spk_sig_mldsa))
                    .value(signed_pre_key.published, false)
                    .value(signed_pre_key.created_at, (long) new DateTime.now_utc().to_unix())
                    .perform();

                bundle.upsert()
                    .value(bundle.account_id, account.id, true)
                    .value(bundle.bare_jid, account.bare_jid.to_string(), true)
                    .value(bundle.device_id, row[account_identity.device_id], true)
                    .value(bundle.aik_pub_ed25519_base64, row[account_identity.aik_pub_ed25519_base64])
                    .value(bundle.aik_pub_mldsa_base64, row[account_identity.aik_pub_mldsa_base64])
                    .value(bundle.identity_pub_ed25519_base64, row[account_identity.dik_pub_ed25519_base64])
                    .value(bundle.identity_pub_x25519_base64, row[account_identity.dik_pub_x25519_base64])
                    .value(bundle.identity_pub_mldsa_base64, row[account_identity.dik_pub_mldsa_base64])
                    .value(bundle.signed_pre_key_id, key_id)
                    .value(bundle.signed_pre_key_public_base64, bytes_to_base64(spk_pub))
                    .value(bundle.signed_pre_key_signature_ed25519_base64, bytes_to_base64(spk_sig_ed25519))
                    .value(bundle.signed_pre_key_signature_mldsa_base64, bytes_to_base64(spk_sig_mldsa))
                    .value(bundle.device_certificate_base64, cert)
                    .value(bundle.updated_at, (long) new DateTime.now_utc().to_unix())
                    .perform();
            }

            while (count_kem_pre_keys(account) < 5) {
                Bytes kem_pub;
                Bytes kem_priv;
                global::X3dhpq.Crypto.generate_mlkem768(out kem_pub, out kem_priv);
                kem_pre_key.insert()
                    .value(kem_pre_key.account_id, account.id)
                    .value(kem_pre_key.key_id, next_key_id(kem_pre_key, kem_pre_key.account_id, kem_pre_key.key_id, account.id))
                    .value(kem_pre_key.public_base64, bytes_to_base64(kem_pub))
                    .value(kem_pre_key.private_base64, bytes_to_base64(kem_priv))
                    .value(kem_pre_key.published, false)
                    .value(kem_pre_key.consumed, false)
                    .value(kem_pre_key.created_at, (long) new DateTime.now_utc().to_unix())
                    .perform();
            }

            while (count_one_time_pre_keys(account) < 10) {
                Bytes opk_pub;
                Bytes opk_priv;
                global::X3dhpq.Crypto.generate_x25519(out opk_pub, out opk_priv);
                one_time_pre_key.insert()
                    .value(one_time_pre_key.account_id, account.id)
                    .value(one_time_pre_key.key_id, next_key_id(one_time_pre_key, one_time_pre_key.account_id, one_time_pre_key.key_id, account.id))
                    .value(one_time_pre_key.public_base64, bytes_to_base64(opk_pub))
                    .value(one_time_pre_key.private_base64, bytes_to_base64(opk_priv))
                    .value(one_time_pre_key.published, false)
                    .value(one_time_pre_key.consumed, false)
                    .value(one_time_pre_key.created_at, (long) new DateTime.now_utc().to_unix())
                    .perform();
            }
        } catch (GLib.Error e) {
            warning("Unable to initialize x3dhpq prekeys for %s: %s", account.bare_jid.to_string(), e.message);
        }
    }

    public Row? get_local_bundle(Account account) {
        int? device_id = get_local_device_id(account);
        if (device_id == null) {
            return null;
        }
        return bundle.select()
            .with(bundle.account_id, "=", account.id)
            .with(bundle.bare_jid, "=", account.bare_jid.to_string())
            .with(bundle.device_id, "=", (!) device_id)
            .single().row().inner;
    }

    public Row get_required_local_bundle(Account account) {
        Row? row = get_local_bundle(account);
        assert(row != null);
        return (!) row;
    }

    public string get_local_identity_string(Account account, Column<string> column) {
        return get_required_local_identity(account)[column];
    }

    public Bytes get_local_identity_bytes(Account account, Column<string> column) {
        return bytes_from_base64(get_required_local_identity(account)[column]);
    }

    public Protocol.DeviceCertificate? get_local_device_certificate(Account account) {
        Row bundle_row = get_required_local_bundle(account);
        string? encoded = bundle_row[bundle.device_certificate_base64];
        return encoded != null ? Protocol.DeviceCertificate.unmarshal(bytes_from_base64(encoded)) : null;
    }

    public Gee.List<Row> get_local_kem_pre_keys(Account account) {
        Gee.ArrayList<Row> rows = new Gee.ArrayList<Row>();
        RowIterator iterator = kem_pre_key.select().with(kem_pre_key.account_id, "=", account.id).iterator();
        Row? row;
        while ((row = iterator.get_next()) != null) {
            rows.add((!) row);
        }
        return rows;
    }

    public Row? get_local_signed_pre_key(Account account, int key_id) {
        return signed_pre_key.select()
            .with(signed_pre_key.account_id, "=", account.id)
            .with(signed_pre_key.key_id, "=", key_id)
            .single().row().inner;
    }

    public Row? get_local_kem_pre_key(Account account, int key_id) {
        return kem_pre_key.select()
            .with(kem_pre_key.account_id, "=", account.id)
            .with(kem_pre_key.key_id, "=", key_id)
            .single().row().inner;
    }

    public Row? get_local_one_time_pre_key(Account account, int key_id) {
        return one_time_pre_key.select()
            .with(one_time_pre_key.account_id, "=", account.id)
            .with(one_time_pre_key.key_id, "=", key_id)
            .single().row().inner;
    }

    public void mark_local_one_time_pre_key_consumed(Account account, int key_id) {
        one_time_pre_key.update()
            .with(one_time_pre_key.account_id, "=", account.id)
            .with(one_time_pre_key.key_id, "=", key_id)
            .set(one_time_pre_key.consumed, true)
            .perform();
    }

    public bool has_remote_device_list(Account account, string bare_jid) {
        return device_list.select()
            .with(device_list.account_id, "=", account.id)
            .with(device_list.bare_jid, "=", bare_jid)
            .single().row().is_present();
    }

    public Gee.List<int> get_remote_device_ids(Account account, string bare_jid) {
        Gee.ArrayList<int> devices = new Gee.ArrayList<int>();
        foreach (Row row in peer_device.select()
            .with(peer_device.account_id, "=", account.id)
            .with(peer_device.bare_jid, "=", bare_jid)
            .with(peer_device.active, "=", true)) {
            devices.add(row[peer_device.device_id]);
        }
        return devices;
    }

    // §10.6.3: device ids seen in a signed, version-valid OWN devicelist that
    // are NOT (yet) covered by a chain-verified AddDevice audit entry. Stored
    // by parse_device_list's is_self branch with peer_device.active=false
    // (store_remote_device's `active` parameter) precisely so they stay
    // queryable here without ever being treated as trusted by
    // get_remote_device_ids / get_device_list_devices (both filter
    // active=true). Surfaced by the devices-list UI as a pending/unconfirmed
    // security event per §10.6.3 rather than silently dropped.
    public Gee.List<int> get_pending_own_device_ids(Account account) {
        Gee.ArrayList<int> devices = new Gee.ArrayList<int>();
        string own_jid = account.bare_jid.to_string();
        foreach (Row row in peer_device.select()
            .with(peer_device.account_id, "=", account.id)
            .with(peer_device.bare_jid, "=", own_jid)
            .with(peer_device.active, "=", false)) {
            devices.add(row[peer_device.device_id]);
        }
        return devices;
    }

    public void store_session(Account account, string bare_jid, int device_id, Protocol.SessionState state) {
        pairwise_session.upsert()
            .value(pairwise_session.account_id, account.id, true)
            .value(pairwise_session.bare_jid, bare_jid, true)
            .value(pairwise_session.device_id, device_id, true)
            .value(pairwise_session.session_state_base64, Base64.encode(string_to_bytes(state.serialize())))
            .value(pairwise_session.created_at, (long) new DateTime.now_utc().to_unix())
            .value(pairwise_session.updated_at, (long) new DateTime.now_utc().to_unix())
            .perform();
    }

    public void delete_session(Account account, string bare_jid, int device_id) {
        pairwise_session.delete()
            .with(pairwise_session.account_id, "=", account.id)
            .with(pairwise_session.bare_jid, "=", bare_jid)
            .with(pairwise_session.device_id, "=", device_id)
            .perform();
    }

    // One-shot recovery hook — drop every pairwise session for this account
    // so the next outgoing pairwise message re-bootstraps via a prekey
    // envelope. Used to recover from a peer that wiped its own session
    // store: with no peer-side session, our cached session can't be
    // decoded by the peer, leaving group sender-chain announcements
    // stranded.
    public int wipe_all_sessions(Account account) {
        int n = (int) pairwise_session.select()
            .with(pairwise_session.account_id, "=", account.id)
            .count();
        pairwise_session.delete()
            .with(pairwise_session.account_id, "=", account.id)
            .perform();
        return n;
    }

    public Protocol.SessionState? get_session(Account account, string bare_jid, int device_id) {
        Row? row = pairwise_session.select()
            .with(pairwise_session.account_id, "=", account.id)
            .with(pairwise_session.bare_jid, "=", bare_jid)
            .with(pairwise_session.device_id, "=", device_id)
            .single().row().inner;
        if (row == null || ((!) row)[pairwise_session.session_state_base64] == null) {
            return null;
        }
        uint8[] decoded = Base64.decode(((!) row)[pairwise_session.session_state_base64]);
        string serialized = (string) decoded;
        return Protocol.SessionState.deserialize(serialized);
    }

    public Protocol.PeerBundle? get_remote_bundle(Account account, string bare_jid, int device_id) {
        Row? row = bundle.select()
            .with(bundle.account_id, "=", account.id)
            .with(bundle.bare_jid, "=", bare_jid)
            .with(bundle.device_id, "=", device_id)
            .single().row().inner;
        if (row == null) {
            return null;
        }
        string? aik_ed = ((!) row)[bundle.aik_pub_ed25519_base64];
        string? aik_m = ((!) row)[bundle.aik_pub_mldsa_base64];
        string? cert = ((!) row)[bundle.device_certificate_base64];
        string? ik = ((!) row)[bundle.identity_pub_x25519_base64];
        string? spk = ((!) row)[bundle.signed_pre_key_public_base64];
        string? spk_sig = ((!) row)[bundle.signed_pre_key_signature_ed25519_base64];
        if (aik_ed == null || aik_m == null || cert == null || ik == null || spk == null || spk_sig == null) {
            return null;
        }

        Protocol.DeviceCertificate? device_certificate = Protocol.DeviceCertificate.unmarshal(bytes_from_base64(cert));
        if (device_certificate == null) {
            return null;
        }

        Protocol.PeerBundle peer_bundle = new Protocol.PeerBundle();
        peer_bundle.bare_jid = bare_jid;
        peer_bundle.device_id = (uint32) device_id;
        peer_bundle.aik_pub_ed25519_base64 = aik_ed;
        peer_bundle.aik_pub_mldsa_base64 = aik_m;
        peer_bundle.device_certificate = device_certificate;
        // Use the device certificate as the canonical remote device identity.
        // If the published <ik/> field ever drifts from the certified DIK, the
        // initiator and responder derive different X3DH secrets.
        peer_bundle.identity_pub_x25519_base64 = bytes_to_base64(device_certificate.dik_pub_x25519);
        peer_bundle.signed_pre_key_id = (uint32) ((!) row)[bundle.signed_pre_key_id];
        peer_bundle.signed_pre_key_base64 = spk;
        peer_bundle.signed_pre_key_signature_base64 = spk_sig;
        populate_public_prekeys(peer_bundle.kem_pre_keys, ((!) row)[bundle.kem_pre_keys_base64]);
        populate_public_prekeys(peer_bundle.one_time_pre_keys, ((!) row)[bundle.one_time_pre_keys_base64]);
        return peer_bundle;
    }

    public Row? get_peer_account_identity_row(Account account, string bare_jid) {
        return peer_account_identity.select()
            .with(peer_account_identity.account_id, "=", account.id)
            .with(peer_account_identity.bare_jid, "=", bare_jid)
            .single().row().inner;
    }

    public int get_session_count(Account account, string bare_jid) {
        return (int) pairwise_session.select()
            .with(pairwise_session.account_id, "=", account.id)
            .with(pairwise_session.bare_jid, "=", bare_jid)
            .count();
    }

    // Find a peer's AIK pub halves by matching the raw 20-byte BLAKE2b-160
    // fingerprint of the canonical (version | hasMldsa | ed25519 | mldsa)
    // serialisation. Used to TOFU-bootstrap the room owner's identity from a
    // membership-journal AddMember entry's payload.
    public bool find_peer_account_identity_by_aik_fp(Account account, uint8[] aik_fp_raw_20,
            out uint8[] out_aik_ed, out uint8[] out_aik_mldsa) {
        out_aik_ed = {};
        out_aik_mldsa = {};
        if (aik_fp_raw_20.length != 20) return false;
        var rows = peer_account_identity.select()
            .with(peer_account_identity.account_id, "=", account.id);
        foreach (Row r in rows) {
            string? ed_b64 = r[peer_account_identity.aik_pub_ed25519_base64];
            string? ml_b64 = r[peer_account_identity.aik_pub_mldsa_base64];
            if (ed_b64 == null || ml_b64 == null) continue;
            try {
                Bytes ed = bytes_from_base64(ed_b64);
                Bytes ml = bytes_from_base64(ml_b64);
                uint8[] ed_arr = bytes_to_uint8_array(ed);
                uint8[] ml_arr = bytes_to_uint8_array(ml);
                // canonical: 0x00 0x01 0x01 | ed25519(32) | mldsa
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

    // Reverse lookup: given a raw 20-byte AIK fingerprint, return the peer's
    // bare JID (or null). Used to resolve journal member fingerprints to JIDs so
    // the sender-chain / group-sync broadcast can reach every crypto member,
    // not only those currently cached as MUC occupants.
    public string? find_peer_jid_by_aik_fp(Account account, uint8[] aik_fp_raw_20) {
        if (aik_fp_raw_20.length != 20) return null;
        var rows = peer_account_identity.select()
            .with(peer_account_identity.account_id, "=", account.id);
        foreach (Row r in rows) {
            string? ed_b64 = r[peer_account_identity.aik_pub_ed25519_base64];
            string? ml_b64 = r[peer_account_identity.aik_pub_mldsa_base64];
            if (ed_b64 == null || ml_b64 == null) continue;
            try {
                uint8[] ed_arr = bytes_to_uint8_array(bytes_from_base64(ed_b64));
                uint8[] ml_arr = bytes_to_uint8_array(bytes_from_base64(ml_b64));
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
                if (match) return r[peer_account_identity.bare_jid];
            } catch (Error e) {
                continue;
            }
        }
        // Fallback: the peer's AIK may only be cached in the bundle table (from a
        // 1:1 bundle fetch) and not yet mirrored into peer_account_identity.
        var brows = bundle.select().with(bundle.account_id, "=", account.id);
        foreach (Row r in brows) {
            string? ed_b64 = r[bundle.aik_pub_ed25519_base64];
            string? ml_b64 = r[bundle.aik_pub_mldsa_base64];
            if (ed_b64 == null || ml_b64 == null) continue;
            try {
                uint8[] ed_arr = bytes_to_uint8_array(bytes_from_base64(ed_b64));
                uint8[] ml_arr = bytes_to_uint8_array(bytes_from_base64(ml_b64));
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
                if (match) return r[bundle.bare_jid];
            } catch (Error e) {
                continue;
            }
        }
        return null;
    }

    public string? get_peer_aik_fingerprint(Account account, string bare_jid) {
        Row? row = get_peer_account_identity_row(account, bare_jid);
        if (row == null || ((!) row)[peer_account_identity.aik_pub_ed25519_base64] == null || ((!) row)[peer_account_identity.aik_pub_mldsa_base64] == null) {
            return null;
        }
        try {
            return account_fingerprint(
                bytes_from_base64(((!) row)[peer_account_identity.aik_pub_ed25519_base64]),
                bytes_from_base64(((!) row)[peer_account_identity.aik_pub_mldsa_base64])
            );
        } catch (Error e) {
            warning("Unable to compute x3dhpq peer fingerprint for %s: %s", bare_jid, e.message);
            return null;
        }
    }

    // Fetch a peer's AIK public halves (raw bytes) by bare JID. Returns false if
    // the peer AIK is not yet known (first contact — caller should defer the
    // devicelist signature gate per §8.5).
    public bool get_peer_aik_pubs(Account account, string bare_jid, out Bytes aik_ed, out Bytes aik_mldsa) {
        aik_ed = new Bytes(new uint8[0]);
        aik_mldsa = new Bytes(new uint8[0]);
        Row? row = get_peer_account_identity_row(account, bare_jid);
        if (row == null || ((!) row)[peer_account_identity.aik_pub_ed25519_base64] == null || ((!) row)[peer_account_identity.aik_pub_mldsa_base64] == null) {
            return false;
        }
        try {
            aik_ed = bytes_from_base64(((!) row)[peer_account_identity.aik_pub_ed25519_base64]);
            aik_mldsa = bytes_from_base64(((!) row)[peer_account_identity.aik_pub_mldsa_base64]);
            return true;
        } catch (GLib.Error e) {
            return false;
        }
    }

    public bool get_peer_aik_fingerprint_raw(Account account, string bare_jid, out uint8[] fingerprint_raw) {
        fingerprint_raw = {};
        Row? row = get_peer_account_identity_row(account, bare_jid);
        if (row == null || ((!) row)[peer_account_identity.aik_pub_ed25519_base64] == null || ((!) row)[peer_account_identity.aik_pub_mldsa_base64] == null) {
            return false;
        }
        try {
            Bytes ed25519 = bytes_from_base64(((!) row)[peer_account_identity.aik_pub_ed25519_base64]);
            Bytes mldsa = bytes_from_base64(((!) row)[peer_account_identity.aik_pub_mldsa_base64]);
            uint8[] ed25519_arr = bytes_to_uint8_array(ed25519);
            uint8[] mldsa_arr = bytes_to_uint8_array(mldsa);
            uint8[] encoded = new uint8[3 + ed25519_arr.length + mldsa_arr.length];
            encoded[0] = 0;
            encoded[1] = 1;
            encoded[2] = 1;
            Memory.copy((uint8*) encoded + 3, ed25519_arr, ed25519_arr.length);
            Memory.copy((uint8*) encoded + 3 + ed25519_arr.length, mldsa_arr, mldsa_arr.length);
            Bytes digest = global::X3dhpq.Crypto.blake2b160(new Bytes(encoded));
            fingerprint_raw = bytes_to_uint8_array(digest);
            return true;
        } catch (GLib.Error e) {
            warning("Unable to compute raw x3dhpq peer fingerprint for %s: %s", bare_jid, e.message);
            return false;
        }
    }

    public Gee.List<Row> get_local_one_time_pre_keys(Account account) {
        Gee.ArrayList<Row> rows = new Gee.ArrayList<Row>();
        RowIterator iterator = one_time_pre_key.select().with(one_time_pre_key.account_id, "=", account.id).iterator();
        Row? row;
        while ((row = iterator.get_next()) != null) {
            rows.add((!) row);
        }
        return rows;
    }

    public void mark_local_bundle_published(Account account) {
        signed_pre_key.update()
            .with(signed_pre_key.account_id, "=", account.id)
            .set(signed_pre_key.published, true)
            .perform();
        kem_pre_key.update()
            .with(kem_pre_key.account_id, "=", account.id)
            .set(kem_pre_key.published, true)
            .perform();
        one_time_pre_key.update()
            .with(one_time_pre_key.account_id, "=", account.id)
            .set(one_time_pre_key.published, true)
            .perform();
    }

    public void store_device_list_payload(Account account, string bare_jid, string? item_id, string payload,
            long list_version = -1, bool signed_accepted = false, string? content_key = null) {
        // Preserve the current version/signed flag/content_key when the caller
        // passes the sentinels so legacy call sites that do not track versioning
        // do not clobber the columns.
        long effective_version = list_version;
        bool effective_signed = signed_accepted;
        string? effective_content_key = content_key;
        RowOption existing = device_list.select()
            .with(device_list.account_id, "=", account.id)
            .with(device_list.bare_jid, "=", bare_jid)
            .single().row();
        if (existing.is_present()) {
            if (list_version < 0) {
                effective_version = existing[device_list.list_version];
            }
            // signed_accepted is sticky: once a signed list has been accepted for
            // this jid it MUST stay accepted (downgrade protection §8.5).
            if (existing[device_list.signed_accepted]) {
                effective_signed = true;
            }
            if (content_key == null) {
                effective_content_key = existing[device_list.content_key];
            }
        } else if (list_version < 0) {
            effective_version = 0;
        }
        device_list.upsert()
            .value(device_list.account_id, account.id, true)
            .value(device_list.bare_jid, bare_jid, true)
            .value(device_list.item_id, item_id)
            .value(device_list.signed_payload_base64, Base64.encode(string_to_bytes(payload)))
            .value(device_list.updated_at, (long) new DateTime.now_utc().to_unix())
            .value(device_list.list_version, effective_version)
            .value(device_list.signed_accepted, effective_signed)
            .value(device_list.content_key, effective_content_key)
            .perform();
    }

    public string? get_device_list_content_key(Account account, string bare_jid) {
        RowOption row = get_device_list_row(account, bare_jid);
        if (!row.is_present()) {
            return null;
        }
        return row[device_list.content_key];
    }

    public RowOption get_device_list_row(Account account, string bare_jid) {
        return device_list.select()
            .with(device_list.account_id, "=", account.id)
            .with(device_list.bare_jid, "=", bare_jid)
            .single().row();
    }

    // Decoded devicelist XML previously stored for (account, bare_jid), or null.
    public string? get_device_list_payload_xml(Account account, string bare_jid) {
        RowOption row = get_device_list_row(account, bare_jid);
        if (!row.is_present()) {
            return null;
        }
        string? b64 = row[device_list.signed_payload_base64];
        if (b64 == null) {
            return null;
        }
        return (string) Base64.decode((!) b64);
    }

    public long get_device_list_version(Account account, string bare_jid) {
        RowOption row = get_device_list_row(account, bare_jid);
        if (!row.is_present()) {
            return 0;
        }
        return row[device_list.list_version];
    }

    // ── Trust Manifest (Phase 2) persistence ─────────────────────────────────

    private RowOption get_trust_manifest_row(Account account, string bare_jid) {
        return trust_manifest.select()
            .with(trust_manifest.account_id, "=", account.id)
            .with(trust_manifest.bare_jid, "=", bare_jid)
            .single().row();
    }

    // Highest accepted manifest version for owner bare_jid, or -1 if none seen.
    public long get_trust_manifest_version(Account account, string bare_jid) {
        RowOption row = get_trust_manifest_row(account, bare_jid);
        if (!row.is_present()) return -1;
        return row[trust_manifest.manifest_version];
    }

    // SHA-256(m.marshal()) hex of the last accepted manifest at the stored
    // version (equivocation/fork guard), or null if none.
    public string? get_trust_manifest_blob_hash(Account account, string bare_jid) {
        RowOption row = get_trust_manifest_row(account, bare_jid);
        if (!row.is_present()) return null;
        return row[trust_manifest.blob_hash_hex];
    }

    // base64(m.marshal()) of the last accepted manifest for owner bare_jid, or
    // null if none — used to extend/adopt the current manifest.
    public string? get_trust_manifest_payload(Account account, string bare_jid) {
        RowOption row = get_trust_manifest_row(account, bare_jid);
        if (!row.is_present()) return null;
        return row[trust_manifest.payload_base64];
    }

    // Trust Manifest Phase 2 (task #54): is the LOCAL device a trusted member —
    // i.e. present in the current OWN manifest fold — and therefore able to author
    // DIK-signed edits such as a REVOKE? This is the manifest-model authorization
    // for revoke, which needs only fold membership + this device's DIK, NOT
    // AIK_priv. Falls back to the legacy is_authorized() gate when no manifest
    // exists yet (pre-migration), so behaviour is unchanged before migration.
    // Never throws.
    public bool is_local_device_trusted_member(Account account) {
        int? local_id = get_local_device_id(account);
        if (local_id == null) return false;
        string own_bare = account.bare_jid.to_string();
        string? payload = get_trust_manifest_payload(account, own_bare);
        if (payload != null) {
            Protocol.TrustManifest? m = Protocol.TrustManifest.unmarshal(Base64.decode((!) payload));
            if (m != null) {
                var fold = ((!) m).fold();
                return fold.has_key(((uint32) ((!) local_id)).to_string());
            }
        }
        // No manifest yet — legacy co-account/devicelist membership gate.
        return is_authorized(account);
    }

    public void store_trust_manifest(Account account, string bare_jid, string? item_id,
            string payload_base64, long version, string blob_hash_hex) {
        trust_manifest.upsert()
            .value(trust_manifest.account_id, account.id, true)
            .value(trust_manifest.bare_jid, bare_jid, true)
            .value(trust_manifest.item_id, item_id)
            .value(trust_manifest.payload_base64, payload_base64)
            .value(trust_manifest.manifest_version, version)
            .value(trust_manifest.blob_hash_hex, blob_hash_hex)
            .value(trust_manifest.updated_at, (long) new DateTime.now_utc().to_unix())
            .perform();
    }

    // First-use (TOFU) pin of a peer's account AIK from a trust manifest: only
    // writes when NO AIK is currently pinned for this peer. Never overwrites an
    // existing pin (an AIK swap is handled as a rejection by the caller, not a
    // silent re-pin). Returns true if the peer now has this AIK pinned.
    public bool pin_peer_aik_first_use(Account account, string bare_jid, uint8[] aik_ed, uint8[] aik_ml) {
        Bytes cur_ed, cur_ml;
        if (get_peer_aik_pubs(account, bare_jid, out cur_ed, out cur_ml)) {
            return true; // already pinned — do not touch
        }
        string ed_b64 = Base64.encode(aik_ed);
        string ml_b64 = Base64.encode(aik_ml);
        string? fingerprint = null;
        try {
            fingerprint = account_fingerprint(new Bytes(aik_ed), new Bytes(aik_ml));
        } catch (Error e) {
            warning("pin_peer_aik_first_use: fingerprint failed for %s: %s", bare_jid, e.message);
        }
        Row? existing = get_peer_account_identity_row(account, bare_jid);
        long created_at = existing != null ? ((!) existing)[peer_account_identity.created_at] : (long) new DateTime.now_utc().to_unix();
        peer_account_identity.upsert()
            .value(peer_account_identity.account_id, account.id, true)
            .value(peer_account_identity.bare_jid, bare_jid, true)
            .value(peer_account_identity.aik_pub_ed25519_base64, ed_b64)
            .value(peer_account_identity.aik_pub_mldsa_base64, ml_b64)
            .value(peer_account_identity.aik_fingerprint, fingerprint)
            .value(peer_account_identity.trust_state, existing != null ? ((!) existing)[peer_account_identity.trust_state] : "unverified")
            .value(peer_account_identity.downgraded, existing != null ? ((!) existing)[peer_account_identity.downgraded] : false)
            .value(peer_account_identity.created_at, created_at)
            .value(peer_account_identity.updated_at, (long) new DateTime.now_utc().to_unix())
            .perform();
        return true;
    }

    public bool get_device_list_signed_accepted(Account account, string bare_jid) {
        RowOption row = get_device_list_row(account, bare_jid);
        if (!row.is_present()) {
            return false;
        }
        return row[device_list.signed_accepted];
    }

    // Drop every cached peer_device / bundle / pairwise_session row for
    // (account, bare_jid) whose device id is NOT in keep_ids. Mirrors the
    // Conversations-side prune so that when Conversations regenerates
    // identity (resulting in a brand-new device id) we stop addressing
    // pairwise envelopes — and group sender-chain announcements — to
    // device ids that no longer exist on the peer.
    public void prune_remote_devices_not_in(Account account, string bare_jid, Gee.Collection<int> keep_ids) {
        // Snapshot existing rows then drop the stragglers individually.
        Gee.ArrayList<int> all = new Gee.ArrayList<int>();
        var rows = peer_device.select()
            .with(peer_device.account_id, "=", account.id)
            .with(peer_device.bare_jid, "=", bare_jid);
        foreach (Row r in rows) {
            all.add(r[peer_device.device_id]);
        }
        foreach (int existing in all) {
            if (keep_ids.contains(existing)) continue;
            peer_device.delete()
                .with(peer_device.account_id, "=", account.id)
                .with(peer_device.bare_jid, "=", bare_jid)
                .with(peer_device.device_id, "=", existing)
                .perform();
            bundle.delete()
                .with(bundle.account_id, "=", account.id)
                .with(bundle.bare_jid, "=", bare_jid)
                .with(bundle.device_id, "=", existing)
                .perform();
            pairwise_session.delete()
                .with(pairwise_session.account_id, "=", account.id)
                .with(pairwise_session.bare_jid, "=", bare_jid)
                .with(pairwise_session.device_id, "=", existing)
                .perform();
        }
    }

    // Locally remove a single peer-device entry (and its bundle/session) for
    // (account, bare_jid). Used by the self-devices "Remove" UX; does NOT
    // republish a versioned devicelist. Caller is responsible for pruning the
    // local device id from any subsequent devicelist re-publish.
    public void remove_peer_device(Account account, string bare_jid, int device_id) {
        peer_device.delete()
            .with(peer_device.account_id, "=", account.id)
            .with(peer_device.bare_jid, "=", bare_jid)
            .with(peer_device.device_id, "=", device_id)
            .perform();
        bundle.delete()
            .with(bundle.account_id, "=", account.id)
            .with(bundle.bare_jid, "=", bare_jid)
            .with(bundle.device_id, "=", device_id)
            .perform();
        pairwise_session.delete()
            .with(pairwise_session.account_id, "=", account.id)
            .with(pairwise_session.bare_jid, "=", bare_jid)
            .with(pairwise_session.device_id, "=", device_id)
            .perform();
    }

    // Remove a single device from the account's OWN persisted device set: the
    // peer_device row stored under our own bare JID that publish_device_list
    // unions from. Used by the §8.6 revocation path so the rebuilt union — and
    // therefore the next signed devicelist — no longer lists the removed id.
    // Mirrors remove_peer_device but scoped to the account's own JID and limited
    // to the peer_device row (bundle/session teardown is handled separately).
    public void delete_own_device(Account account, uint32 device_id) {
        peer_device.delete()
            .with(peer_device.account_id, "=", account.id)
            .with(peer_device.bare_jid, "=", account.bare_jid.to_string())
            .with(peer_device.device_id, "=", (int) device_id)
            .perform();
    }

    public void forget_peer(Account account, string bare_jid) {
        device_list.delete()
            .with(device_list.account_id, "=", account.id)
            .with(device_list.bare_jid, "=", bare_jid)
            .perform();
        peer_account_identity.delete()
            .with(peer_account_identity.account_id, "=", account.id)
            .with(peer_account_identity.bare_jid, "=", bare_jid)
            .perform();
        peer_device.delete()
            .with(peer_device.account_id, "=", account.id)
            .with(peer_device.bare_jid, "=", bare_jid)
            .perform();
        bundle.delete()
            .with(bundle.account_id, "=", account.id)
            .with(bundle.bare_jid, "=", bare_jid)
            .perform();
        pairwise_session.delete()
            .with(pairwise_session.account_id, "=", account.id)
            .with(pairwise_session.bare_jid, "=", bare_jid)
            .perform();
    }

    // Mark the peer's CURRENTLY-OBSERVED AIK as user-verified (re-pinned). Clears
    // the `downgraded`/rotated flag. Called only from the explicit user "accept
    // identity" action (contact details), after the user has reviewed the new
    // fingerprint — never automatically, so a server-substituted AIK cannot be
    // silently trusted.
    public void set_peer_aik_verified(Account account, string bare_jid) {
        Row? existing = get_peer_account_identity_row(account, bare_jid);
        if (existing == null) return;
        peer_account_identity.update()
            .with(peer_account_identity.account_id, "=", account.id)
            .with(peer_account_identity.bare_jid, "=", bare_jid)
            .set(peer_account_identity.trust_state, "verified")
            .set(peer_account_identity.downgraded, false)
            .set(peer_account_identity.updated_at, (long) new DateTime.now_utc().to_unix())
            .perform();
    }

    // Reset the devicelist/version rollback state and stale device/bundle/session
    // rows for a peer WITHOUT forgetting its (new) AIK identity. After a peer
    // legitimately resets (fresh install → version restarts at 1, which the
    // rollback guard (§8.5) would otherwise reject), this lets the fresh signed
    // devicelist be re-accepted on the next fetch. Keeps peer_account_identity so
    // the just-accepted AIK survives.
    public void reset_peer_devicelist(Account account, string bare_jid) {
        device_list.delete()
            .with(device_list.account_id, "=", account.id)
            .with(device_list.bare_jid, "=", bare_jid)
            .perform();
        peer_device.delete()
            .with(peer_device.account_id, "=", account.id)
            .with(peer_device.bare_jid, "=", bare_jid)
            .perform();
        bundle.delete()
            .with(bundle.account_id, "=", account.id)
            .with(bundle.bare_jid, "=", bare_jid)
            .perform();
        pairwise_session.delete()
            .with(pairwise_session.account_id, "=", account.id)
            .with(pairwise_session.bare_jid, "=", bare_jid)
            .perform();
    }

    public void store_remote_device(Account account, string bare_jid, int device_id, string? certificate_base64 = null, long added_at = 0, uint8 flags = 1, bool active = true) {
        // Preserve the earliest known added_at (first-seen) for this device id:
        // once a peer has published a device with a given added_at we keep it so
        // the reconstructed SignedPart stays stable even if a later republish
        // (mistakenly) carries a different value.
        long effective_added_at = added_at;
        RowOption existing = peer_device.select()
            .with(peer_device.account_id, "=", account.id)
            .with(peer_device.bare_jid, "=", bare_jid)
            .with(peer_device.device_id, "=", device_id)
            .single().row();
        if (existing.is_present()) {
            long prev = existing[peer_device.added_at];
            if (prev > 0) {
                effective_added_at = prev;
            }
        }
        peer_device.upsert()
            .value(peer_device.account_id, account.id, true)
            .value(peer_device.bare_jid, bare_jid, true)
            .value(peer_device.device_id, device_id, true)
            .value(peer_device.certificate_base64, certificate_base64)
            .value(peer_device.active, active)
            .value(peer_device.updated_at, (long) new DateTime.now_utc().to_unix())
            .value(peer_device.created_at, (long) new DateTime.now_utc().to_unix())
            .value(peer_device.added_at, effective_added_at)
            .value(peer_device.flags, (int) flags)
            .perform();
    }

    // Every persisted device row for a bare_jid, as full DeviceListDevice
    // records (id, added_at, flags, cert_bytes). Used by publish_device_list
    // to reconstruct the account's own multi-device union (§8.2/§8.3): when
    // this device has previously accepted the account's own signed devicelist
    // (is_self branch of parse_device_list, which persists every entry via
    // store_remote_device under the account's bare JID), those rows let a
    // routine republish include co-account devices instead of shrinking the
    // list back down to this device alone. A row whose certificate was never
    // persisted yields empty cert_bytes; callers MUST skip such rows since an
    // uncertified device cannot be safely re-emitted on a signed list.
    public Gee.List<Protocol.DeviceListDevice> get_device_list_devices(Account account, string bare_jid) {
        var result = new Gee.ArrayList<Protocol.DeviceListDevice>();
        foreach (Row row in peer_device.select()
                .with(peer_device.account_id, "=", account.id)
                .with(peer_device.bare_jid, "=", bare_jid)
                .with(peer_device.active, "=", true)) {
            var d = new Protocol.DeviceListDevice();
            d.device_id = (uint32) row[peer_device.device_id];
            d.added_at = row[peer_device.added_at];
            d.flags = (uint8) row[peer_device.flags];
            string? cert_b64 = row[peer_device.certificate_base64];
            try {
                d.cert_bytes = cert_b64 != null ? bytes_to_uint8_array(bytes_from_base64(cert_b64)) : new uint8[0];
            } catch (GLib.Error e) {
                d.cert_bytes = new uint8[0];
            }
            result.add(d);
        }
        return result;
    }

    // First-seen creation time of the local device's own identity (unix
    // seconds). Used as the stable `added_at` for the account's own device on
    // the signed devicelist so routine self-republishes reproduce byte-identical
    // SignedPart bytes (XEP §8.2–§8.4).
    public long get_local_device_created_at(Account account) {
        Row? row = get_local_identity(account.id);
        if (row == null) {
            return (long) new DateTime.now_utc().to_unix();
        }
        return ((!) row)[account_identity.created_at];
    }

    public void store_bundle_payload(Account account, string bare_jid, int device_id, StanzaNode bundle_node) {
        StanzaNode? aik_ed_node = bundle_node.get_subnode("aik-ed25519", Protocol.NS_BUNDLE);
        StanzaNode? aik_mldsa_node = bundle_node.get_subnode("aik-mldsa", Protocol.NS_BUNDLE);
        StanzaNode? dc_node = bundle_node.get_subnode("dc", Protocol.NS_BUNDLE);
        StanzaNode? ik_node = bundle_node.get_subnode("ik", Protocol.NS_BUNDLE);
        StanzaNode? dik_ed_node = bundle_node.get_subnode("dik-ed25519", Protocol.NS_BUNDLE);
        StanzaNode? dik_mldsa_node = bundle_node.get_subnode("dik-mldsa", Protocol.NS_BUNDLE);
        StanzaNode? spk_node = bundle_node.get_subnode("spk", Protocol.NS_BUNDLE);
        string? spk_key = null;
        string? spk_sig = null;
        int spk_id = -1;
        if (spk_node != null) {
            spk_id = spk_node.get_attribute_int("id");
            StanzaNode? spk_key_node = spk_node.get_subnode("key", Protocol.NS_BUNDLE);
            StanzaNode? spk_sig_node = spk_node.get_subnode("sig", Protocol.NS_BUNDLE);
            spk_key = spk_key_node != null ? spk_key_node.get_string_content() : null;
            spk_sig = spk_sig_node != null ? spk_sig_node.get_string_content() : null;
        }

        bundle.upsert()
            .value(bundle.account_id, account.id, true)
            .value(bundle.bare_jid, bare_jid, true)
            .value(bundle.device_id, device_id, true)
            .value(bundle.aik_pub_ed25519_base64, aik_ed_node != null ? aik_ed_node.get_string_content() : null)
            .value(bundle.aik_pub_mldsa_base64, aik_mldsa_node != null ? aik_mldsa_node.get_string_content() : null)
            .value(bundle.identity_pub_ed25519_base64, dik_ed_node != null ? dik_ed_node.get_string_content() : null)
            .value(bundle.identity_pub_x25519_base64, ik_node != null ? ik_node.get_string_content() : null)
            .value(bundle.identity_pub_mldsa_base64, dik_mldsa_node != null ? dik_mldsa_node.get_string_content() : null)
            .value(bundle.signed_pre_key_id, spk_id)
            .value(bundle.signed_pre_key_public_base64, spk_key)
            .value(bundle.signed_pre_key_signature_ed25519_base64, spk_sig)
            .value(bundle.kem_pre_keys_base64, serialize_key_nodes(bundle_node.get_subnode("kemkeys", Protocol.NS_BUNDLE), "kemkey"))
            .value(bundle.one_time_pre_keys_base64, serialize_key_nodes(bundle_node.get_subnode("opks", Protocol.NS_BUNDLE), "opk"))
            .value(bundle.device_certificate_base64, dc_node != null ? dc_node.get_string_content() : null)
            .value(bundle.bundle_payload_base64, Base64.encode(string_to_bytes(bundle_node.to_string())))
            .value(bundle.updated_at, (long) new DateTime.now_utc().to_unix())
            .perform();
        peer_device.upsert()
            .value(peer_device.account_id, account.id, true)
            .value(peer_device.bare_jid, bare_jid, true)
            .value(peer_device.device_id, device_id, true)
            .value(peer_device.dik_pub_ed25519_base64, dik_ed_node != null ? dik_ed_node.get_string_content() : null)
            .value(peer_device.dik_pub_x25519_base64, ik_node != null ? ik_node.get_string_content() : null)
            .value(peer_device.dik_pub_mldsa_base64, dik_mldsa_node != null ? dik_mldsa_node.get_string_content() : null)
            .value(peer_device.certificate_base64, dc_node != null ? dc_node.get_string_content() : null)
            .value(peer_device.active, true)
            .value(peer_device.updated_at, (long) new DateTime.now_utc().to_unix())
            .value(peer_device.created_at, (long) new DateTime.now_utc().to_unix())
            .perform();

        if (aik_ed_node != null || aik_mldsa_node != null) {
            update_peer_identity(
                account,
                bare_jid,
                aik_ed_node != null ? aik_ed_node.get_string_content() : null,
                aik_mldsa_node != null ? aik_mldsa_node.get_string_content() : null
            );
        }
    }

    public string? get_aik_fingerprint(Account account) {
        Row? row = get_local_identity(account.id);
        if (row == null) {
            return null;
        }
        try {
            return account_fingerprint(
                bytes_from_base64(((!) row)[account_identity.aik_pub_ed25519_base64]),
                bytes_from_base64(((!) row)[account_identity.aik_pub_mldsa_base64])
            );
        } catch (GLib.Error e) {
            warning("Unable to compute x3dhpq AIK fingerprint for %s: %s", account.bare_jid.to_string(), e.message);
            return null;
        }
    }

    // Per-device identity fingerprint for a device listed under `bare_jid`
    // (used for the account's own sibling devices in the devices-list UI, §10.6),
    // derived from that device's DIK public keys the same way get_aik_fingerprint
    // derives the account-level fingerprint from the AIK. All devices under one
    // account share a single AIK (§7) — that is the account fingerprint shown
    // prominently once — but each device holds its own DIK, so this value
    // differs per device and lets a user out-of-band-compare a specific device.
    // Returns null if we have not yet learned this device's DIK (e.g. its bundle
    // has not been fetched).
    public string? get_device_fingerprint(Account account, string bare_jid, int device_id) {
        Row? row = peer_device.select()
            .with(peer_device.account_id, "=", account.id)
            .with(peer_device.bare_jid, "=", bare_jid)
            .with(peer_device.device_id, "=", device_id)
            .single().row().inner;
        if (row == null) return null;
        string? dik_ed = ((!) row)[peer_device.dik_pub_ed25519_base64];
        string? dik_ml = ((!) row)[peer_device.dik_pub_mldsa_base64];
        if (dik_ed == null || dik_ml == null) return null;
        try {
            return account_fingerprint(bytes_from_base64((!) dik_ed), bytes_from_base64((!) dik_ml));
        } catch (GLib.Error e) {
            warning("Unable to compute x3dhpq device fingerprint for %s/%d: %s", bare_jid, device_id, e.message);
            return null;
        }
    }

    // §10.6.1 fresh-device gating: a freshly-generated identity NEVER self-claims
    // primary. It always mints device-level material (DIK) plus a throwaway AIK
    // (account_identity's AIK columns are NOT NULL, so unlike PQ's two-table split
    // some AIK bytes must exist locally even before this device is confirmed —
    // this is exactly the "pending-enrollment flag" schema gap; see the WS4 final
    // report's DDL note), but is_primary is left FALSE. Only two paths ever flip
    // it to true: (1) apply_paired_identity, when an existing primary confirms
    // this device via CPace pairing with share_primary=true, or (2) StreamModule's
    // resolve_pending_primary (called once online), which promotes this device's
    // OWN already-generated throwaway identity to primary ONLY after confirming
    // via a live devicelist fetch that NO AIK exists anywhere for this account —
    // i.e. this is genuinely the first device. Until either happens,
    // is_primary=false blocks publish_device_list (§10.6.1 "MUST NOT publish an
    // authoritative devicelist"); publish_bundle is unaffected (a confirmed
    // non-primary device legitimately publishes its own bundle regardless).
    public void ensure_local_identity(Account account) {
        if (has_local_identity(account)) {
            return;
        }
        generate_local_identity_row(account);
    }

    // Shared generation logic for ensure_local_identity (pending, is_primary=false)
    // and mint_fresh_identity (§10.6.4b explicit override; caller sets is_primary
    // afterwards via promote_to_primary once it has minted the row).
    private void generate_local_identity_row(Account account) {
        try {
            Bytes aik_pub_ed25519;
            Bytes aik_priv_ed25519;
            Bytes aik_pub_mldsa;
            Bytes aik_priv_mldsa;
            Bytes dik_pub_ed25519;
            Bytes dik_priv_ed25519;
            Bytes dik_pub_x25519;
            Bytes dik_priv_x25519;
            Bytes dik_pub_mldsa;
            Bytes dik_priv_mldsa;

            global::X3dhpq.Crypto.generate_ed25519(out aik_pub_ed25519, out aik_priv_ed25519);
            global::X3dhpq.Crypto.generate_mldsa65(out aik_pub_mldsa, out aik_priv_mldsa);
            global::X3dhpq.Crypto.generate_ed25519(out dik_pub_ed25519, out dik_priv_ed25519);
            global::X3dhpq.Crypto.generate_x25519(out dik_pub_x25519, out dik_priv_x25519);
            global::X3dhpq.Crypto.generate_mldsa65(out dik_pub_mldsa, out dik_priv_mldsa);

            account_identity.insert()
                .value(account_identity.account_id, account.id)
                .value(account_identity.device_id, build_random_device_id())
                .value(account_identity.is_primary, false)
                .value(account_identity.aik_pub_ed25519_base64, bytes_to_base64(aik_pub_ed25519))
                .value(account_identity.aik_priv_ed25519_base64, bytes_to_base64(aik_priv_ed25519))
                .value(account_identity.aik_pub_mldsa_base64, bytes_to_base64(aik_pub_mldsa))
                .value(account_identity.aik_priv_mldsa_base64, bytes_to_base64(aik_priv_mldsa))
                .value(account_identity.dik_pub_ed25519_base64, bytes_to_base64(dik_pub_ed25519))
                .value(account_identity.dik_priv_ed25519_base64, bytes_to_base64(dik_priv_ed25519))
                .value(account_identity.dik_pub_x25519_base64, bytes_to_base64(dik_pub_x25519))
                .value(account_identity.dik_priv_x25519_base64, bytes_to_base64(dik_priv_x25519))
                .value(account_identity.dik_pub_mldsa_base64, bytes_to_base64(dik_pub_mldsa))
                .value(account_identity.dik_priv_mldsa_base64, bytes_to_base64(dik_priv_mldsa))
                .value(account_identity.created_at, (long) new DateTime.now_utc().to_unix())
                .perform();
        } catch (GLib.Error e) {
            warning("Unable to initialize x3dhpq identity for %s: %s", account.bare_jid.to_string(), e.message);
        }
    }

    // §10.6.4b: explicit, user-chosen "generate a new identity instead" override.
    // Destructive — wipes this device's local AIK/DIK row and mints a brand-new
    // one, becoming primary of a fresh identity. The caller (StreamModule, owned)
    // is responsible for the network-visible side effects (publishing the fresh
    // devicelist so contacts observe a reconstruction event per §10.6.5); this
    // only replaces local key material.
    public void mint_fresh_identity(Account account) {
        account_identity.delete().with(account_identity.account_id, "=", account.id).perform();
        generate_local_identity_row(account);
        promote_to_primary(account);
    }

    // True if this device's local identity is confirmed primary (either
    // genuinely the first device, promoted via promote_to_primary, or paired in
    // with share_primary=true via apply_paired_identity). False while pending
    // (§10.6.1, see ensure_local_identity) AND for a confirmed non-primary/
    // non-shared secondary — both legitimately never self-publish an
    // authoritative devicelist, which is the only thing this flag gates.
    public bool is_local_primary(Account account) {
        Row? row = get_local_identity(account.id);
        if (row == null) return false;
        return ((!) row)[account_identity.is_primary];
    }

    // Trust Manifest Phase 2 account reset (task #55, RESET-only, STRICT): mint a
    // NEW account AIK (ed25519 + ML-DSA-65) while KEEPING this device's DIK and
    // device_id, and mark this device primary/confirmed of the fresh single-device
    // lineage. Unlike mint_fresh_identity (which regenerates the whole identity incl.
    // a new device_id), this preserves device continuity — the fresh Trust Manifest
    // genesis self-issues a NEW genesis DC under the new AIK over the SAME DIK. The
    // caller MUST also invalidate the cached self DC (invalidate_local_device_certificate)
    // so it re-issues under the new AIK, and reset the trust_manifest store
    // (clear_trust_manifest) so the fresh version=1 genesis is accepted.
    public void reset_account_identity_new_aik(Account account) {
        if (!has_local_identity(account)) {
            // No existing identity to rotate — fall back to a full fresh mint.
            mint_fresh_identity(account);
            return;
        }
        try {
            Bytes aik_pub_ed, aik_priv_ed, aik_pub_ml, aik_priv_ml;
            global::X3dhpq.Crypto.generate_ed25519(out aik_pub_ed, out aik_priv_ed);
            global::X3dhpq.Crypto.generate_mldsa65(out aik_pub_ml, out aik_priv_ml);
            account_identity.update()
                .with(account_identity.account_id, "=", account.id)
                .set(account_identity.aik_pub_ed25519_base64, bytes_to_base64(aik_pub_ed))
                .set(account_identity.aik_priv_ed25519_base64, bytes_to_base64(aik_priv_ed))
                .set(account_identity.aik_pub_mldsa_base64, bytes_to_base64(aik_pub_ml))
                .set(account_identity.aik_priv_mldsa_base64, bytes_to_base64(aik_priv_ml))
                .set(account_identity.is_primary, true)
                .set(account_identity.confirmed, true)
                .perform();
        } catch (GLib.Error e) {
            warning("reset_account_identity_new_aik: key generation failed for %s: %s",
                account.bare_jid.to_string(), e.message);
        }
    }

    // Clear the cached self DeviceCertificate for the own account so
    // ensure_local_device_certificate re-issues it under the CURRENT (post-reset,
    // new) AIK instead of returning the stale old-AIK-signed cert.
    public void invalidate_local_device_certificate(Account account) {
        bundle.update()
            .with(bundle.account_id, "=", account.id)
            .with(bundle.bare_jid, "=", account.bare_jid.to_string())
            .set(bundle.device_certificate_base64, null)
            .perform();
    }

    // Reset the Trust Manifest version/blob store for an owner (own account on
    // reset) so a fresh genesis at version=1 under a new AIK is a re-pin event, not
    // a rollback of the old-AIK lineage.
    public void clear_trust_manifest(Account account, string bare_jid) {
        trust_manifest.delete()
            .with(trust_manifest.account_id, "=", account.id)
            .with(trust_manifest.bare_jid, "=", bare_jid)
            .perform();
    }

    // §10.6.1: promotes THIS device's own already-generated (throwaway, pending)
    // identity to genuine primary. Called by StreamModule.resolve_pending_primary
    // ONLY after confirming via a live server round-trip that no AIK exists
    // anywhere for this account yet (i.e. this is genuinely the first device).
    // Idempotent/race-safe: a no-op if this row is already primary (e.g. a
    // concurrent pairing completed first via apply_paired_identity).
    public void promote_to_primary(Account account) {
        if (is_local_primary(account)) {
            return;
        }
        account_identity.update()
            .with(account_identity.account_id, "=", account.id)
            .set(account_identity.is_primary, true)
            .set(account_identity.confirmed, true)
            .perform();
    }

    // §10.6.4 (UX): true while this device's local identity row exists but has
    // not yet been resolved either way (see AccountIdentityTable.confirmed) —
    // i.e. it detected an existing account AIK on first run and is waiting to
    // be confirmed by an existing device via CPace pairing (§10.6.2). False
    // once resolved (genuinely-first-device primary, or a paired-in secondary)
    // and false if no local identity row exists yet at all (nothing to show).
    public bool is_pending_enrollment(Account account) {
        Row? row = get_local_identity(account.id);
        if (row == null) return false;
        return !((!) row)[account_identity.confirmed];
    }

    // Adopt the pairing primary's account identity (AIK) into a new device's
    // account_identity row. ensure_local_identity() already ran on this device
    // and generated its own DIK (kept as-is) plus a throwaway AIK (replaced
    // here, since the account is now bound to the primary's AIK instead).
    //
    // If the primary shared its ML-DSA-65 (and Ed25519) AIK private key
    // (result.aik_priv != null), this device becomes able to self-issue
    // DeviceCertificates for further devices, so it is marked is_primary and
    // the private key material is persisted. Otherwise the account_identity
    // row's aik_priv_* columns are cleared to "" — they are NonNullText and
    // the values ensure_local_identity() generated for the throwaway AIK are
    // now invalid because the AIK public key changed.
    public void apply_paired_identity(Account account, Protocol.PairingResult result) {
        var update = account_identity.update()
            .with(account_identity.account_id, "=", account.id)
            .set(account_identity.device_id, (int) result.cert.device_id)
            .set(account_identity.aik_pub_ed25519_base64, Base64.encode(result.aik_pub.pub_ed25519))
            .set(account_identity.aik_pub_mldsa_base64, Base64.encode(result.aik_pub.pub_mldsa))
            // §10.6.4: pairing completion — success or share_primary=false — always
            // resolves the pending-enrollment window; this device is now a
            // confirmed (primary or secondary) member of the account.
            .set(account_identity.confirmed, true);
        // Trust Manifest Phase 2 (§E1): AIK_priv no longer travels in the issuance
        // payload, so a paired newcomer NEVER adopts it — it is a delegated member
        // whose authority flows from the manifest ADD entry (DIK-signed by the
        // confirmer), not from holding the account root key. Always clear the
        // aik_priv_* columns (NonNullText → "") and mark this device non-primary.
        // result.aik_priv is expected to be null in Phase 2; even if a legacy peer
        // still sent one, we deliberately drop it.
        update
            .set(account_identity.is_primary, false)
            .set(account_identity.aik_priv_ed25519_base64, "")
            .set(account_identity.aik_priv_mldsa_base64, "");
        update.perform();
    }

    // §11.8: true if this device currently holds the account AIK private key
    // material (genuinely primary, or a share_primary=true paired secondary) —
    // i.e. it can sign new devicelist/tracker/audit entries. Used to decide
    // whether a decrypted tracker's (optional) sealed AIK_priv should be
    // adopted (only when we don't already hold it).
    public bool has_local_aik_priv(Account account) {
        Row? row = get_local_identity(account.id);
        if (row == null) return false;
        string? ed = ((!) row)[account_identity.aik_priv_ed25519_base64];
        string? ml = ((!) row)[account_identity.aik_priv_mldsa_base64];
        return ed != null && ed != "" && ml != null && ml != "";
    }

    // §10.6.6: true iff THIS device is currently authorized to act as the
    // account — confirmed (not pending/disabled) AND holding AIK_priv. This is
    // the general "any authorized device" gate the XEP requires wherever code
    // used to check is_local_primary for a management decision (confirm a
    // device, revoke a device, publish the devicelist/tracker, send as the
    // account): every confirmed device holding AIK_priv is an equal manager,
    // not just the one that happened to mint the account.
    //
    // Deliberately NOT the same as is_local_primary(): is_local_primary's
    // underlying is_primary column is set by promote_to_primary and by
    // apply_paired_identity(share_primary=true), but NOT by
    // mark_tracker_authorized's AIK_priv-recovery path (§11.8 — "MAY carry the
    // shared AIK_priv... self-refreshing, device-key-sealed recovery"), which
    // only ever touches the aik_priv_* columns and intentionally never flips
    // is_primary. A device that recovered AIK_priv via the tracker therefore
    // holds signing material and IS authorized per §10.6.6 even though
    // is_local_primary would (incorrectly) still say false. Use is_authorized()
    // — not is_local_primary() — for every "can this device act as the
    // account right now" decision; is_local_primary() is kept only for its
    // narrower "genuinely first device" / UI Primary-vs-Secondary badge use.
    public bool is_authorized(Account account) {
        return !is_pending_enrollment(account) && has_local_aik_priv(account);
    }

    // §11.8: this device successfully decrypted its own <emk> copy of the
    // sealed device-state tracker — re-affirms/records authorization. Only
    // touches AIK private-key material if `aik_priv` is supplied AND we do not
    // already hold our own (recovery path: "a newly-associated device recover[s]
    // the shared account identity key"). Never flips is_primary — that stays
    // reserved for the genuine first-device / explicit reset paths.
    public void mark_tracker_authorized(Account account, Protocol.AccountIdentityKey? aik_priv = null) {
        var update = account_identity.update()
            .with(account_identity.account_id, "=", account.id)
            .set(account_identity.confirmed, true)
            .set(account_identity.tracker_last_decryptable, true)
            .set(account_identity.tracker_revoked, false);
        if (aik_priv != null && !has_local_aik_priv(account)) {
            Protocol.AccountIdentityKey priv = (!) aik_priv;
            update
                .set(account_identity.aik_priv_ed25519_base64, Base64.encode(priv.priv_ed25519))
                .set(account_identity.aik_priv_mldsa_base64, Base64.encode(priv.priv_mldsa));
        }
        update.perform();
    }

    // §11.8: our device's tracker recipient copy is absent or no longer
    // decrypts. If it USED to decrypt (tracker_last_decryptable was true), this
    // is a revocation reaching us offline — mark it distinctly and reopen the
    // pending-enrollment banner. If it never decrypted (still-pending device
    // that was never in the authorized set), this is a no-op: presence of the
    // tracker without a matching recipient is already handled by leaving the
    // device pending, which is the existing default state.
    public void mark_tracker_not_authorized(Account account) {
        Row? row = get_local_identity(account.id);
        if (row == null) return;
        bool was_decryptable = ((!) row)[account_identity.tracker_last_decryptable];
        if (!was_decryptable) return;
        account_identity.update()
            .with(account_identity.account_id, "=", account.id)
            .set(account_identity.tracker_last_decryptable, false)
            .set(account_identity.tracker_revoked, true)
            .set(account_identity.confirmed, false)
            .perform();
    }

    // §11.8 canonical wire format: monotonic per-account devtracker version
    // counter (rollback guard, mirrors X3dhpqService.nextTrackerVersion).
    // Advanced on every republish, independent of the devicelist's own
    // list_version. Returns 1 on the very first call for an account.
    public long next_tracker_version(Account account) {
        Row? row = get_local_identity(account.id);
        long next = (row != null ? ((!) row)[account_identity.tracker_version] : 0) + 1;
        account_identity.update()
            .with(account_identity.account_id, "=", account.id)
            .set(account_identity.tracker_version, next)
            .perform();
        return next;
    }

    // §11.8: true while this device was revoked (previously authorized, tracker
    // no longer decryptable) — lets the pending-enrollment banner show a
    // "you were revoked" message distinct from "never confirmed".
    public bool is_tracker_revoked(Account account) {
        Row? row = get_local_identity(account.id);
        if (row == null) return false;
        return ((!) row)[account_identity.tracker_revoked];
    }

    // §11.8 queued enrollment request cache (see PendingEnrollmentRequestTable).
    // One row per account; a fresh request overwrites the previous one.
    public void store_pending_enrollment_request(Account account, uint32 device_id, string full_jid,
            string sid_base64, string? dik_ed25519_base64, string? dik_x25519_base64, string? dik_mldsa_base64) {
        pending_enrollment_request.upsert()
            .value(pending_enrollment_request.account_id, account.id, true)
            .value(pending_enrollment_request.device_id, (int) device_id)
            .value(pending_enrollment_request.full_jid, full_jid)
            .value(pending_enrollment_request.sid_base64, sid_base64)
            .value(pending_enrollment_request.dik_ed25519_base64, dik_ed25519_base64)
            .value(pending_enrollment_request.dik_x25519_base64, dik_x25519_base64)
            .value(pending_enrollment_request.dik_mldsa_base64, dik_mldsa_base64)
            .value(pending_enrollment_request.received_at, (long) new DateTime.now_utc().to_unix())
            .perform();
    }

    public Row? get_pending_enrollment_request_row(Account account) {
        return pending_enrollment_request.select()
            .with(pending_enrollment_request.account_id, "=", account.id)
            .single().row().inner;
    }

    public void clear_pending_enrollment_request(Account account) {
        pending_enrollment_request.delete()
            .with(pending_enrollment_request.account_id, "=", account.id)
            .perform();
    }

    private string? serialize_key_nodes(StanzaNode? parent_node, string child_name) {
        if (parent_node == null) {
            return null;
        }
        StringBuilder builder = new StringBuilder();
        foreach (StanzaNode child in parent_node.get_subnodes(child_name, Protocol.NS_BUNDLE)) {
            builder.append(child.get_attribute("id") ?? "");
            builder.append(":");
            builder.append(child.get_string_content() ?? "");
            builder.append("\n");
        }
        return builder.str;
    }

    private void populate_public_prekeys(Gee.ArrayList<Protocol.PublicPreKey> target, string? encoded) {
        if (encoded == null || encoded == "") {
            return;
        }
        foreach (string line in encoded.split("\n")) {
            if (line == "" || !line.contains(":")) {
                continue;
            }
            string[] parts = line.split(":", 2);
            Protocol.PublicPreKey key = new Protocol.PublicPreKey();
            key.id = (uint32) int.parse(parts[0]);
            key.public_base64 = parts[1];
            target.add(key);
        }
    }

    public void store_group_session(Account account, string room_jid, Protocol.GroupSession gs) {
        string send_state = gs.serialize_send_state();
        string member_state = gs.serialize_member_state() + gs.serialize_recv_chains();
        group_session.upsert()
            .value(group_session.account_id, account.id, true)
            .value(group_session.room_jid, room_jid, true)
            .value(group_session.epoch, (int) gs.epoch, true)
            .value(group_session.sender_state_base64, Base64.encode(string_to_bytes(send_state)))
            .value(group_session.member_state_base64, Base64.encode(string_to_bytes(member_state)))
            .value(group_session.removed_aiks_json, null)
            .value(group_session.created_at, (long) new DateTime.now_utc().to_unix())
            .value(group_session.updated_at, (long) new DateTime.now_utc().to_unix())
            .perform();
    }

    public Protocol.GroupSession? load_group_session(Account account, string room_jid, uint8[] my_aik_pub_bytes, uint32 my_device_id) {
        // Find the row with the highest epoch for this room.
        Row? row = group_session.select()
            .with(group_session.account_id, "=", account.id)
            .with(group_session.room_jid, "=", room_jid)
            .order_by(group_session.epoch, "DESC")
            .single().row().inner;
        if (row == null) return null;
        string? ss64 = ((!) row)[group_session.sender_state_base64];
        string? ms64 = ((!) row)[group_session.member_state_base64];
        string send_state = ss64 != null ? (string)(Base64.decode(ss64)) : "";
        string member_state = ms64 != null ? (string)(Base64.decode(ms64)) : "";
        return Protocol.GroupSession.deserialize(room_jid, my_aik_pub_bytes, my_device_id, send_state, member_state);
    }

    public bool has_membership_journal(Account account, string room_jid) {
        return membership_journal.select()
            .with(membership_journal.account_id, "=", account.id)
            .with(membership_journal.room_jid, "=", room_jid)
            .count() > 0;
    }

    // Returns all stored journal entries for the given room ordered by seq.
    // Caller is responsible for re-applying them to in-memory GroupSession.
    public Gee.List<Protocol.MemberAuditEntry> list_membership_journal_entries(
            Account account, string room_jid) {
        Gee.ArrayList<Protocol.MemberAuditEntry> out_entries = new Gee.ArrayList<Protocol.MemberAuditEntry>();
        var rows = membership_journal.select()
            .with(membership_journal.account_id, "=", account.id)
            .with(membership_journal.room_jid, "=", room_jid)
            .order_by(membership_journal.seq, "ASC");
        foreach (Row r in rows) {
            try {
                Protocol.MemberAuditEntry e = new Protocol.MemberAuditEntry();
                e.seq = (uint64) r[membership_journal.seq];
                // prev_hash hex → bytes
                string ph_hex = r[membership_journal.prev_hash_hex];
                e.prev_hash = new uint8[32];
                if (ph_hex != null && ph_hex.length == 64) {
                    for (int i = 0; i < 32; i++) {
                        // xdigit_value() is hex-aware (0-9, a-f, A-F); digit_value()
                        // only handles 0-9 and returned -1 for a-f, which silently
                        // zeroed every hex-letter nibble and corrupted the prevHash
                        // chain link for any non-genesis entry.
                        int hi = ph_hex.get_char(i * 2).xdigit_value();
                        int lo = ph_hex.get_char(i * 2 + 1).xdigit_value();
                        if (hi < 0 || lo < 0) { hi = 0; lo = 0; }
                        e.prev_hash[i] = (uint8) ((hi << 4) | lo);
                    }
                }
                e.action = (uint8) (int) r[membership_journal.action];
                string p_b64 = r[membership_journal.payload_base64];
                e.payload = (p_b64 != null) ? Base64.decode(p_b64) : new uint8[0];
                // Restore the hybrid signatures and the entry timestamp — required
                // so a re-marshalled entry (e.g. bundled into a group-sync
                // announcement) still verifies. Previously these were dropped,
                // which produced signature-less, timestamp-0 entries.
                string? sig_ed_b64 = r[membership_journal.sig_ed_base64];
                string? sig_ml_b64 = r[membership_journal.sig_mldsa_base64];
                e.signature = (sig_ed_b64 != null) ? Base64.decode(sig_ed_b64) : new uint8[0];
                e.mldsa_signature = (sig_ml_b64 != null) ? Base64.decode(sig_ml_b64) : new uint8[0];
                e.timestamp = (int64) r[membership_journal.created_at];
                out_entries.add(e);
            } catch (Error err) {
                continue;
            }
        }
        return out_entries;
    }

    public void store_membership_journal_entry(Account account, string room_jid, Protocol.MemberAuditEntry entry) {
        string prev_hash_hex = bytes_to_hex_string(entry.prev_hash);
        membership_journal.upsert()
            .value(membership_journal.account_id, account.id, true)
            .value(membership_journal.room_jid, room_jid, true)
            .value(membership_journal.seq, (int) entry.seq, true)
            .value(membership_journal.prev_hash_hex, prev_hash_hex)
            .value(membership_journal.action, (int) entry.action)
            .value(membership_journal.payload_base64, Base64.encode(entry.payload))
            .value(membership_journal.sig_ed_base64, Base64.encode(entry.signature))
            .value(membership_journal.sig_mldsa_base64, Base64.encode(entry.mldsa_signature))
            // Persist the entry's OWN signed timestamp (not store-time) so a
            // reloaded+re-marshalled entry reproduces the exact signed_part.
            .value(membership_journal.created_at, (long) entry.timestamp)
            .perform();
    }

    // §11.7 device-audit DAG persistence (device_dag.vala). Upsert-by-natural-key
    // (account_id, entry_hash_hex) mirrors store_membership_journal_entry: a
    // re-store of an already-known entry (e.g. re-deriving the genesis Snapshot)
    // is a harmless idempotent overwrite, never a duplicate row or a failure.
    public void store_device_audit_entry(Account account, Protocol.DeviceAuditEntryV2 entry) {
        device_audit.upsert()
            .value(device_audit.account_id, account.id, true)
            .value(device_audit.entry_hash_hex, entry.hash_hex(), true)
            .value(device_audit.entry_blob_base64, Base64.encode(entry.marshal()))
            .value(device_audit.created_at, (long) new DateTime.now_utc().to_unix())
            .perform();
    }

    // Every persisted device-audit entry for this account, unmarshalled. Row
    // order is NOT causal order — DeviceDag.recompute() performs its own
    // Kahn topo-sort (canonical_order) over the ingested set, so callers must
    // feed the full list to a fresh DeviceDag rather than relying on this order.
    // A row that fails to base64-decode or unmarshal is skipped defensively
    // rather than aborting the whole fold.
    public Gee.List<Protocol.DeviceAuditEntryV2> list_device_audit_entries(Account account) {
        var out_entries = new Gee.ArrayList<Protocol.DeviceAuditEntryV2>();
        var rows = device_audit.select().with(device_audit.account_id, "=", account.id);
        foreach (Row r in rows) {
            try {
                uint8[] blob = bytes_to_uint8_array(bytes_from_base64(r[device_audit.entry_blob_base64]));
                Protocol.DeviceAuditEntryV2? e = Protocol.DeviceAuditEntryV2.unmarshal(blob);
                if (e != null) {
                    out_entries.add(e);
                }
            } catch (Error err) {
                continue;
            }
        }
        return out_entries;
    }

    // True once at least one device-audit row (genesis Snapshot or later) has
    // been persisted for this account. Used to gate the one-time genesis
    // bootstrap so it never re-fires on every publish.
    public bool has_device_audit_entries(Account account) {
        return device_audit.select().with(device_audit.account_id, "=", account.id).count() > 0;
    }

    // §10.6.6/§12 account reset: drop every locally-cached device-audit DAG
    // (§11.7) entry for this account so ensure_device_audit_genesis /
    // try_derive_devices_from_dag re-bootstrap cleanly under the NEW AIK
    // instead of permanently failing to resolve against entries signed by the
    // now-revoked OLD AIK (the fold's resolver only accepts the CURRENTLY
    // pinned AIK's fingerprint, so leftover OLD-AIK entries could never fold
    // again anyway — this just clears the dead weight). Mirrors
    // prune_remote_devices_not_in's "wipe everything from the old identity"
    // role, but for the v2 DAG cache. Deliberately does NOT touch the v1
    // account_audit chain (audit_entry table): that chain intentionally
    // continues unbroken so a RotateAIK entry can still be appended and
    // hash-linked to it (§12.1 step 3).
    public void clear_device_audit_entries(Account account) {
        device_audit.delete().with(device_audit.account_id, "=", account.id).perform();
    }

    // Wipe the v1 linear account-audit chain (AddDevice/RemoveDevice/RotateAIK). Used
    // by account reset so the new AIK starts from an empty chain and the fresh primary
    // re-records its self-genesis AddDevice(self)@0 (§11) instead of the stale chain
    // (signed by the now-revoked old AIK) blocking it.
    public void clear_account_audit_entries(Account account) {
        audit_entry.delete().with(audit_entry.account_id, "=", account.id).perform();
    }

    // §8.6 revocation tombstone: record a device as explicitly revoked so no
    // inbound devicelist/peer/pair-hello can ever re-seed it (the phantom
    // "previous master" case). Idempotent.
    public void store_revoked_device(Account account, int device_id) {
        revoked_device.upsert()
            .value(revoked_device.account_id, account.id, true)
            .value(revoked_device.device_id, device_id, true)
            .value(revoked_device.revoked_at, (long) new DateTime.now_utc().to_unix())
            .perform();
    }

    public bool is_device_revoked(Account account, int device_id) {
        return revoked_device.select()
            .with(revoked_device.account_id, "=", account.id)
            .with(revoked_device.device_id, "=", device_id)
            .count() > 0;
    }

    public Gee.Set<int> get_revoked_device_ids(Account account) {
        var result = new Gee.HashSet<int>();
        foreach (Row row in revoked_device.select()
                .with(revoked_device.account_id, "=", account.id)) {
            result.add(row[revoked_device.device_id]);
        }
        return result;
    }

    // Cleared only on account reset (fresh AIK/genesis): the new identity's
    // device set starts empty, so prior tombstones no longer apply.
    public void clear_revoked_devices(Account account) {
        revoked_device.delete().with(revoked_device.account_id, "=", account.id).perform();
    }

    // Local device nickname (§10.6 client-side label). Returns null when the user
    // has not set one — callers fall back to a "Device N" default.
    public string? lookup_device_nickname(Account account, int device_id) {
        Row? row = device_nickname.select()
            .with(device_nickname.account_id, "=", account.id)
            .with(device_nickname.device_id, "=", device_id)
            .single().row().inner;
        if (row == null) return null;
        return ((!) row)[device_nickname.nickname];
    }

    // Set (or, for a blank name, clear back to the default) a device's local
    // nickname. Never published — purely a client-side convenience.
    public void store_device_nickname(Account account, int device_id, string? name) {
        string trimmed = (name ?? "").strip();
        if (trimmed == "") {
            device_nickname.delete()
                .with(device_nickname.account_id, "=", account.id)
                .with(device_nickname.device_id, "=", device_id)
                .perform();
            return;
        }
        device_nickname.upsert()
            .value(device_nickname.account_id, account.id, true)
            .value(device_nickname.device_id, device_id, true)
            .value(device_nickname.nickname, trimmed)
            .perform();
    }

    // The user-facing label for one of the account's own devices: the local
    // nickname if set, otherwise the "Device N" default. N is a stable 1-based
    // ordinal over the full known own-device set (this device + confirmed
    // siblings + pending), sorted ascending by id — matching self_devices_widget
    // so the same device reads the same everywhere.
    public string device_display_label(Account account, int device_id) {
        string? nick = lookup_device_nickname(account, device_id);
        if (nick != null && nick.strip() != "") return (!) nick;

        Gee.Set<int> revoked = get_revoked_device_ids(account);
        var ids = new Gee.TreeSet<int>();
        int? local = get_local_device_id(account);
        if (local != null) ids.add((int) ((!) local));
        string own_jid = account.bare_jid.to_string();
        foreach (int did in get_remote_device_ids(account, own_jid)) {
            if (!revoked.contains(did)) ids.add(did);
        }
        foreach (int did in get_pending_own_device_ids(account)) {
            if (!revoked.contains(did)) ids.add(did);
        }
        int n = 1;
        foreach (int did in ids) {
            if (did == device_id) return @"Device $n";
            n++;
        }
        return @"Device $device_id";
    }

    // Record that a decrypted 1:1 message (identified by stanza_id) was authored
    // by one of the account's own devices. Written only for genuine sibling
    // messages so a later render can attribute them. Idempotent per stanza_id.
    public void store_message_source_device(Account account, string stanza_id, int device_id) {
        message_device.upsert()
            .value(message_device.account_id, account.id, true)
            .value(message_device.stanza_id, stanza_id, true)
            .value(message_device.device_id, device_id)
            .perform();
    }

    // The own-device id that authored the given 1:1 message, or null if none was
    // recorded (peer message, this device's own message, or pre-v15 history).
    public int? lookup_message_source_device(Account account, string stanza_id) {
        Row? row = message_device.select()
            .with(message_device.account_id, "=", account.id)
            .with(message_device.stanza_id, "=", stanza_id)
            .single().row().inner;
        if (row == null) return null;
        return ((!) row)[message_device.device_id];
    }

    // Drop the persisted OWN devicelist snapshot (payload/version/content-key). Used by
    // account reset: the shrink guard (§8.6) compares a fresh publish against this
    // snapshot, so a stale snapshot from the OLD identity would refuse to publish the
    // new single-device list ("dropping known device(s) … without revocation"). After
    // clearing, the reset republishes with first-publish (empty-prev) semantics.
    public void clear_own_device_list_snapshot(Account account) {
        device_list.delete()
            .with(device_list.account_id, "=", account.id)
            .with(device_list.bare_jid, "=", account.bare_jid.to_string())
            .perform();
    }

    private string bytes_to_hex_string(uint8[] b) {
        StringBuilder sb = new StringBuilder();
        foreach (uint8 byte in b) {
            sb.append_printf("%02x", byte);
        }
        return sb.str;
    }

    // Account audit chain (§11) persisted rows for our own account, ordered by
    // seq ascending. Used to derive the chain tail (seq + prev_hash) when we
    // append a new locally-originated entry (e.g. RemoveDevice, §8.6).
    public Gee.List<Protocol.AuditEntry> list_account_audit_entries(Account account) {
        var parsed = new Gee.ArrayList<Protocol.AuditEntry>();
        var rows = audit_entry.select()
            .with(audit_entry.account_id, "=", account.id)
            .with(audit_entry.bare_jid, "=", account.bare_jid.to_string());
        foreach (Row r in rows) {
            string? b64 = r[audit_entry.entry_base64];
            if (b64 == null) continue;
            Protocol.AuditEntry? e = Protocol.AuditEntry.unmarshal(Base64.decode((!) b64));
            if (e != null) parsed.add(e);
        }
        parsed.sort((a, b) => (a.seq < b.seq) ? -1 : (a.seq > b.seq ? 1 : 0));
        return parsed;
    }

    public void store_account_audit_entry(Account account, Protocol.AuditEntry entry) {
        audit_entry.upsert()
            .value(audit_entry.account_id, account.id, true)
            .value(audit_entry.bare_jid, account.bare_jid.to_string(), true)
            .value(audit_entry.item_id, entry.seq.to_string(), true)
            .value(audit_entry.entry_base64, Base64.encode(entry.marshal()))
            .value(audit_entry.previous_hash_hex, bytes_to_hex_string(entry.prev_hash))
            .value(audit_entry.created_at, (long) new DateTime.now_utc().to_unix())
            .perform();
    }

    // Emitted when a peer's observed AIK changes from a previously-stored one
    // (rotation/reset). The UI raises a review notification; the change itself is
    // NOT auto-trusted — trust_state moves to "rotated" until the user accepts.
    public signal void peer_identity_rotated(Account account, string bare_jid, string? fingerprint);

    private void update_peer_identity(Account account, string bare_jid, string? aik_ed25519, string? aik_mldsa) {
        Row? existing = get_peer_account_identity_row(account, bare_jid);
        string trust_state = "unverified";
        bool downgraded = false;
        bool rotation_detected = false;
        long created_at = (long) new DateTime.now_utc().to_unix();
        if (existing != null) {
            created_at = ((!) existing)[peer_account_identity.created_at];
            string? old_ed = ((!) existing)[peer_account_identity.aik_pub_ed25519_base64];
            string? old_m = ((!) existing)[peer_account_identity.aik_pub_mldsa_base64];
            trust_state = ((!) existing)[peer_account_identity.trust_state];
            downgraded = ((!) existing)[peer_account_identity.downgraded];
            if ((old_ed != null && aik_ed25519 != null && old_ed != aik_ed25519) || (old_m != null && aik_mldsa != null && old_m != aik_mldsa)) {
                // Only fire the review signal on a genuine transition into the
                // rotated state (not on every subsequent republish of the new
                // AIK, which would already be "rotated").
                rotation_detected = trust_state != "rotated";
                trust_state = "rotated";
                downgraded = true;
            }
        }

        string? fingerprint = null;
        if (aik_ed25519 != null && aik_mldsa != null) {
            try {
                fingerprint = account_fingerprint(bytes_from_base64(aik_ed25519), bytes_from_base64(aik_mldsa));
            } catch (Error e) {
                warning("Unable to compute x3dhpq peer fingerprint for %s: %s", bare_jid, e.message);
            }
        }

        peer_account_identity.upsert()
            .value(peer_account_identity.account_id, account.id, true)
            .value(peer_account_identity.bare_jid, bare_jid, true)
            .value(peer_account_identity.aik_pub_ed25519_base64, aik_ed25519)
            .value(peer_account_identity.aik_pub_mldsa_base64, aik_mldsa)
            .value(peer_account_identity.aik_fingerprint, fingerprint)
            .value(peer_account_identity.trust_state, trust_state)
            .value(peer_account_identity.downgraded, downgraded)
            .value(peer_account_identity.created_at, created_at)
            .value(peer_account_identity.updated_at, (long) new DateTime.now_utc().to_unix())
            .perform();

        if (rotation_detected) {
            peer_identity_rotated(account, bare_jid, fingerprint);
        }
    }

    // §10.6.5: a signed devicelist from a peer we already have a pinned AIK for
    // failed to verify against that AIK (stream_module.vala's verify_inbound_devicelist,
    // both the "AIK signature does not verify" and the "same version, different
    // content (fork)" rejections) — this is exactly the "same JID, different/
    // reconstructed AIK" event that MUST NOT be auto-accepted. Unlike
    // update_peer_identity (called from a freshly-fetched BUNDLE, where we already
    // hold the new AIK bytes to store), here we only know the devicelist looked
    // wrong — we do NOT yet know the new AIK, since verification against the OLD
    // pinned one is exactly what failed. So this only flips trust_state to
    // "rotated" (reusing the SAME column + signal + UI review flow that
    // update_peer_identity/peer_identity_rotated already drive — contact_details_
    // provider.vala's "Review"/"Accept new identity" button and manager.vala's
    // accept_peer_aik, which re-learns the peer from scratch via db.forget_peer).
    // Idempotent: only fires the signal on the transition into "rotated".
    public void flag_peer_devicelist_fork(Account account, string bare_jid) {
        Row? existing = get_peer_account_identity_row(account, bare_jid);
        if (existing == null) {
            // No prior pinned identity to have forked from; nothing to flag.
            return;
        }
        string trust_state = ((!) existing)[peer_account_identity.trust_state];
        if (trust_state == "rotated") {
            return; // already flagged; avoid re-notifying on every rejected republish
        }
        string? fingerprint = ((!) existing)[peer_account_identity.aik_fingerprint];
        peer_account_identity.update()
            .with(peer_account_identity.account_id, "=", account.id)
            .with(peer_account_identity.bare_jid, "=", bare_jid)
            .set(peer_account_identity.trust_state, "rotated")
            .set(peer_account_identity.downgraded, true)
            .set(peer_account_identity.updated_at, (long) new DateTime.now_utc().to_unix())
            .perform();
        peer_identity_rotated(account, bare_jid, fingerprint);
    }

    public override void migrate(long old_version) {
        if (old_version < 4) {
            try {
                exec("DROP TABLE IF EXISTS pairing_session");
                exec("CREATE TABLE pairing_session (account_id INTEGER NOT NULL, sid TEXT NOT NULL PRIMARY KEY, role INTEGER NOT NULL, peer_full_jid TEXT NOT NULL, code TEXT NOT NULL, started_at INTEGER NOT NULL, state_blob TEXT)");
            } catch (Error e) {
                error("x3dhpq migrate pairing_session: %s", e.message);
            }
        }
    }

    public void persist_pairing_session(int account_id, uint8[] sid, int role, string peer_full_jid, string code, int64 started_at, uint8[]? state_blob) {
        pairing_session.upsert()
            .value(pairing_session.sid, Base64.encode(sid), true)
            .value(pairing_session.account_id, account_id)
            .value(pairing_session.role, role)
            .value(pairing_session.peer_full_jid, peer_full_jid)
            .value(pairing_session.code, code)
            .value(pairing_session.started_at, (long) started_at)
            .value(pairing_session.state_blob, state_blob != null ? Base64.encode(state_blob) : null)
            .perform();
    }

    public bool load_pairing_session(uint8[] sid, out PairingSessionRow row) {
        row = new PairingSessionRow();
        string sid_b64 = Base64.encode(sid);
        Row? r = pairing_session.row_with(pairing_session.sid, sid_b64).inner;
        if (r == null) return false;
        row.account_id = ((!) r)[pairing_session.account_id];
        row.sid = Base64.decode(((!) r)[pairing_session.sid]);
        row.role = ((!) r)[pairing_session.role];
        row.peer_full_jid = ((!) r)[pairing_session.peer_full_jid];
        row.code = ((!) r)[pairing_session.code];
        row.started_at = (int64) ((!) r)[pairing_session.started_at];
        string? sb = ((!) r)[pairing_session.state_blob];
        row.state_blob = sb != null ? Base64.decode(sb) : null;
        return true;
    }

    public void update_pairing_state(uint8[] sid, uint8[] state_blob) {
        pairing_session.update()
            .with(pairing_session.sid, "=", Base64.encode(sid))
            .set(pairing_session.state_blob, Base64.encode(state_blob))
            .perform();
    }

    public void delete_pairing_session(uint8[] sid) {
        pairing_session.delete()
            .with(pairing_session.sid, "=", Base64.encode(sid))
            .perform();
    }

    public void sweep_expired_pairing_sessions(int64 now_unix, int ttl_seconds = 60) {
        try {
            exec(@"DELETE FROM pairing_session WHERE started_at + $ttl_seconds < $now_unix");
        } catch (Error e) {
            warning("x3dhpq sweep_expired_pairing_sessions: %s", e.message);
        }
    }
}

}
