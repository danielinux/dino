using Qlite;
using Dino.Entities;
using Xmpp;

namespace Dino.Plugins.X3dhpq {

public class Database : Qlite.Database {
    private const int VERSION = 2;

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

        internal AccountIdentityTable(Database db) {
            base(db, "account_identity");
            init({ id, account_id, device_id, is_primary, aik_pub_ed25519_base64, aik_priv_ed25519_base64, aik_pub_mldsa_base64, aik_priv_mldsa_base64, dik_pub_ed25519_base64, dik_priv_ed25519_base64, dik_pub_x25519_base64, dik_priv_x25519_base64, dik_pub_mldsa_base64, dik_priv_mldsa_base64, created_at });
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

        internal PeerDeviceTable(Database db) {
            base(db, "peer_device");
            init({ account_id, bare_jid, device_id, dik_pub_ed25519_base64, dik_pub_x25519_base64, dik_pub_mldsa_base64, certificate_base64, active, created_at, updated_at });
            unique({ account_id, bare_jid, device_id });
        }
    }

    public class DeviceListTable : Table {
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> bare_jid = new Column.NonNullText("bare_jid");
        public Column<string?> item_id = new Column.Text("item_id");
        public Column<string?> signed_payload_base64 = new Column.Text("signed_payload_base64");
        public Column<long> updated_at = new Column.Long("updated_at") { not_null = true };

        internal DeviceListTable(Database db) {
            base(db, "device_list");
            init({ account_id, bare_jid, item_id, signed_payload_base64, updated_at });
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
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };
        public Column<long> updated_at = new Column.Long("updated_at") { not_null = true };

        internal GroupSessionTable(Database db) {
            base(db, "group_session");
            init({ account_id, room_jid, epoch, sender_state_base64, member_state_base64, created_at, updated_at });
            unique({ account_id, room_jid, epoch });
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
        public Column<int> account_id = new Column.Integer("account_id") { not_null = true };
        public Column<string> session_id = new Column.NonNullText("session_id");
        public Column<string?> peer_resource = new Column.Text("peer_resource");
        public Column<string> state = new Column.NonNullText("state") { default = "created" };
        public Column<string?> transcript_base64 = new Column.Text("transcript_base64");
        public Column<long> created_at = new Column.Long("created_at") { not_null = true };
        public Column<long> updated_at = new Column.Long("updated_at") { not_null = true };

        internal PairingSessionTable(Database db) {
            base(db, "pairing_session");
            init({ account_id, session_id, peer_resource, state, transcript_base64, created_at, updated_at });
            unique({ account_id, session_id });
        }
    }

    public AccountIdentityTable account_identity { get; private set; }
    public PeerAccountIdentityTable peer_account_identity { get; private set; }
    public PeerDeviceTable peer_device { get; private set; }
    public DeviceListTable device_list { get; private set; }
    public BundleTable bundle { get; private set; }
    public SignedPreKeyTable signed_pre_key { get; private set; }
    public KemPreKeyTable kem_pre_key { get; private set; }
    public OneTimePreKeyTable one_time_pre_key { get; private set; }
    public PairwiseSessionTable pairwise_session { get; private set; }
    public GroupSessionTable group_session { get; private set; }
    public AuditEntryTable audit_entry { get; private set; }
    public RecoveryBlobTable recovery_blob { get; private set; }
    public PairingSessionTable pairing_session { get; private set; }

    public Database(string file_name) {
        base(file_name, VERSION);
        account_identity = new AccountIdentityTable(this);
        peer_account_identity = new PeerAccountIdentityTable(this);
        peer_device = new PeerDeviceTable(this);
        device_list = new DeviceListTable(this);
        bundle = new BundleTable(this);
        signed_pre_key = new SignedPreKeyTable(this);
        kem_pre_key = new KemPreKeyTable(this);
        one_time_pre_key = new OneTimePreKeyTable(this);
        pairwise_session = new PairwiseSessionTable(this);
        group_session = new GroupSessionTable(this);
        audit_entry = new AuditEntryTable(this);
        recovery_blob = new RecoveryBlobTable(this);
        pairing_session = new PairingSessionTable(this);
        init({ account_identity, peer_account_identity, peer_device, device_list, bundle, signed_pre_key, kem_pre_key, one_time_pre_key, pairwise_session, group_session, audit_entry, recovery_blob, pairing_session });
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

    public string ensure_local_device_certificate(Account account) {
        Row row = get_required_local_identity(account);
        RowOption bundle_row = bundle.select()
            .with(bundle.account_id, "=", account.id)
            .with(bundle.bare_jid, "=", account.bare_jid.to_string())
            .with(bundle.device_id, "=", row[account_identity.device_id])
            .single().row();
        if (bundle_row.is_present() && bundle_row[bundle.device_certificate_base64] != null) {
            return bundle_row[bundle.device_certificate_base64];
        }
        string certificate;
        try {
            Protocol.DeviceCertificate cert = Protocol.DeviceCertificate.issue(
                (uint32) row[account_identity.device_id],
                bytes_from_base64(row[account_identity.dik_pub_ed25519_base64]),
                bytes_from_base64(row[account_identity.dik_pub_x25519_base64]),
                bytes_from_base64(row[account_identity.dik_pub_mldsa_base64]),
                bytes_from_base64(row[account_identity.aik_priv_ed25519_base64]),
                bytes_from_base64(row[account_identity.aik_priv_mldsa_base64]),
                1
            );
            certificate = Base64.encode(cert.marshal());
        } catch (GLib.Error e) {
            warning("Unable to issue x3dhpq device certificate for %s: %s", account.bare_jid.to_string(), e.message);
            certificate = "";
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

    public void ensure_local_prekeys(Account account) {
        ensure_local_identity(account);
        Row row = get_required_local_identity(account);
        string cert = ensure_local_device_certificate(account);

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
        peer_bundle.identity_pub_x25519_base64 = ik;
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

    public void store_device_list_payload(Account account, string bare_jid, string? item_id, string payload) {
        device_list.upsert()
            .value(device_list.account_id, account.id, true)
            .value(device_list.bare_jid, bare_jid, true)
            .value(device_list.item_id, item_id)
            .value(device_list.signed_payload_base64, Base64.encode(string_to_bytes(payload)))
            .value(device_list.updated_at, (long) new DateTime.now_utc().to_unix())
            .perform();
    }

    public void store_remote_device(Account account, string bare_jid, int device_id, string? certificate_base64 = null) {
        peer_device.upsert()
            .value(peer_device.account_id, account.id, true)
            .value(peer_device.bare_jid, bare_jid, true)
            .value(peer_device.device_id, device_id, true)
            .value(peer_device.certificate_base64, certificate_base64)
            .value(peer_device.active, true)
            .value(peer_device.updated_at, (long) new DateTime.now_utc().to_unix())
            .value(peer_device.created_at, (long) new DateTime.now_utc().to_unix())
            .perform();
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

    public void ensure_local_identity(Account account) {
        if (has_local_identity(account)) {
            return;
        }

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
                .value(account_identity.is_primary, true)
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

    private void update_peer_identity(Account account, string bare_jid, string? aik_ed25519, string? aik_mldsa) {
        Row? existing = get_peer_account_identity_row(account, bare_jid);
        string trust_state = "unverified";
        bool downgraded = false;
        long created_at = (long) new DateTime.now_utc().to_unix();
        if (existing != null) {
            created_at = ((!) existing)[peer_account_identity.created_at];
            string? old_ed = ((!) existing)[peer_account_identity.aik_pub_ed25519_base64];
            string? old_m = ((!) existing)[peer_account_identity.aik_pub_mldsa_base64];
            trust_state = ((!) existing)[peer_account_identity.trust_state];
            downgraded = ((!) existing)[peer_account_identity.downgraded];
            if ((old_ed != null && aik_ed25519 != null && old_ed != aik_ed25519) || (old_m != null && aik_mldsa != null && old_m != aik_mldsa)) {
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
    }
}

}
