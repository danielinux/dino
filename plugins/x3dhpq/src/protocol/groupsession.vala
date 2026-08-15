// Per-room group session. Mirrors groupsession.go semantics.
// Members are keyed by AIK fingerprint string. Epoch rotates on add/remove.
// RecvChains keyed by (aik_fp, device_id, epoch) encoded as a string "fp:devid:epoch".
// Removed AIKs are tracked with the epoch after which they were removed.

using Gee;

namespace Dino.Plugins.X3dhpq.Protocol {

public class GroupMember : Object {
    public uint8[] aik_pub_bytes { get; set; }    // canonical AccountIdentityPub.Marshal()
    public ArrayList<uint32> device_ids { get; set; default = new ArrayList<uint32>(); }

    public string fingerprint() throws GLib.Error {
        if (aik_pub_bytes.length < 3 + 32) {
            throw new IOError.FAILED("aik pub too short");
        }
        uint8[] ed = new uint8[32];
        Memory.copy(ed, (uint8*) aik_pub_bytes + 3, 32);
        int mldsa_off = 35;
        int mldsa_len = aik_pub_bytes.length - mldsa_off;
        uint8[] mldsa = new uint8[mldsa_len > 0 ? mldsa_len : 0];
        if (mldsa_len > 0) {
            Memory.copy(mldsa, (uint8*) aik_pub_bytes + mldsa_off, mldsa_len);
        }
        return account_fingerprint(new Bytes(ed), new Bytes(mldsa));
    }
}

// Returned when encryption is refused due to missing journal.
public errordomain GroupSessionError {
    NO_JOURNAL,
    AEAD_FAILURE,
    UNKNOWN_SENDER,
    REMOVED_MEMBER,
    ANNOUNCEMENT_FROM_REMOVED,
    ANNOUNCEMENT_WRONG_ROOM,
    ANNOUNCEMENT_UNKNOWN_SENDER,
    STALE_EPOCH,
}

private string recv_key(string aik_fp, uint32 device_id, uint32 epoch) {
    return @"$aik_fp:$device_id:$epoch";
}

public class GroupSession : Object {
    public string room_jid { get; set; }
    public uint8[] my_aik_pub_bytes { get; set; }
    public uint32 my_device_id { get; set; }
    public uint32 epoch { get; set; default = 0; }

    // aik_fp -> GroupMember
    private HashMap<string, GroupMember> members = new HashMap<string, GroupMember>();
    // recv_key string -> SenderChain
    private HashMap<string, SenderChain> recv_chains = new HashMap<string, SenderChain>();
    // aik_fp -> epoch at which removed
    private HashMap<string, uint32> removed_aiks = new HashMap<string, uint32>();

    public SenderChain? send_chain { get; private set; }

    // Rolling checkpoint of our send chain that announce_sender_chain() exports
    // INSTEAD of the live (latest) ratchet position. A member that lacks a recv
    // chain (new device, was offline) can therefore only decrypt back to the
    // checkpoint, not to the epoch start. maybe_advance_checkpoint() slides it
    // forward at most once per max-age window (24h, set by the caller), so the
    // window of past messages exposed by re-sharing — the option-1 forward-
    // secrecy cost — is bounded to ~24h instead of the whole (possibly unbounded)
    // epoch. send_ckpt_key is the chain_key snapshot AT send_ckpt_index.
    private uint8[] send_ckpt_key = new uint8[0];
    private uint32 send_ckpt_index = 0;
    private int64 send_ckpt_time = 0;   // unix seconds; 0 = not yet initialised

    public static GroupSession new_session(
        string room_jid,
        uint8[] my_aik_pub_bytes,
        uint32 my_device_id
    ) throws GLib.Error {
        GroupSession gs = new GroupSession();
        gs.room_jid = room_jid;
        gs.my_aik_pub_bytes = my_aik_pub_bytes.copy();
        gs.my_device_id = my_device_id;
        gs.epoch = 0;
        gs.send_chain = SenderChain.new_random(0);
        /* §13.3a: every epoch gets its own sender signing key, so a compromised device
         * cannot retroactively sign for an epoch it has left. */
        Bytes sig_pub0;
        Bytes sig_priv0;
        global::X3dhpq.Crypto.generate_ed25519(out sig_pub0, out sig_priv0);
        gs.send_chain.sig_pub = bytes_to_uint8_array(sig_pub0);
        gs.send_chain.sig_priv = bytes_to_uint8_array(sig_priv0);
        gs.send_ckpt_key = gs.send_chain.chain_key.copy();
        gs.send_ckpt_index = 0;
        gs.send_ckpt_time = 0;
        return gs;
    }

    public void add_member(GroupMember m) throws GLib.Error {
        string fp = m.fingerprint();
        removed_aiks.unset(fp);
        members[fp] = m;
        rotate_epoch();
    }

    // Populate the members map without rotating epoch. Used when replaying a
    // journal at startup: every AddMember in the journal would otherwise
    // bump the local epoch counter past the sender's, causing recv-chain
    // lookups to mis-key. Conversations' GroupSession.create has the same
    // "add at epoch 0 without rotating" semantics for initial members.
    public void add_initial_member(GroupMember m) throws GLib.Error {
        string fp = m.fingerprint();
        removed_aiks.unset(fp);
        members[fp] = m;
    }

    public void remove_member_by_fp(string fp) throws GLib.Error {
        members.unset(fp);
        // Clear recv chains for this AIK.
        ArrayList<string> to_remove = new ArrayList<string>();
        foreach (string k in recv_chains.keys) {
            if (k.has_prefix(fp + ":")) {
                to_remove.add(k);
            }
        }
        foreach (string k in to_remove) {
            recv_chains.unset(k);
        }
        rotate_epoch();
        removed_aiks[fp] = epoch;
    }

    private void rotate_epoch() throws GLib.Error {
        epoch++;
        send_chain = SenderChain.new_random(epoch);
        /* §13.3a: a new epoch means a new signing key, so authority to sign as us in this
         * room never outlives the epoch it was issued for. */
        Bytes rot_sig_pub;
        Bytes rot_sig_priv;
        global::X3dhpq.Crypto.generate_ed25519(out rot_sig_pub, out rot_sig_priv);
        send_chain.sig_pub = bytes_to_uint8_array(rot_sig_pub);
        send_chain.sig_priv = bytes_to_uint8_array(rot_sig_priv);
        // Fresh epoch → the checkpoint restarts at the new chain's index 0, so
        // early members of the new epoch still get it whole; it then slides
        // forward again via maybe_advance_checkpoint.
        send_ckpt_key = send_chain.chain_key.copy();
        send_ckpt_index = 0;
        send_ckpt_time = 0;
    }

    // Slide the announce checkpoint forward to the CURRENT send position once the
    // max-age window has elapsed. `now` is unix seconds; `max_age_seconds` bounds
    // the re-shareable history / forward-secrecy window (e.g. 24h). The first call
    // in an epoch just stamps the start time (checkpoint stays at index 0 so a
    // member joining early in the epoch still gets it whole). Returns true iff the
    // checkpoint actually moved (so the caller can persist).
    public bool maybe_advance_checkpoint(int64 now, int64 max_age_seconds) {
        if (send_chain == null) return false;
        if (send_ckpt_time == 0) {
            send_ckpt_time = now;
            return false;
        }
        if (now - send_ckpt_time >= max_age_seconds) {
            send_ckpt_key = send_chain.chain_key.copy();
            send_ckpt_index = send_chain.next_index;
            send_ckpt_time = now;
            return true;
        }
        return false;
    }

    // Produce an announcement for our send chain. Exports the rolling CHECKPOINT
    // (bounded history) rather than the live position, so a member lacking a recv
    // chain can decrypt back only to the checkpoint (≤ max-age old), not the whole
    // epoch. Falls back to the live position for a session persisted before
    // checkpoints existed (no stored checkpoint key).
    public SenderChainAnnouncement announce_sender_chain() {
        SenderChainAnnouncement ann = new SenderChainAnnouncement();
        ann.sig_pub = send_chain != null ? send_chain.sig_pub.copy() : new uint8[32];
        ann.sender_aik_pub_bytes = my_aik_pub_bytes.copy();
        ann.sender_device_id = my_device_id;
        ann.room_jid = room_jid;
        ann.epoch = epoch;
        if (send_ckpt_key.length == 32) {
            ann.chain_key = send_ckpt_key.copy();
            ann.next_index = send_ckpt_index;
        } else {
            ann.chain_key = ((!) send_chain).chain_key.copy();
            ann.next_index = ((!) send_chain).next_index;
        }
        return ann;
    }

    // Install an incoming SenderChainAnnouncement from a peer.
    public void accept_sender_chain(SenderChainAnnouncement ann) throws GLib.Error {
        if (ann.room_jid != room_jid) {
            throw new GroupSessionError.ANNOUNCEMENT_WRONG_ROOM("room jid mismatch");
        }
        string fp;
        try {
            fp = ann.aik_fingerprint();
        } catch (GLib.Error e) {
            throw new GroupSessionError.ANNOUNCEMENT_UNKNOWN_SENDER("cannot compute sender fingerprint");
        }
        if (removed_aiks.has_key(fp)) {
            throw new GroupSessionError.ANNOUNCEMENT_FROM_REMOVED(@"announcement from removed AIK $fp");
        }
        if (!members.has_key(fp)) {
            throw new GroupSessionError.ANNOUNCEMENT_UNKNOWN_SENDER(@"sender AIK $fp not a current member");
        }
        SenderChain? sc = SenderChain.restore(ann.epoch, ann.chain_key, ann.next_index);
        if (sc != null) {
            /* §13.3a: the verification key for everything this sender emits in this epoch. */
            ((!) sc).sig_pub = ann.sig_pub.copy();
        }
        if (sc == null) {
            throw new IOError.FAILED("senderchain restore failed");
        }
        string rk = recv_key(fp, ann.sender_device_id, ann.epoch);
        // Install ONCE per (sender, device, epoch). Announcements now carry a
        // forward-MOVING checkpoint; overwriting a recv chain we already ratcheted
        // forward with a LATER checkpoint would skip us past (and permanently lose)
        // messages between our position and the new checkpoint. A member that
        // already holds a chain for this epoch simply ratchets it forward / catches
        // up via MAM instead of re-installing.
        if (!recv_chains.has_key(rk)) {
            recv_chains[rk] = sc;
        }
    }

    // Encrypt plaintext. Returns (header, ciphertext+tag) or throws on failure.
    /* Convenience wrapper for a message with no <heads> advertisement. It still returns
     * the §13.3a signature: an API that quietly dropped it would produce group messages no
     * conforming receiver can attribute, which is precisely the state this design removes. */
    public void encrypt(uint8[] plaintext, out GroupMessageHeader header_out, out uint8[] ciphertext_out, out uint8[] sig_out) throws GLib.Error {
        encrypt_with_heads(plaintext, null, out header_out, out ciphertext_out, out sig_out);
    }

    // heads_payload is the canonical <heads> advertisement (§13.1b) that will accompany
    // this message, or null when none is sent. It is bound into the AAD, so the caller
    // MUST pass exactly the bytes it puts on the wire.
    public void encrypt_with_heads(uint8[] plaintext, uint8[]? heads_payload, out GroupMessageHeader header_out, out uint8[] ciphertext_out, out uint8[] sig_out) throws GLib.Error {
        if (send_chain == null) {
            send_chain = SenderChain.new_random(epoch);
            /* §13.3a: a lazily created send chain still needs a signing key, or we would
             * emit unsigned (and therefore unattributable) group messages. */
            Bytes lazy_sig_pub;
            Bytes lazy_sig_priv;
            global::X3dhpq.Crypto.generate_ed25519(out lazy_sig_pub, out lazy_sig_priv);
            send_chain.sig_pub = bytes_to_uint8_array(lazy_sig_pub);
            send_chain.sig_priv = bytes_to_uint8_array(lazy_sig_priv);
        }
        uint32 idx;
        uint8[]? mk = send_chain.step(out idx);
        if (mk == null) {
            throw new IOError.FAILED("send chain step failed");
        }

        GroupMessageHeader hdr = new GroupMessageHeader();
        hdr.version = 1;
        hdr.epoch = epoch;
        hdr.sender_device_id = my_device_id;
        hdr.chain_index = idx;

        uint8[] aad_bytes = hdr.aad_with_heads(room_jid, heads_payload);
        uint8[] nonce_bytes = hdr.aead_nonce();

        Bytes ct = global::X3dhpq.Crypto.aes256gcm_encrypt(
            new Bytes(mk),
            new Bytes(nonce_bytes),
            new Bytes(plaintext),
            new Bytes(aad_bytes));

        header_out = hdr;
        ciphertext_out = bytes_to_uint8_array(ct);

        /* §13.3a: sign the message so recipients can attribute it. Every member holds this
         * sender chain key, so the AEAD tag proves only "someone in the room"; without this
         * signature any member could derive our future message keys and emit messages
         * cryptographically attributed to us. */
        if (send_chain.sig_priv.length == 0) {
            throw new IOError.FAILED("send chain has no signing key; refusing to emit an unauthenticated group message (§13.3a)");
        }
        uint8[] signed = concat_byte_arrays(aad_bytes, ciphertext_out);
        Bytes sig = global::X3dhpq.Crypto.ed25519_sign(new Bytes(send_chain.sig_priv), new Bytes(signed));
        sig_out = bytes_to_uint8_array(sig);
    }

    // Decrypt a group message.
    public uint8[] decrypt(
        string sender_aik_fp,
        GroupMessageHeader hdr,
        uint8[] ciphertext,
        uint8[]? sig
    ) throws GLib.Error {
        return decrypt_with_heads(sender_aik_fp, hdr, ciphertext, null, sig);
    }

    // heads_payload MUST be the RAW bytes of the received <heads> advertisement (or null
    // if absent), not a re-encoding of a decoded frontier — re-encoding would normalise
    // away exactly the difference the AAD binding is meant to detect (§13.1b).
    public uint8[] decrypt_with_heads(
        string sender_aik_fp,
        GroupMessageHeader hdr,
        uint8[] ciphertext,
        uint8[]? heads_payload,
        uint8[]? sig
    ) throws GLib.Error {
        if (removed_aiks.has_key(sender_aik_fp)) {
            throw new GroupSessionError.REMOVED_MEMBER(@"message from removed member $sender_aik_fp");
        }
        if (hdr.epoch < epoch) {
            throw new GroupSessionError.STALE_EPOCH("header epoch behind session epoch");
        }
        string rk = recv_key(sender_aik_fp, hdr.sender_device_id, hdr.epoch);
        SenderChain? sc = recv_chains[rk];
        if (sc == null) {
            throw new GroupSessionError.UNKNOWN_SENDER(@"no recv chain for $rk");
        }
        // §13.7: derive the key WITHOUT mutating the chain, authenticate, and only then
        // commit. The header (including chain_index) is unauthenticated until the AEAD
        // tag verifies, so ratcheting first would let anyone able to place a group
        // stanza in the room push this recv chain permanently past the real sender.
        PendingMessageKey? pending = sc.derive_message_key_at(hdr.chain_index);
        if (pending == null) {
            throw new IOError.FAILED("derive_message_key_at returned null");
        }
        uint8[] aad_bytes = hdr.aad_with_heads(room_jid, heads_payload);
        uint8[] nonce_bytes = hdr.aead_nonce();

        /* §13.3a: verify the SENDER SIGNATURE first.
         *
         * The AEAD tag alone cannot attribute a group message: the sender chain key it
         * derives from is symmetric and was handed to every member, so any member could
         * ratchet another member's chain forward and produce a message that decrypts
         * cleanly under that member's identity. Only this signature — verifiable with the
         * per-epoch key from the sender's announcement, but not forgeable by someone
         * holding merely the chain key — makes attribution sound.
         *
         * An absent signature is a failure, not an exemption: treating "no <gsig>" as
         * "this sender doesn't sign" would let a relay strip the element and restore the
         * forgery hole wholesale. */
        if (sc.sig_pub.length == 0) {
            throw new GroupSessionError.AEAD_FAILURE("no sender verification key for this epoch (§13.3a)");
        }
        if (sig == null || ((!) sig).length == 0) {
            throw new GroupSessionError.AEAD_FAILURE("group message carries no sender signature (§13.3a)");
        }
        uint8[] signed_bytes = concat_byte_arrays(aad_bytes, ciphertext);
        bool sig_ok;
        try {
            /* wolfSSL raises SIG_VERIFY_E (rc=-229) on a bad signature rather than
             * returning false, so a forgery arrives as an exception. Normalise both shapes
             * to one rejection: any outcome other than an explicit "valid" is a failure. */
            sig_ok = global::X3dhpq.Crypto.ed25519_verify(
                new Bytes(sc.sig_pub), new Bytes(signed_bytes), new Bytes((!) sig));
        } catch (GLib.Error e) {
            sig_ok = false;
        }
        if (!sig_ok) {
            throw new GroupSessionError.AEAD_FAILURE("group sender signature invalid (§13.3a)");
        }

        try {
            Bytes pt = global::X3dhpq.Crypto.aes256gcm_decrypt(
                new Bytes(((!) pending).message_key),
                new Bytes(nonce_bytes),
                new Bytes(ciphertext),
                new Bytes(aad_bytes));
            ((!) pending).commit();
            return bytes_to_uint8_array(pt);
        } catch (GLib.Error e) {
            throw new GroupSessionError.AEAD_FAILURE("AEAD authentication failed");
        }
    }

    public bool is_removed(string fp) {
        return removed_aiks.has_key(fp);
    }

    public bool has_member(string fp) {
        return members.has_key(fp);
    }

    public HashMap<string, GroupMember> get_members() {
        return members;
    }

    public HashMap<string, uint32> get_removed_aiks() {
        return removed_aiks;
    }

    // Serialise to a key=value string for DB storage (sender_state column).
    public string serialize_send_state() {
        if (send_chain == null) return "";
        return @"epoch=$(epoch)\nsend_chain=$(Base64.encode(send_chain.marshal()))\nckpt_index=$(send_ckpt_index)\nckpt_time=$(send_ckpt_time)\nckpt_key=$(Base64.encode(send_ckpt_key))\n";
    }

    // Serialise member / removed-aik maps as JSON-like text for the member_state column.
    public string serialize_member_state() {
        StringBuilder sb = new StringBuilder();
        foreach (var e in members.entries) {
            sb.append("M:");
            sb.append(e.key);
            sb.append(":");
            sb.append(Base64.encode(e.value.aik_pub_bytes));
            foreach (uint32 did in e.value.device_ids) {
                sb.append(",");
                sb.append(did.to_string());
            }
            sb.append("\n");
        }
        foreach (var e in removed_aiks.entries) {
            sb.append("R:");
            sb.append(e.key);
            sb.append(":");
            sb.append(e.value.to_string());
            sb.append("\n");
        }
        return sb.str;
    }

    // Serialise recv chains for member_state_base64 (appended).
    public string serialize_recv_chains() {
        StringBuilder sb = new StringBuilder();
        foreach (var e in recv_chains.entries) {
            sb.append("RC:");
            sb.append(e.key);
            sb.append(":");
            sb.append(Base64.encode(e.value.marshal()));
            sb.append("\n");
        }
        return sb.str;
    }

    public static GroupSession? deserialize(
        string room_jid,
        uint8[] my_aik_pub_bytes,
        uint32 my_device_id,
        string send_state,
        string member_state
    ) {
        GroupSession gs = new GroupSession();
        gs.room_jid = room_jid;
        gs.my_aik_pub_bytes = my_aik_pub_bytes.copy();
        gs.my_device_id = my_device_id;
        gs.epoch = 0;
        gs.send_chain = null;

        // Parse send_state.
        uint32 parsed_epoch = 0;
        string? send_chain_b64 = null;
        string? ckpt_key_b64 = null;
        uint32 ckpt_index = 0;
        int64 ckpt_time = 0;
        foreach (string line in send_state.split("\n")) {
            if (line.has_prefix("epoch=")) {
                parsed_epoch = (uint32) int.parse(line.substring(6));
            } else if (line.has_prefix("send_chain=")) {
                send_chain_b64 = line.substring(11);
            } else if (line.has_prefix("ckpt_index=")) {
                ckpt_index = (uint32) int.parse(line.substring(11));
            } else if (line.has_prefix("ckpt_time=")) {
                ckpt_time = int64.parse(line.substring(10));
            } else if (line.has_prefix("ckpt_key=")) {
                ckpt_key_b64 = line.substring(9);
            }
        }
        gs.epoch = parsed_epoch;
        if (send_chain_b64 != null && send_chain_b64 != "") {
            uint8[] sc_bytes = Base64.decode(send_chain_b64);
            gs.send_chain = SenderChain.unmarshal(sc_bytes);
        }
        if (ckpt_key_b64 != null && ckpt_key_b64 != "") {
            gs.send_ckpt_key = Base64.decode(ckpt_key_b64);
            gs.send_ckpt_index = ckpt_index;
            gs.send_ckpt_time = ckpt_time;
        } else if (gs.send_chain != null) {
            // Migration (session persisted before checkpoints existed): start the
            // checkpoint at the CURRENT live position so we never re-share more
            // history than from now forward.
            gs.send_ckpt_key = ((!) gs.send_chain).chain_key.copy();
            gs.send_ckpt_index = ((!) gs.send_chain).next_index;
            gs.send_ckpt_time = 0;
        }

        // Parse member_state.
        foreach (string line in member_state.split("\n")) {
            if (line.has_prefix("M:")) {
                string rest = line.substring(2);
                int colon1 = rest.index_of(":");
                if (colon1 < 0) continue;
                string fp = rest.substring(0, colon1);
                string after = rest.substring(colon1 + 1);
                string[] parts = after.split(",");
                if (parts.length == 0) continue;
                uint8[] aik_bytes = Base64.decode(parts[0]);
                GroupMember m = new GroupMember();
                m.aik_pub_bytes = aik_bytes;
                for (int i = 1; i < parts.length; i++) {
                    if (parts[i] != "") {
                        m.device_ids.add((uint32) int.parse(parts[i]));
                    }
                }
                gs.members[fp] = m;
            } else if (line.has_prefix("R:")) {
                string rest = line.substring(2);
                int colon1 = rest.index_of(":");
                if (colon1 < 0) continue;
                string fp = rest.substring(0, colon1);
                uint32 ep = (uint32) int.parse(rest.substring(colon1 + 1));
                gs.removed_aiks[fp] = ep;
            } else if (line.has_prefix("RC:")) {
                // Recv-chain key format is `<fp>:<device>:<epoch>` and the
                // fp itself never contains a colon, so the SERIALISE wrote
                // `RC:<fp>:<device>:<epoch>:<base64>` (4 colons in total).
                // The base64 portion is the LAST field — split on the last
                // colon, not the first, otherwise rk decodes to just the
                // fp and b64 decodes to "device:epoch:<actual base64>"
                // which is not valid base64. SenderChain.unmarshal then
                // returns null and the recv chain silently disappears
                // from the persisted state, surfacing later as
                // "no recv chain for ..." even though accept_sender_chain
                // succeeded just milliseconds before.
                string rest = line.substring(3);
                int last_colon = rest.last_index_of(":");
                if (last_colon < 0) continue;
                string rk = rest.substring(0, last_colon);
                string b64 = rest.substring(last_colon + 1);
                uint8[] sc_bytes = Base64.decode(b64);
                SenderChain? sc = SenderChain.unmarshal(sc_bytes);
                if (sc != null) {
                    gs.recv_chains[rk] = sc;
                }
            }
        }

        return gs;
    }
}

}
