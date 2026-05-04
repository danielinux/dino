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
    }

    // Produce an announcement for our current send chain state.
    public SenderChainAnnouncement announce_sender_chain() {
        SenderChainAnnouncement ann = new SenderChainAnnouncement();
        ann.sender_aik_pub_bytes = my_aik_pub_bytes.copy();
        ann.sender_device_id = my_device_id;
        ann.room_jid = room_jid;
        ann.epoch = epoch;
        ann.chain_key = send_chain.chain_key.copy();
        ann.next_index = send_chain.next_index;
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
        if (sc == null) {
            throw new IOError.FAILED("senderchain restore failed");
        }
        string rk = recv_key(fp, ann.sender_device_id, ann.epoch);
        recv_chains[rk] = sc;
    }

    // Encrypt plaintext. Returns (header, ciphertext+tag) or throws on failure.
    public void encrypt(uint8[] plaintext, out GroupMessageHeader header_out, out uint8[] ciphertext_out) throws GLib.Error {
        if (send_chain == null) {
            send_chain = SenderChain.new_random(epoch);
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

        uint8[] aad_bytes = hdr.aad(room_jid);
        uint8[] nonce_bytes = hdr.aead_nonce();

        Bytes ct = global::X3dhpq.Crypto.aes256gcm_encrypt(
            new Bytes(mk),
            new Bytes(nonce_bytes),
            new Bytes(plaintext),
            new Bytes(aad_bytes));

        header_out = hdr;
        ciphertext_out = bytes_to_uint8_array(ct);
    }

    // Decrypt a group message.
    public uint8[] decrypt(
        string sender_aik_fp,
        GroupMessageHeader hdr,
        uint8[] ciphertext
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
        uint8[]? mk = sc.message_key_at(hdr.chain_index);
        if (mk == null) {
            throw new IOError.FAILED("message_key_at returned null");
        }
        uint8[] aad_bytes = hdr.aad(room_jid);
        uint8[] nonce_bytes = hdr.aead_nonce();
        try {
            Bytes pt = global::X3dhpq.Crypto.aes256gcm_decrypt(
                new Bytes(mk),
                new Bytes(nonce_bytes),
                new Bytes(ciphertext),
                new Bytes(aad_bytes));
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
        return @"epoch=$(epoch)\nsend_chain=$(Base64.encode(send_chain.marshal()))\n";
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
        foreach (string line in send_state.split("\n")) {
            if (line.has_prefix("epoch=")) {
                parsed_epoch = (uint32) int.parse(line.substring(6));
            } else if (line.has_prefix("send_chain=")) {
                send_chain_b64 = line.substring(11);
            }
        }
        gs.epoch = parsed_epoch;
        if (send_chain_b64 != null && send_chain_b64 != "") {
            uint8[] sc_bytes = Base64.decode(send_chain_b64);
            gs.send_chain = SenderChain.unmarshal(sc_bytes);
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
