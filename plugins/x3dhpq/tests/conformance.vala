/* The shared x3dhpq conformance corpus (§19.2.0), executed against the PRODUCTION
 * decision path.
 *
 * conformance/v1/group-accept.json pins observable outcomes of the receive state
 * machine — which decision a receiver reaches for a given state and inbound header,
 * and the ORDER in which its checks fire — rather than byte strings. It exists
 * because twice now the two reference clients each passed a complete green suite,
 * including byte-identical pinned cross-client vectors, while disagreeing about the
 * protocol. Neither disagreement was reachable from an encoding test.
 *
 * TWO RULES GOVERN THIS FILE.
 *
 * 1. It must not reimplement the decision logic. Every vector is driven through
 *    GroupSession.receive(), the single ordered evaluator the live receive path in
 *    Manager also calls. A harness that mirrored the checks would agree with itself
 *    and pin nothing. What this file builds is only the INPUT: a receiver session
 *    restored from persisted state, and a genuinely encrypted, genuinely signed
 *    message from a real sender session, adversarially damaged where the vector asks
 *    for damage.
 *
 * 2. A vector it cannot execute is a FAILURE, not a skip — including a missing
 *    corpus file. Silent skipping is how a corpus rots into decoration.
 */

namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq.Protocol;

class ConformanceTest : Gee.TestCase {

    // Any room JID works; it just has to be the same on both sides, because §13.3
    // binds it into the AAD.
    private const string ROOM = "conformance@conference.example.org";
    private const string PAYLOAD = "conformance vector payload";

    private Gee.HashMap<string, string> constants = new Gee.HashMap<string, string>();
    private int executed = 0;
    private int declared = 0;

    public ConformanceTest() {
        base("Conformance");

        string? path = find_corpus();
        if (path == null) {
            /* Loud, not silent. A build that cannot see the corpus has not run it,
             * and pretending otherwise is worse than not having one. */
            add_test("group_accept_CORPUS_NOT_FOUND", () => {
                fail_if_reached("conformance/v1/group-accept.json not found. Looked at "
                    + "$X3DHPQ_CONFORMANCE_DIR and upward from both the working directory "
                    + "and the test binary. The corpus is normative (§19.2.0): a vector "
                    + "that cannot be executed is a failure, not a skip.");
            });
            return;
        }

        string contents;
        try {
            FileUtils.get_contents((!) path, out contents);
        } catch (GLib.Error e) {
            string p = (!) path;
            add_test("group_accept_CORPUS_UNREADABLE", () => {
                fail_if_reached(@"cannot read the conformance corpus at $p");
            });
            return;
        }

        Jv? root = new JsonReader(contents).parse();
        if (root == null || root.kind != Jv.Kind.OBJECT) {
            add_test("group_accept_CORPUS_UNPARSEABLE", () => {
                fail_if_reached("conformance/v1/group-accept.json did not parse as a JSON object");
            });
            return;
        }

        Jv? consts = ((!) root).member("constants");
        if (consts != null && ((!) consts).kind == Jv.Kind.OBJECT) {
            foreach (var e in ((!) consts).obj.entries) {
                constants[e.key] = e.value.str;
            }
        }

        Jv? vectors = ((!) root).member("vectors");
        if (vectors == null || ((!) vectors).kind != Jv.Kind.ARRAY) {
            add_test("group_accept_CORPUS_HAS_NO_VECTORS", () => {
                fail_if_reached("conformance/v1/group-accept.json carries no `vectors` array");
            });
            return;
        }

        declared = ((!) vectors).arr.size;
        foreach (Jv item in ((!) vectors).arr) {
            Jv vector = item;
            Jv? id_node = vector.member("id");
            string id = (id_node != null) ? ((!) id_node).str : "<unnamed>";
            add_test(@"group_accept_$id", () => { run_vector(id, vector); });
        }

        /* Guards the one failure mode per-vector tests cannot see: vectors silently
         * disappearing, whether from the file or from this loop. */
        add_test("group_accept_all_vectors_executed", () => {
            fail_if_not(executed == declared,
                @"executed $executed of $declared corpus vectors — every vector MUST run (§19.2.0)");
            fail_if_not(declared > 0, "the corpus declared no vectors at all");
        });
    }

    /* Resolve the corpus. This client is a git submodule, so the file lives in the
     * PARENT repository; walking upward finds it from either the build directory or
     * the test binary's location, and the environment variable lets a packager point
     * at it explicitly. */
    private static string? find_corpus() {
        string? env = GLib.Environment.get_variable("X3DHPQ_CONFORMANCE_DIR");
        if (env != null) {
            string direct = Path.build_filename((!) env, "v1", "group-accept.json");
            if (FileUtils.test(direct, FileTest.EXISTS)) return direct;
        }

        var roots = new Gee.ArrayList<string>();
        roots.add(GLib.Environment.get_current_dir());
        try {
            roots.add(Path.get_dirname(FileUtils.read_link("/proc/self/exe")));
        } catch (GLib.Error e) {
            // /proc unavailable; the working directory is still a candidate.
        }

        foreach (string root in roots) {
            string dir = root;
            for (int depth = 0; depth < 10; depth++) {
                string candidate = Path.build_filename(dir, "conformance", "v1", "group-accept.json");
                if (FileUtils.test(candidate, FileTest.EXISTS)) return candidate;
                string parent = Path.get_dirname(dir);
                if (parent == dir) break;
                dir = parent;
            }
        }
        return null;
    }

    // Vectors name constants; the constants map holds the values.
    private string konst(string name) {
        return constants.has_key(name) ? constants[name] : name;
    }

    private static uint64 hex64(string hex) {
        uint64 v = 0;
        for (int i = 0; i < hex.length; i++) {
            int d = "0123456789abcdef".index_of_char(hex[i].tolower());
            if (d < 0) continue;
            v = (v << 4) | (uint64) d;
        }
        return v;
    }

    private void run_vector(string id, Jv vector) {
        executed++;
        var problems = new Gee.ArrayList<string>();
        try {
            evaluate(id, vector, problems);
        } catch (GLib.Error e) {
            problems.add("the vector could not be executed at all: " + e.message);
        }
        if (problems.size > 0) {
            /* Report EVERY mismatch this vector produced, not just the first — a
             * decision that is right for the wrong reason still has to show up. */
            var sb = new StringBuilder();
            sb.append(@"conformance vector `$id` failed:");
            foreach (string p in problems) {
                sb.append("\n  - ");
                sb.append(p);
            }
            fail_if_reached(sb.str);
        }
    }

    private void evaluate(string id, Jv vector, Gee.ArrayList<string> problems) throws GLib.Error {
        Jv receiver_spec = vector.req("receiver");
        Jv message_spec = vector.req("message");
        Jv expect_spec = vector.req("expect");

        // ---- receiver state -------------------------------------------------
        uint32 fold_epoch = (uint32) receiver_spec.int_member("fold_epoch", 0);
        bool sender_authorized = receiver_spec.bool_member("sender_authorized", true);
        bool manifest_known = receiver_spec.bool_member("sender_manifest_known", true);
        bool sender_removed = receiver_spec.bool_member("sender_removed", false);

        /* Step 1 is an INPUT, exactly as it is for Manager: authorization is resolved
         * from the Trust Manifest fold, which the protocol layer has no business
         * reaching into. That is what lets the corpus supply it directly. */
        GroupDeviceAuthorization auth = sender_authorized
            ? GroupDeviceAuthorization.AUTHORIZED
            : (manifest_known ? GroupDeviceAuthorization.NOT_AUTHORIZED
                              : GroupDeviceAuthorization.NO_MANIFEST);

        // ---- the inbound message -------------------------------------------
        string msg_fp = konst(message_spec.req("sender_aik_fp").str);
        uint32 msg_device = (uint32) message_spec.int_member("sender_device_id", 0);
        uint32 msg_epoch = (uint32) message_spec.int_member("epoch", 0);
        uint64 msg_epoch_id = hex64(konst(message_spec.req("epoch_id").str));
        string gsig_mode = message_spec.req("gsig").str;
        string aead_mode = message_spec.req("aead").str;

        /* A real sender session at the message's (epoch, epoch_id). Everything the
         * receiver will check — ciphertext, tag, per-epoch Ed25519 signature — is
         * produced by the production encrypt path, so "present_valid" really is valid
         * and the AEAD really does authenticate. */
        GroupSession sender = GroupSession.new_session(ROOM, random_aik(), msg_device);
        sender.apply_fold_epoch(msg_epoch, msg_epoch_id);
        uint8[] live_chain_key = ((!) sender.send_chain).chain_key.copy();
        uint8[] live_sig_pub = ((!) sender.send_chain).sig_pub.copy();
        uint8[] live_sig_priv = ((!) sender.send_chain).sig_priv.copy();

        // ---- restore the receiver from persisted state ----------------------
        var member_state = new StringBuilder();
        if (sender_removed) {
            member_state.append("R:%s:%u\n".printf(msg_fp, fold_epoch));
        }
        Jv? chains = receiver_spec.member("recv_chains");
        if (chains != null) {
            foreach (Jv c in ((!) chains).arr) {
                string cfp = konst(c.req("aik_fp").str);
                uint32 cdev = (uint32) c.int_member("device_id", 0);
                uint32 cepoch = (uint32) c.int_member("epoch", 0);
                uint64 cepoch_id = hex64(konst(c.req("epoch_id").str));
                bool has_sig_pub = c.bool_member("has_sig_pub", true);

                /* Only the chain the 4-tuple actually selects gets the sender's real
                 * key material. Every other chain is unrelated noise — which is the
                 * point of the epoch_id vectors: if selection is wrong, the message
                 * lands on a chain that cannot decrypt it. */
                bool selected = (cfp == msg_fp && cdev == msg_device
                                 && cepoch == msg_epoch && cepoch_id == msg_epoch_id);
                SenderChain? sc = SenderChain.restore(cepoch,
                    selected ? live_chain_key : random32(), 0, cepoch_id);
                if (sc == null) throw new IOError.FAILED("could not build a recv chain for the vector");
                ((!) sc).sig_pub = has_sig_pub
                    ? (selected ? live_sig_pub : random32())
                    : new uint8[0];
                member_state.append("RC:%s:%u:%u:%s:%s\n".printf(
                    cfp, cdev, cepoch, cepoch_id.to_string(), Base64.encode(((!) sc).marshal())));
            }
        }

        GroupSession? receiver = GroupSession.deserialize(
            ROOM, random_aik(), 99,
            "epoch=%u\nepoch_id=0\n".printf(fold_epoch),
            member_state.str);
        if (receiver == null) throw new IOError.FAILED("could not restore the receiver session");
        if (((!) receiver).epoch != fold_epoch) {
            problems.add(@"harness bug: receiver fold epoch is $(((!) receiver).epoch), vector says $fold_epoch");
        }

        // ---- produce, then damage as the vector prescribes -------------------
        GroupMessageHeader hdr;
        uint8[] ciphertext;
        uint8[] signature;
        sender.encrypt(string_bytes(PAYLOAD), out hdr, out ciphertext, out signature);

        if (aead_mode == "fail") {
            /* Flip a ciphertext byte so the tag cannot verify, then RE-SIGN: the
             * message has to reach step 6 with a signature that passes step 5, or the
             * vector would be testing the signature check instead. */
            ciphertext[ciphertext.length - 1] ^= 0xFF;
            uint8[] aad = hdr.aad_with_heads(ROOM, null);
            uint8[] signed = new uint8[aad.length + ciphertext.length];
            Memory.copy(signed, aad, aad.length);
            Memory.copy((uint8*) signed + aad.length, ciphertext, ciphertext.length);
            signature = bytes_arr(Crypto.ed25519_sign(new Bytes(live_sig_priv), new Bytes(signed)));
        } else if (aead_mode != "ok") {
            problems.add(@"vector asks for an aead mode this harness does not implement: `$aead_mode`");
            return;
        }

        /* Assign only AFTER any damage: Vala copies an array on assignment to another
         * owned variable, so mutating `signature` afterwards would leave `sig_arg`
         * holding the pristine bytes — and this vector would silently pass as ACCEPT. */
        uint8[]? sig_arg;
        switch (gsig_mode) {
            case "present_valid":
                sig_arg = signature;
                break;
            case "present_invalid":
                signature[0] ^= 0xFF;
                sig_arg = signature;
                break;
            case "absent":
                sig_arg = null;
                break;
            default:
                problems.add(@"vector asks for a gsig mode this harness does not implement: `$gsig_mode`");
                return;
        }

        // ---- THE production decision ----------------------------------------
        string state_before = chain_state_digest((!) receiver);
        GroupReceiveOutcome outcome = ((!) receiver).receive(
            msg_fp, hdr, ciphertext, null, sig_arg, auth);
        string state_after = chain_state_digest((!) receiver);

        // ---- assertions ------------------------------------------------------
        string want_decision = expect_spec.req("decision").str;
        string got_decision = outcome.decision.to_name();
        if (got_decision != want_decision) {
            problems.add(@"decision: expected $want_decision, got $got_decision ($(outcome.detail))");
        }

        var want_effects = new Gee.TreeSet<string>();
        Jv? effects = expect_spec.member("side_effects");
        if (effects != null) {
            foreach (Jv e in ((!) effects).arr) {
                string name = e.str;
                if (name != "drop_recv_chains_all_rooms" && name != "stash_for_retry"
                        && name != "fetch_manifest" && name != "recv_chain_advanced") {
                    problems.add(@"vector asks for a side effect this harness does not know: `$name`");
                }
                want_effects.add(name);
            }
        }
        var got_effects = new Gee.TreeSet<string>();
        if (outcome.drop_recv_chains_all_rooms) got_effects.add("drop_recv_chains_all_rooms");
        if (outcome.stash_for_retry) got_effects.add("stash_for_retry");
        if (outcome.fetch_manifest) got_effects.add("fetch_manifest");
        if (outcome.recv_chain_advanced) got_effects.add("recv_chain_advanced");

        foreach (string w in want_effects) {
            if (!got_effects.contains(w)) problems.add(@"missing side effect `$w`");
        }
        foreach (string g in got_effects) {
            if (!want_effects.contains(g)) problems.add(@"unexpected side effect `$g`");
        }

        if (expect_spec.bool_member("assert_state_unchanged", false)) {
            if (state_before != state_after) {
                problems.add("chain state moved on a decision the corpus requires to leave it untouched");
            }
        }

        if (want_decision == "ACCEPT") {
            /* Two extra checks the corpus implies but does not spell out: the
             * plaintext really came back, and `recv_chain_advanced` is not a flag the
             * evaluator sets while leaving the chain where it was. */
            if (outcome.plaintext == null) {
                problems.add("ACCEPT produced no plaintext");
            } else if (bytes_hex((!) outcome.plaintext) != bytes_hex(string_bytes(PAYLOAD))) {
                problems.add("ACCEPT returned a plaintext that is not the one that was encrypted");
            }
            if (state_before == state_after) {
                problems.add("ACCEPT reported recv_chain_advanced but the chain state did not move");
            }
        }
    }

    /* A stable fingerprint of every recv chain: key, chain key, index and the
     * skipped-key cache all ride in SenderChain.marshal(). Sorted, because map
     * iteration order is not part of the state being compared. */
    private static string chain_state_digest(GroupSession gs) {
        string[] lines = gs.serialize_recv_chains().split("\n");
        var kept = new Gee.ArrayList<string>();
        foreach (string l in lines) {
            if (l.strip() != "") kept.add(l);
        }
        kept.sort();
        var sb = new StringBuilder();
        foreach (string l in kept) {
            sb.append(l);
            sb.append("\n");
        }
        return sb.str;
    }

    private static uint8[] random_aik() throws GLib.Error {
        Bytes ed_pub; Bytes ed_priv; Bytes ml_pub; Bytes ml_priv;
        Crypto.generate_ed25519(out ed_pub, out ed_priv);
        Crypto.generate_mldsa65(out ml_pub, out ml_priv);
        uint8[] ed = bytes_arr(ed_pub);
        uint8[] ml = bytes_arr(ml_pub);
        uint8[] buf = new uint8[2 + 1 + 32 + ml.length];
        buf[0] = 0; buf[1] = 1; buf[2] = 1;
        Memory.copy((uint8*) buf + 3, ed, 32);
        if (ml.length > 0) Memory.copy((uint8*) buf + 35, ml, ml.length);
        return buf;
    }

    private static uint8[] random32() throws GLib.Error {
        return bytes_arr(Crypto.random_bytes(32));
    }

    private static uint8[] bytes_arr(Bytes b) {
        unowned uint8[] d = b.get_data();
        uint8[] copy = new uint8[d.length];
        Memory.copy(copy, d, d.length);
        return copy;
    }

    private static uint8[] string_bytes(string s) {
        return ((uint8[]) s.data).copy();
    }

    private static string bytes_hex(uint8[] b) {
        var sb = new StringBuilder();
        foreach (uint8 x in b) sb.append_printf("%02x", x);
        return sb.str;
    }
}

/* ------------------------------------------------------------------------- *
 * A minimal JSON reader.
 *
 * json-glib would be the obvious choice, but Dino declares no dependency on it and
 * this machine has only the runtime library, not the headers — so requiring it would
 * make the corpus unbuildable here, and a corpus that does not build is a corpus that
 * does not run. This covers exactly what the corpus uses: objects, arrays, strings
 * with escapes, numbers, booleans and null. It is strict: anything it does not
 * recognise yields null, which surfaces as a loud CORPUS_UNPARSEABLE failure rather
 * than a half-read file.
 * ------------------------------------------------------------------------- */

private class Jv : Object {
    public enum Kind { OBJECT, ARRAY, STRING, NUMBER, BOOL, NUL }

    public Kind kind { get; set; default = Kind.NUL; }
    public string str { get; set; default = ""; }
    public double num { get; set; default = 0.0; }
    public bool flag { get; set; default = false; }
    public Gee.HashMap<string, Jv> obj { get; set; default = new Gee.HashMap<string, Jv>(); }
    public Gee.ArrayList<Jv> arr { get; set; default = new Gee.ArrayList<Jv>(); }

    public Jv? member(string name) {
        if (kind != Kind.OBJECT) return null;
        return obj.has_key(name) ? obj[name] : null;
    }

    public Jv req(string name) throws GLib.Error {
        Jv? v = member(name);
        if (v == null) throw new IOError.FAILED(@"corpus vector is missing the required field `$name`");
        return (!) v;
    }

    public int int_member(string name, int fallback) {
        Jv? v = member(name);
        return (v != null && ((!) v).kind == Kind.NUMBER) ? (int) ((!) v).num : fallback;
    }

    public bool bool_member(string name, bool fallback) {
        Jv? v = member(name);
        return (v != null && ((!) v).kind == Kind.BOOL) ? ((!) v).flag : fallback;
    }
}

private class JsonReader : Object {
    private string s;
    private int i = 0;

    public JsonReader(string s) {
        this.s = s;
    }

    public Jv? parse() {
        skip_ws();
        Jv? v = read_value();
        if (v == null) return null;
        skip_ws();
        return (i >= s.length) ? v : null;
    }

    private void skip_ws() {
        while (i < s.length) {
            char c = s[i];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++;
            else break;
        }
    }

    private Jv? read_value() {
        if (i >= s.length) return null;
        char c = s[i];
        if (c == '{') return read_object();
        if (c == '[') return read_array();
        if (c == '"') {
            string? str = read_string();
            if (str == null) return null;
            var v = new Jv();
            v.kind = Jv.Kind.STRING;
            v.str = (!) str;
            return v;
        }
        if (s.substring(i).has_prefix("true")) { i += 4; var v = new Jv(); v.kind = Jv.Kind.BOOL; v.flag = true; return v; }
        if (s.substring(i).has_prefix("false")) { i += 5; var v = new Jv(); v.kind = Jv.Kind.BOOL; v.flag = false; return v; }
        if (s.substring(i).has_prefix("null")) { i += 4; var v = new Jv(); v.kind = Jv.Kind.NUL; return v; }
        return read_number();
    }

    private Jv? read_object() {
        i++;  // '{'
        var v = new Jv();
        v.kind = Jv.Kind.OBJECT;
        skip_ws();
        if (i < s.length && s[i] == '}') { i++; return v; }
        while (true) {
            skip_ws();
            string? key = read_string();
            if (key == null) return null;
            skip_ws();
            if (i >= s.length || s[i] != ':') return null;
            i++;
            skip_ws();
            Jv? val = read_value();
            if (val == null) return null;
            v.obj[(!) key] = (!) val;
            skip_ws();
            if (i >= s.length) return null;
            if (s[i] == ',') { i++; continue; }
            if (s[i] == '}') { i++; return v; }
            return null;
        }
    }

    private Jv? read_array() {
        i++;  // '['
        var v = new Jv();
        v.kind = Jv.Kind.ARRAY;
        skip_ws();
        if (i < s.length && s[i] == ']') { i++; return v; }
        while (true) {
            skip_ws();
            Jv? item = read_value();
            if (item == null) return null;
            v.arr.add((!) item);
            skip_ws();
            if (i >= s.length) return null;
            if (s[i] == ',') { i++; continue; }
            if (s[i] == ']') { i++; return v; }
            return null;
        }
    }

    private string? read_string() {
        if (i >= s.length || s[i] != '"') return null;
        i++;
        var sb = new StringBuilder();
        while (i < s.length) {
            char c = s[i];
            if (c == '"') { i++; return sb.str; }
            if (c == '\\') {
                i++;
                if (i >= s.length) return null;
                char e = s[i];
                switch (e) {
                    case '"':  sb.append_c('"');  break;
                    case '\\': sb.append_c('\\'); break;
                    case '/':  sb.append_c('/');  break;
                    case 'b':  sb.append_c('\b'); break;
                    case 'f':  sb.append_c('\f'); break;
                    case 'n':  sb.append_c('\n'); break;
                    case 'r':  sb.append_c('\r'); break;
                    case 't':  sb.append_c('\t'); break;
                    case 'u':
                        if (i + 4 >= s.length) return null;
                        int cp = 0;
                        for (int k = 1; k <= 4; k++) {
                            int d = "0123456789abcdef".index_of_char(s[i + k].tolower());
                            if (d < 0) return null;
                            cp = cp * 16 + d;
                        }
                        sb.append_unichar((unichar) cp);
                        i += 4;
                        break;
                    default: return null;
                }
                i++;
                continue;
            }
            sb.append_c(c);
            i++;
        }
        return null;
    }

    private Jv? read_number() {
        int start = i;
        if (i < s.length && (s[i] == '-' || s[i] == '+')) i++;
        bool any = false;
        while (i < s.length) {
            char c = s[i];
            if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '-' || c == '+') {
                any = true;
                i++;
            } else break;
        }
        if (!any) return null;
        var v = new Jv();
        v.kind = Jv.Kind.NUMBER;
        v.num = double.parse(s.substring(start, i - start));
        return v;
    }
}

}
