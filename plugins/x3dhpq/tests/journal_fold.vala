/* SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * conformance/v2/journal-fold.json — the shared corpus's SECOND file, executed against
 * the PRODUCTION membership fold.
 *
 * Where group-accept.json pins what a receiver DECIDES, this pins what the membership
 * journal FOLDS TO — the layer where the epoch-numbering divergence that started the
 * corpus actually lived. One client derived the group epoch from the fold, the other
 * from a local member-change counter; both encoded `uint32 epoch` identically and both
 * passed every byte-level KAT, because a KAT pins Marshal() and neither bug is reachable
 * from Marshal(). The decision table cannot reach it either — it takes the fold state as
 * an INPUT. This file is where that input is checked.
 *
 * THE SAME TWO RULES GOVERN THIS FILE AS conformance.vala.
 *
 * 1. It must not reimplement the fold. Every vector goes through
 *    MembershipDag.recompute_authorized(), the same entry point Manager's live
 *    recompute_dag_pinned() calls. What this file builds is only the INPUT: a DAG loaded
 *    with the corpus's signed blobs (delivered in the corpus's order, which is
 *    deliberately NOT canonical for several vectors), an AIK resolver over the corpus's
 *    published identities, and the §13.1a.0 step-5 issuer verdict the corpus states.
 *    A harness that sorted the entries itself, or that decided authorization itself,
 *    would agree with itself and pin nothing.
 *
 * 2. A vector it cannot execute is a FAILURE, not a skip — including a missing corpus
 *    file, an unreadable identity, or a `device_auth` value this harness does not know.
 *
 * On the three inputs the corpus supplies from outside the entries: `device_auth` is the
 * RESOLVED §13.1a.0 step-5 status per (account, device id), `pinned_owner` is the durable
 * §13.1a.1 owner pin, and `identities` is the AIK material the fold verifies signatures
 * against. All three are app-layer state in production — the fold has no business
 * reaching into the Trust Manifest store — which is exactly why the corpus states them
 * directly: a vector then pins the FOLD rather than one client's manifest bookkeeping.
 */

namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

class JournalFoldTest : Gee.TestCase {

    /* The corpus's own count, pinned here. Every other test in this file is per-vector,
     * so all of them together cannot see a vector that silently disappeared from the
     * file — a truncated corpus would simply report fewer green tests, which reads as
     * clean. This is the one assertion that catches it. */
    private const int EXPECTED_VECTORS = 18;

    private string room_jid = "";
    // Constant name (OWNER_FP, …) -> raw-hex fingerprint, lowercased.
    private Gee.HashMap<string, string> constants = new Gee.HashMap<string, string>();
    // fp hex -> the published AIK halves, for the fold's AikResolver.
    private Gee.HashMap<string, Bytes> aik_ed = new Gee.HashMap<string, Bytes>();
    private Gee.HashMap<string, Bytes> aik_ml = new Gee.HashMap<string, Bytes>();
    /* "<fp hex>/<device id>" -> IssuerAuthStatus, rebuilt per vector. A field rather
     * than a parameter because DeviceIssuerChecker is a delegate the fold calls back
     * into; the vector under test owns it for the duration of that fold. */
    private Gee.HashMap<string, int> device_auth = new Gee.HashMap<string, int>();

    private int executed = 0;
    private int declared = 0;

    public JournalFoldTest() {
        base("JournalFold");

        string? path = find_corpus();
        if (path == null) {
            /* Loud, not silent. A build that cannot see the corpus has not run it, and
             * pretending otherwise is worse than not having one (README rule 1). */
            add_test("journal_fold_CORPUS_NOT_FOUND", () => {
                fail_if_reached("conformance/v2/journal-fold.json not found. Looked at "
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
            add_test("journal_fold_CORPUS_UNREADABLE", () => {
                fail_if_reached(@"cannot read the conformance corpus at $p");
            });
            return;
        }

        Jv? root = new JsonReader(contents).parse();
        if (root == null || ((!) root).kind != Jv.Kind.OBJECT) {
            add_test("journal_fold_CORPUS_UNPARSEABLE", () => {
                fail_if_reached("conformance/v2/journal-fold.json did not parse as a JSON object");
            });
            return;
        }

        Jv? room = ((!) root).member("room_jid");
        if (room == null || ((!) room).kind != Jv.Kind.STRING) {
            add_test("journal_fold_CORPUS_HAS_NO_ROOM_JID", () => {
                fail_if_reached("the corpus carries no `room_jid`; epoch_id is derived from "
                    + "it (§13.5a), so every epoch_id assertion would be vacuous");
            });
            return;
        }
        room_jid = ((!) room).str;

        Jv? consts = ((!) root).member("constants");
        if (consts != null && ((!) consts).kind == Jv.Kind.OBJECT) {
            foreach (var e in ((!) consts).obj.entries) {
                if (e.value.kind == Jv.Kind.STRING) constants[e.key] = e.value.str.down();
            }
        }

        /* Load the AIK material the fold verifies against. This is not decoration: the
         * fold resolves the signer's AIK for every entry, and a kind-1 RetireMember
         * additionally resolves the RETIRED member's AIK to re-verify the embedded
         * pointer (§13.5c). Without them several vectors cannot execute at all. */
        var identity_problems = new Gee.ArrayList<string>();
        load_identities(((!) root).member("identities"), identity_problems);
        add_test("journal_fold_identities_match_their_fingerprints", () => {
            report("identities", identity_problems);
        });

        /* The `defaults` and `harness_inputs` blocks are normative in the same way
         * group-accept's is: they are what makes "this field is absent" mean the same
         * thing in both implementations. An absent field is invisible at run time — no
         * vector can catch a harness that guessed the wrong fallback — so both blocks
         * are compared directly against what this file actually does. */
        Jv? defaults = ((!) root).member("defaults");
        add_test("journal_fold_defaults_match_harness", () => { check_defaults(defaults); });
        Jv? inputs = ((!) root).member("harness_inputs");
        add_test("journal_fold_harness_inputs_implemented", () => { check_inputs(inputs); });

        Jv? vectors = ((!) root).member("vectors");
        if (vectors == null || ((!) vectors).kind != Jv.Kind.ARRAY) {
            add_test("journal_fold_CORPUS_HAS_NO_VECTORS", () => {
                fail_if_reached("conformance/v2/journal-fold.json carries no `vectors` array");
            });
            return;
        }

        declared = ((!) vectors).arr.size;
        foreach (Jv item in ((!) vectors).arr) {
            Jv vector = item;
            Jv? id_node = vector.member("id");
            string id = (id_node != null) ? ((!) id_node).str : "<unnamed>";
            add_test(@"journal_fold_$id", () => { run_vector(id, vector); });
        }

        add_test("journal_fold_all_vectors_executed", () => {
            fail_if_not(executed == declared,
                @"executed $executed of $declared corpus vectors — every vector MUST run (§19.2.0)");
            fail_if_not(declared == EXPECTED_VECTORS,
                @"the corpus declares $declared vectors, this suite is pinned to $EXPECTED_VECTORS. "
                + "Vectors are append-only within a version (README rule 3): a corpus that "
                + "SHRANK is a truncated file, and one that grew needs this pin raised in the "
                + "same change that reviews the new vectors.");
        });
    }

    /* Resolve the corpus. This client is a git submodule, so the file lives in the PARENT
     * repository; walking upward finds it from either the build directory or the test
     * binary's location, and the environment variable lets a packager point at it. */
    private static string? find_corpus() {
        string? env = GLib.Environment.get_variable("X3DHPQ_CONFORMANCE_DIR");
        if (env != null) {
            string direct = Path.build_filename((!) env, "v2", "journal-fold.json");
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
                string candidate = Path.build_filename(dir, "conformance", "v2", "journal-fold.json");
                if (FileUtils.test(candidate, FileTest.EXISTS)) return candidate;
                string parent = Path.get_dirname(dir);
                if (parent == dir) break;
                dir = parent;
            }
        }
        return null;
    }

    /* Every AIK the corpus publishes, keyed by fingerprint, plus the check that each one
     * really IS the identity its constant names. That check is the whole reason to do
     * this rather than trust the map: the resolver is keyed by fingerprint, so a
     * mislabelled identity would silently make some entries unverifiable and quietly
     * turn accepted vectors into "unauthorized" ones — which looks like a protocol
     * disagreement rather than a corrupt input. */
    private void load_identities(Jv? identities, Gee.ArrayList<string> problems) {
        if (identities == null || ((!) identities).kind != Jv.Kind.OBJECT) {
            problems.add("the corpus carries no `identities` map; the fold cannot resolve a "
                + "single signer AIK without it and no vector could execute");
            return;
        }
        foreach (var e in ((!) identities).obj.entries) {
            if (e.key == "note") continue;
            if (e.value.kind != Jv.Kind.STRING) {
                problems.add(@"identity `$(e.key)` is not a base64 string");
                continue;
            }
            uint8[] raw = Base64.decode(e.value.str);
            AccountIdentityPub? pub = AccountIdentityPub.unmarshal(raw);
            if (pub == null) {
                problems.add(@"identity `$(e.key)` did not parse as AccountIdentityPub (§7.2)");
                continue;
            }
            string fp;
            try {
                fp = hex(bytes_arr(Crypto.blake2b160(new Bytes(((!) pub).marshal()))));
            } catch (GLib.Error err) {
                problems.add(@"identity `$(e.key)`: could not fingerprint it: $(err.message)");
                continue;
            }
            if (!constants.has_key(e.key)) {
                problems.add(@"identity `$(e.key)` names no constant, so nothing refers to it");
                continue;
            }
            if (fp != constants[e.key]) {
                problems.add(@"identity `$(e.key)` fingerprints to $fp, but the constant says "
                    + @"$(constants[e.key]) — the resolver would be keyed on the wrong AIK");
                continue;
            }
            aik_ed[fp] = new Bytes(((!) pub).pub_ed25519);
            aik_ml[fp] = new Bytes(((!) pub).pub_mldsa);
        }
        foreach (string name in constants.keys) {
            if (!((!) identities).obj.has_key(name)) {
                problems.add(@"constant `$name` has no published identity, so any entry it "
                    + "signs or any pointer naming it cannot be verified");
            }
        }
    }

    /* Every fallback this harness applies for an optional corpus field, keyed exactly as
     * the corpus `defaults` block keys it, and rendered as JSON so a default of any shape
     * compares the same way. */
    private static Gee.HashMap<string, string> harness_defaults() {
        var d = new Gee.HashMap<string, string>();
        d["device_auth[*]"]      = "\"EVER_AUTHORIZED\"";
        d["pinned_owner"]        = "\"OWNER_FP\"";
        d["expect.removed"]      = "[]";
        d["expect.banned"]       = "[]";
        d["expect.retired"]      = "[]";
        d["expect.unauthorized"] = "[]";
        d["expect.quarantined"]  = "[]";
        return d;
    }

    private static void check_defaults(Jv? defaults) {
        if (defaults == null || ((!) defaults).kind != Jv.Kind.OBJECT) {
            fail_if_reached("the corpus carries no `defaults` object; absent-field behaviour "
                + "would then be agreed only by coincidence (§19.2.0)");
            return;
        }
        var expected = harness_defaults();
        var problems = new Gee.ArrayList<string>();

        foreach (var e in ((!) defaults).obj.entries) {
            if (e.key == "note") continue;
            if (!expected.has_key(e.key)) {
                problems.add(@"the corpus declares a default for `$(e.key)` that this harness "
                    + "does not implement — every vector omitting that field is running untested");
                continue;
            }
            string got = render(e.value);
            if (got != expected[e.key]) {
                problems.add(@"default for `$(e.key)`: corpus says $got, harness falls back to $(expected[e.key])");
            }
        }
        foreach (string k in expected.keys) {
            if (!((!) defaults).obj.has_key(k)) {
                problems.add(@"this harness falls back on `$k`, which the corpus no longer declares a default for");
            }
        }
        report("the corpus `defaults` block and this harness disagree", problems);
    }

    /* The corpus names, in `harness_inputs`, every value the fold takes from the app
     * layer rather than from the entries. An input this harness ignored would leave the
     * vectors that rely on it testing something other than what they say — and silently,
     * because ignoring an input mostly still produces A fold. */
    private static void check_inputs(Jv? inputs) {
        if (inputs == null || ((!) inputs).kind != Jv.Kind.OBJECT) {
            fail_if_reached("the corpus carries no `harness_inputs` object, so which values "
                + "the fold takes from outside the entries is agreed only by coincidence");
            return;
        }
        var implemented = new Gee.TreeSet<string>();
        implemented.add("device_auth");    // -> DeviceIssuerChecker (§13.1a.0 step 5)
        implemented.add("pinned_owner");   // -> recompute_authorized's pin (§13.1a.1)

        var problems = new Gee.ArrayList<string>();
        foreach (var e in ((!) inputs).obj.entries) {
            if (e.key == "note") continue;
            if (!implemented.contains(e.key)) {
                problems.add(@"the corpus declares a harness input `$(e.key)` this file does "
                    + "not feed into the fold; every vector that sets it is running untested");
            }
        }
        foreach (string k in implemented) {
            if (!((!) inputs).obj.has_key(k)) {
                problems.add(@"this harness feeds `$k` into the fold, but the corpus no longer "
                    + "declares it as an input — the two sides disagree about what a vector states");
            }
        }
        report("the corpus `harness_inputs` block and this harness disagree", problems);
    }

    // Just enough JSON rendering to compare a declared default with a harness fallback.
    private static string render(Jv v) {
        switch (v.kind) {
            case Jv.Kind.BOOL:   return v.flag ? "true" : "false";
            case Jv.Kind.STRING: return "\"" + v.str + "\"";
            case Jv.Kind.NUL:    return "null";
            case Jv.Kind.NUMBER: return "%g".printf(v.num);
            case Jv.Kind.ARRAY:
                var sb = new StringBuilder("[");
                bool first = true;
                foreach (Jv e in v.arr) {
                    if (!first) sb.append(",");
                    sb.append(render(e));
                    first = false;
                }
                sb.append("]");
                return sb.str;
            default: return "{...}";
        }
    }

    private static void report(string headline, Gee.ArrayList<string> problems) {
        if (problems.size == 0) return;
        var sb = new StringBuilder();
        sb.append(headline);
        sb.append(":");
        foreach (string p in problems) {
            sb.append("\n  - ");
            sb.append(p);
        }
        fail_if_reached(sb.str);
    }

    // Vectors name constants; the constants map holds the raw-hex fingerprints.
    private string konst(string name) {
        return constants.has_key(name) ? constants[name] : name.down();
    }

    private void run_vector(string id, Jv vector) {
        executed++;
        var problems = new Gee.ArrayList<string>();
        try {
            evaluate(id, vector, problems);
        } catch (GLib.Error e) {
            problems.add("the vector could not be executed at all: " + e.message);
        }
        /* Report EVERY mismatch this vector produced, not just the first: a fold that is
         * right about the member set and wrong about the epoch is a different bug from
         * one that is wrong about both, and the corpus exists to tell them apart. */
        report(@"conformance vector `$id` failed", problems);
    }

    private void evaluate(string id, Jv vector, Gee.ArrayList<string> problems) throws GLib.Error {
        Jv entries = vector.req("entries");
        if (entries.kind != Jv.Kind.ARRAY || entries.arr.size == 0) {
            problems.add("the vector carries no `entries` array");
            return;
        }
        Jv expect = vector.req("expect");

        /* ---- the §13.1a.0 step-5 verdict, as the app layer would supply it ----------
         *
         * Production resolves this from the Trust Manifest fold and the revocation
         * tombstone store (Manager.make_issuer_checker), which the protocol layer has no
         * business reaching into — which is exactly what lets the corpus state it. No
         * separate DeviceRevocationChecker is passed: step 5 subsumes the tombstone
         * check (a positive tombstone resolves to REVOKED here), and the corpus states
         * tombstones that way. */
        device_auth = new Gee.HashMap<string, int>();
        Jv? auth = vector.member("device_auth");
        if (auth != null) {
            if (((!) auth).kind != Jv.Kind.OBJECT) {
                problems.add("`device_auth` is present but is not an object");
                return;
            }
            foreach (var e in ((!) auth).obj.entries) {
                int slash = e.key.last_index_of_char('/');
                if (slash <= 0) {
                    problems.add(@"device_auth key `$(e.key)` is not `<CONSTANT>/<device_id>`");
                    continue;
                }
                string who = konst(e.key.substring(0, slash));
                string dev = e.key.substring(slash + 1);
                string status = (e.value.kind == Jv.Kind.STRING) ? e.value.str : "";
                int mapped;
                switch (status) {
                    case "EVER_AUTHORIZED": mapped = (int) IssuerAuthStatus.AUTHORIZED; break;
                    case "REVOKED":         mapped = (int) IssuerAuthStatus.REJECTED;   break;
                    case "UNRESOLVED":      mapped = (int) IssuerAuthStatus.UNRESOLVED; break;
                    default:
                        /* A status this harness does not know must not silently fall
                         * back to the default: the vector would then pin the opposite of
                         * what it says and pass. */
                        problems.add(@"device_auth `$(e.key)` asks for a status this harness "
                            + @"does not implement: `$status`");
                        continue;
                }
                device_auth[@"$who/$dev"] = mapped;
            }
            if (problems.size > 0) return;
        }

        // ---- the §13.1a.1 durable owner pin ---------------------------------
        Jv? pin_node = vector.member("pinned_owner");
        string? pin;
        if (pin_node == null) {
            pin = konst("OWNER_FP");                      // corpus `defaults`
        } else if (((!) pin_node).kind == Jv.Kind.NUL) {
            pin = null;                                   // explicitly unpinned
        } else if (((!) pin_node).kind == Jv.Kind.STRING) {
            pin = konst(((!) pin_node).str);
        } else {
            problems.add("`pinned_owner` is neither a constant name nor null");
            return;
        }

        /* ---- load the DAG in the corpus's DELIVERY order ----------------------------
         *
         * Deliberately not sorted here. Canonical order is content-derived (§13.1a) and
         * deriving it is the production fold's job; a harness that pre-sorted would hide
         * exactly the bug the two `delivery-order-does-not-matter` twins exist to catch. */
        var dag = new MembershipDag();
        var index_of = new Gee.HashMap<string, int>();    // entry_hash hex -> delivery index
        for (int i = 0; i < entries.arr.size; i++) {
            Jv item = entries.arr[i];
            if (item.kind != Jv.Kind.STRING) {
                problems.add(@"entry $i is not a base64 string");
                return;
            }
            uint8[] raw = Base64.decode(item.str);
            JournalEntryV2? parsed = JournalEntryV2.unmarshal(raw);
            if (parsed == null) {
                problems.add(@"entry $i did not parse as a JournalEntryV2 (§13.1a)");
                return;
            }
            string h = ((!) parsed).hash_hex();
            if (index_of.has_key(h)) {
                problems.add(@"entry $i repeats entry $(index_of[h]) byte for byte; the "
                    + "vector's index lists could not then name either one");
                return;
            }
            index_of[h] = i;
            if (!dag.ingest(raw)) {
                problems.add(@"entry $i was refused by the DAG store");
                return;
            }
        }

        // ---- THE production fold --------------------------------------------
        DagState st = dag.recompute_authorized(resolver(), pin, null, issuer_checker());

        // ---- assertions ------------------------------------------------------
        compare_fps("members", st.members, expect.member("members"), problems);
        compare_fps("admins", st.admins, expect.member("admins"), problems);
        compare_fps("removed", st.removed.keys, expect.member("removed"), problems);
        compare_fps("banned", st.banned, expect.member("banned"), problems);
        compare_fps("retired", st.retired, expect.member("retired"), problems);

        int want_epoch = expect.int_member("epoch", -1);
        if ((int) st.epoch != want_epoch) {
            problems.add(@"epoch: expected $want_epoch, got $((int) st.epoch) — the epoch is "
                + "the count of AUTHORIZED rotation-causing entries in this fold (§13.1a.0)");
        }

        string want_fold_hash = expect.req("fold_hash").str.down();
        string got_fold_hash = hex(st.fold_hash);
        if (got_fold_hash != want_fold_hash) {
            problems.add(@"fold_hash: expected $want_fold_hash, got $got_fold_hash (§13.5a)");
        }

        string want_epoch_id = expect.req("epoch_id").str.down();
        string got_epoch_id = hex64(st.epoch_id(room_jid));
        if (got_epoch_id != want_epoch_id) {
            problems.add(@"epoch_id for `$room_jid`: expected $want_epoch_id, got $got_epoch_id (§13.5a)");
        }

        /* `accepted` is compared IN ORDER: it is the canonical fold order, and it is the
         * sequence fold_hash is computed over (§13.5a), so an implementation that
         * accepted the right set in the wrong order has a different fold_hash and a
         * different epoch_id — a real divergence, not a presentation detail.
         *
         * `unauthorized` and `quarantined` are compared as SETS. The corpus documents
         * them as index lists without fixing an order, so pinning one here would be this
         * harness inventing a requirement the corpus does not state. */
        compare_indices("accepted", st.accepted, index_of, expect.member("accepted"), true, problems);
        compare_indices("unauthorized", st.unauthorized, index_of, expect.member("unauthorized"), false, problems);
        compare_indices("quarantined", st.quarantined, index_of, expect.member("quarantined"), false, problems);
    }

    /* The fold's AikResolver over the corpus identities. Keyed by fingerprint, which is
     * how the fold asks: it holds `signer_fp` off the wire, and for a kind-1
     * RetireMember it also asks for the RETIRED identity's AIK to re-verify the pointer
     * against the key the ROOM holds (§13.5c step 3). */
    private AikResolver resolver() {
        return (fp_hex, out ed, out ml) => {
            string k = fp_hex.down();
            if (!aik_ed.has_key(k)) {
                ed = new Bytes(new uint8[0]);
                ml = new Bytes(new uint8[0]);
                return false;
            }
            ed = aik_ed[k];
            ml = aik_ml[k];
            return true;
        };
    }

    /* §13.1a.0 step 5, resolved. Absent from the map means EVER_AUTHORIZED, which is what
     * the corpus `defaults` block declares — checked against this harness by
     * journal_fold_defaults_match_harness rather than left to coincide. */
    private DeviceIssuerChecker issuer_checker() {
        return (fp_hex, device_id) => {
            string k = @"$(fp_hex.down())/$device_id";
            if (!device_auth.has_key(k)) return IssuerAuthStatus.AUTHORIZED;
            return (IssuerAuthStatus) device_auth[k];
        };
    }

    /* Compare a folded fingerprint set against the vector's list of constant names.
     * Sorted ascending, because the corpus states these as sets and equality must not
     * depend on hash-map iteration order. Fixed-width lowercase hex sorts identically to
     * the raw bytes it encodes, which is the order the corpus specifies. */
    private void compare_fps(string field, Gee.Collection<string> got_set, Jv? want_node,
                             Gee.ArrayList<string> problems) {
        var want = new Gee.ArrayList<string>();
        if (want_node != null) {
            if (((!) want_node).kind != Jv.Kind.ARRAY) {
                problems.add(@"`$field` is present in the vector but is not an array");
                return;
            }
            foreach (Jv e in ((!) want_node).arr) want.add(konst(e.str));
        }
        var got = new Gee.ArrayList<string>();
        foreach (string s in got_set) got.add(s.down());
        want.sort((a, b) => strcmp(a, b));
        got.sort((a, b) => strcmp(a, b));
        string w = join(want);
        string g = join(got);
        if (w != g) {
            problems.add(@"$field: expected [$(names(want))], got [$(names(got))]");
        }
    }

    /* Compare one of the three disposition lists. The fold reports entry_hashes; the
     * corpus reports indices into its own `entries` array, which for the permuted vectors
     * is deliberately not the fold order — so mapping hash to index here is what makes
     * "you accepted a different set, here it is" readable rather than a digest mismatch. */
    private void compare_indices(string field, Gee.ArrayList<string> got_hashes,
                                 Gee.HashMap<string, int> index_of, Jv? want_node,
                                 bool ordered, Gee.ArrayList<string> problems) {
        var want = new Gee.ArrayList<string>();
        if (want_node != null) {
            if (((!) want_node).kind != Jv.Kind.ARRAY) {
                problems.add(@"`$field` is present in the vector but is not an array");
                return;
            }
            foreach (Jv e in ((!) want_node).arr) want.add(((int) e.num).to_string());
        }
        var got = new Gee.ArrayList<string>();
        foreach (string h in got_hashes) {
            got.add(index_of.has_key(h) ? index_of[h].to_string() : @"<not delivered:$(h.substring(0, 12))>");
        }
        if (!ordered) {
            want.sort((a, b) => strcmp(a, b));
            got.sort((a, b) => strcmp(a, b));
        }
        if (join(want) != join(got)) {
            string how = ordered ? " (in canonical fold order)" : "";
            problems.add(@"$field$how: expected [$(join_commas(want))], got [$(join_commas(got))]");
        }
    }

    // Render a fingerprint list back as constant names where possible, so a failure names
    // ALICE_FP rather than 40 hex characters.
    private string names(Gee.ArrayList<string> fps) {
        var sb = new StringBuilder();
        bool first = true;
        foreach (string fp in fps) {
            if (!first) sb.append(", ");
            first = false;
            string label = fp;
            foreach (var e in constants.entries) {
                if (e.value == fp) { label = e.key; break; }
            }
            sb.append(label);
        }
        return sb.str;
    }

    private static string join(Gee.ArrayList<string> l) {
        var sb = new StringBuilder();
        foreach (string s in l) { sb.append(s); sb.append("|"); }
        return sb.str;
    }

    private static string join_commas(Gee.ArrayList<string> l) {
        var sb = new StringBuilder();
        bool first = true;
        foreach (string s in l) {
            if (!first) sb.append(", ");
            first = false;
            sb.append(s);
        }
        return sb.str;
    }

    private static string hex(uint8[] b) {
        var sb = new StringBuilder();
        foreach (uint8 x in b) sb.append_printf("%02x", x);
        return sb.str;
    }

    /* 16 lowercase hex digits, big-endian, which is how the corpus writes epoch_id.
     * Built by hand rather than with a printf length modifier so it cannot depend on how
     * uint64 happens to be typedef'd on the build host. */
    private static string hex64(uint64 v) {
        var sb = new StringBuilder();
        for (int i = 15; i >= 0; i--) {
            sb.append_printf("%x", (uint) ((v >> (i * 4)) & 0xF));
        }
        return sb.str;
    }

    private static uint8[] bytes_arr(Bytes b) {
        unowned uint8[] d = b.get_data();
        uint8[] copy = new uint8[d.length];
        Memory.copy(copy, d, d.length);
        return copy;
    }
}

}
