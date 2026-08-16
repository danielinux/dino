/* SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * conformance/v2/issuer-status.json — the shared corpus's THIRD file, executed against
 * the production §13.1a.0 step-5 resolver.
 *
 * This file used to hold a hand-written truth table of the same decision. It no longer
 * does, and that is the whole point: the table it pinned was written by this client,
 * from this client's reading of §13.1a.0, and a table each implementation writes for
 * itself agrees with itself and pins nothing across clients. The divergence it was added
 * to catch — Dino answering REJECTED where PQonversations answered UNRESOLVED for
 * "manifest history held, device id never in it" — was invisible to every byte-level KAT
 * and to all 18 journal-fold vectors, because journal-fold takes the resolved status as a
 * harness INPUT. Both clients now drive the SAME sixteen vectors from the SAME file, so
 * a future re-divergence has to break a shared artifact rather than one client's opinion.
 *
 * THE SAME TWO RULES GOVERN THIS FILE AS conformance.vala AND journal_fold.vala.
 *
 * 1. It must not reimplement the decision. Every vector goes through
 *    Protocol.classify_issuer() and Protocol.issuer_status_wants_manifest_fetch(), the
 *    same two functions Manager.recompute_dag_pinned()'s issuer callback calls. All this
 *    harness builds is the four-boolean input.
 *
 * 2. A vector it cannot execute is a FAILURE, not a skip — a missing corpus file, an
 *    absent input, or a status string this harness does not know.
 *
 * Both halves of each vector are asserted. The status alone is not enough: an UNRESOLVED
 * that never triggers a manifest fetch is behaviourally identical to REJECTED after the
 * first fold, and self-healing is the entire reason quarantine was chosen over rejection.
 * The corpus pins `wants_manifest_fetch` for all sixteen combinations for exactly that
 * reason, so this harness asserts it for all sixteen.
 *
 * Several vectors state input combinations that cannot arise together in a well-formed
 * store (`ever_authorized` true with `manifest_history_held` false). They are deliberate
 * and are asserted like any other: they are what distinguishes one check ORDER from
 * another, so an implementation that reorders the tombstone and history tests fails a
 * vector rather than merely making one unreachable.
 */

namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

class IssuerStatusTest : Gee.TestCase {

    /* The corpus's own count, pinned here. Every other test in this file is per-vector,
     * so all of them together cannot see a vector that silently disappeared from the
     * file — a truncated corpus would simply report fewer green tests, which reads as
     * clean. This is the one assertion that catches it. It is also load-bearing in a way
     * it is not in the other harnesses: sixteen is not an arbitrary corpus size here, it
     * is 2^4, the COMPLETE truth table. Fifteen vectors is not a smaller corpus, it is an
     * incomplete one, and the missing row is exactly where a check-order divergence
     * hides. */
    private const int EXPECTED_VECTORS = 16;

    /* The order in which classify_issuer() answers the four facts, mirrored from the
     * implementation so it can be compared against the corpus's `check_order` block.
     * The contradictory-input vectors already pin this order behaviourally; this checks
     * that the corpus still DECLARES the order those vectors encode, so a corpus edit
     * that renamed or resequenced a step cannot pass by quietly agreeing with a harness
     * that stopped looking. */
    private const string[] HARNESS_CHECK_ORDER = {
        "owner_known", "tombstoned", "manifest_history_held", "ever_authorized"
    };

    /* Every input key this harness reads, and every status string it can map. Checked
     * against the corpus's `inputs` and `outputs.status` blocks: an input this harness
     * ignores would make some vectors vacuous rather than failing, which is the one
     * failure mode a per-vector assertion cannot see. */
    private static string[] harness_inputs() {
        return { "owner_known", "tombstoned", "manifest_history_held", "ever_authorized" };
    }
    private static string[] harness_statuses() {
        return { "AUTHORIZED", "REJECTED", "UNRESOLVED" };
    }

    private int executed = 0;
    private int declared = 0;

    public IssuerStatusTest() {
        base("IssuerStatus");

        string? path = find_corpus();
        if (path == null) {
            /* Loud, not silent. A build that cannot see the corpus has not run it, and
             * pretending otherwise is worse than not having one (README rule 1). */
            add_test("issuer_status_CORPUS_NOT_FOUND", () => {
                fail_if_reached("conformance/v2/issuer-status.json not found. Looked at "
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
            add_test("issuer_status_CORPUS_UNREADABLE", () => {
                fail_if_reached(@"cannot read the conformance corpus at $p");
            });
            return;
        }

        Jv? root = new JsonReader(contents).parse();
        if (root == null || ((!) root).kind != Jv.Kind.OBJECT) {
            add_test("issuer_status_CORPUS_UNPARSEABLE", () => {
                fail_if_reached("conformance/v2/issuer-status.json did not parse as a JSON object");
            });
            return;
        }

        Jv? order = ((!) root).member("check_order");
        add_test("issuer_status_check_order_matches_resolver", () => { check_order(order); });

        Jv? inputs = ((!) root).member("inputs");
        Jv? outputs = ((!) root).member("outputs");
        add_test("issuer_status_vocabulary_matches_harness", () => { check_vocabulary(inputs, outputs); });

        Jv? vectors = ((!) root).member("vectors");
        if (vectors == null || ((!) vectors).kind != Jv.Kind.ARRAY) {
            add_test("issuer_status_CORPUS_HAS_NO_VECTORS", () => {
                fail_if_reached("conformance/v2/issuer-status.json carries no `vectors` array");
            });
            return;
        }

        declared = ((!) vectors).arr.size;
        foreach (Jv item in ((!) vectors).arr) {
            Jv vector = item;
            Jv? id_node = vector.member("id");
            string id = (id_node != null) ? ((!) id_node).str : "<unnamed>";
            add_test(@"issuer_status_$id", () => { run_vector(id, vector); });
        }

        add_test("issuer_status_all_vectors_executed", () => {
            fail_if_not(executed == declared,
                @"executed $executed of $declared corpus vectors — every vector MUST run (§19.2.0)");
            fail_if_not(declared == EXPECTED_VECTORS,
                @"the corpus declares $declared vectors, this suite is pinned to $EXPECTED_VECTORS. "
                + "Sixteen is 2^4 — the complete truth table over the four inputs — so a corpus "
                + "that SHRANK is not a smaller corpus but an incomplete one, and the row it lost "
                + "is where a check-order divergence hides. One that grew needs this pin raised in "
                + "the same change that reviews the new vectors.");
        });
    }

    /* Resolve the corpus. This client is a git submodule, so the file lives in the PARENT
     * repository; walking upward finds it from either the build directory or the test
     * binary's location, and the environment variable lets a packager point at it. */
    private static string? find_corpus() {
        string? env = GLib.Environment.get_variable("X3DHPQ_CONFORMANCE_DIR");
        if (env != null) {
            string direct = Path.build_filename((!) env, "v2", "issuer-status.json");
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
                string candidate = Path.build_filename(dir, "conformance", "v2", "issuer-status.json");
                if (FileUtils.test(candidate, FileTest.EXISTS)) return candidate;
                string parent = Path.get_dirname(dir);
                if (parent == dir) break;
                dir = parent;
            }
        }
        return null;
    }

    /* The corpus's declared check order against the resolver's actual one. */
    private static void check_order(Jv? order) {
        if (order == null || ((!) order).kind != Jv.Kind.ARRAY) {
            fail_if_reached("the corpus carries no `check_order` array; the order the "
                + "contradictory-input vectors encode would then be documented nowhere");
            return;
        }
        var problems = new Gee.ArrayList<string>();
        var got = new Gee.ArrayList<string>();
        foreach (Jv step in ((!) order).arr) {
            Jv? name = step.member("name");
            if (name == null || ((!) name).kind != Jv.Kind.STRING) {
                problems.add("a `check_order` step has no string `name`");
                continue;
            }
            got.add(((!) name).str);
        }
        int declared_steps = got.size;
        int harness_steps = HARNESS_CHECK_ORDER.length;
        if (declared_steps != harness_steps) {
            problems.add(@"the corpus declares $declared_steps check steps, classify_issuer() "
                + @"answers $harness_steps facts");
        }
        for (int i = 0; i < got.size && i < HARNESS_CHECK_ORDER.length; i++) {
            if (got[i] != HARNESS_CHECK_ORDER[i]) {
                problems.add(@"check step $(i + 1): the corpus says `$(got[i])`, "
                    + @"classify_issuer() tests `$(HARNESS_CHECK_ORDER[i])` there");
            }
        }
        report("the corpus `check_order` block and classify_issuer() disagree", problems);
    }

    /* The corpus's input names and status vocabulary against what this harness reads and
     * can map. An input the harness never reads makes every vector that varies it vacuous
     * — the one failure a per-vector assertion cannot see, because the vector still
     * passes. */
    private static void check_vocabulary(Jv? inputs, Jv? outputs) {
        var problems = new Gee.ArrayList<string>();

        if (inputs == null || ((!) inputs).kind != Jv.Kind.OBJECT) {
            problems.add("the corpus carries no `inputs` object");
        } else {
            foreach (var e in ((!) inputs).obj.entries) {
                if (e.key == "note") continue;
                if (!in_list(harness_inputs(), e.key)) {
                    problems.add(@"the corpus declares an input `$(e.key)` that this harness "
                        + "never reads — every vector varying it is running vacuously");
                }
            }
            foreach (string k in harness_inputs()) {
                if (!((!) inputs).obj.has_key(k)) {
                    problems.add(@"this harness reads `$k`, which the corpus no longer declares");
                }
            }
        }

        Jv? statuses = (outputs != null) ? ((!) outputs).member("status") : null;
        if (statuses == null || ((!) statuses).kind != Jv.Kind.OBJECT) {
            problems.add("the corpus carries no `outputs.status` object");
        } else {
            foreach (var e in ((!) statuses).obj.entries) {
                if (e.key == "note") continue;
                if (!in_list(harness_statuses(), e.key)) {
                    problems.add(@"the corpus declares a status `$(e.key)` that this harness "
                        + "cannot map to an IssuerAuthStatus");
                }
            }
            foreach (string k in harness_statuses()) {
                if (!((!) statuses).obj.has_key(k)) {
                    problems.add(@"IssuerAuthStatus.$k is no longer declared by the corpus");
                }
            }
        }

        if (outputs == null || ((!) outputs).member("wants_manifest_fetch") == null) {
            problems.add("the corpus no longer declares `outputs.wants_manifest_fetch`; the "
                + "quarantine-release half of every vector would then be unpinned, and an "
                + "UNRESOLVED that never retries is REJECTED with extra steps");
        }

        report("the corpus vocabulary and this harness disagree", problems);
    }

    private void run_vector(string id, Jv vector) {
        executed++;
        var problems = new Gee.ArrayList<string>();
        try {
            Jv inputs = vector.req("inputs");
            bool owner_known    = req_bool(inputs, "owner_known");
            bool tombstoned     = req_bool(inputs, "tombstoned");
            bool history_held   = req_bool(inputs, "manifest_history_held");
            bool ever_authorized = req_bool(inputs, "ever_authorized");

            Jv expect = vector.req("expect");
            Jv status_node = expect.req("status");
            if (status_node.kind != Jv.Kind.STRING) {
                throw new IOError.FAILED("`expect.status` is not a string");
            }
            IssuerAuthStatus want_status = parse_status(status_node.str);
            Jv fetch_node = expect.req("wants_manifest_fetch");
            if (fetch_node.kind != Jv.Kind.BOOL) {
                throw new IOError.FAILED("`expect.wants_manifest_fetch` is not a boolean");
            }
            bool want_fetch = fetch_node.flag;

            string shape = @"owner_known=$owner_known tombstoned=$tombstoned "
                + @"manifest_history_held=$history_held ever_authorized=$ever_authorized";
            string? why = null;
            Jv? why_node = vector.member("why");
            if (why_node != null && ((!) why_node).kind == Jv.Kind.STRING) why = ((!) why_node).str;

            /* The production resolver, not a restatement of it. */
            IssuerAuthStatus got_status = classify_issuer(owner_known, tombstoned,
                                                          history_held, ever_authorized);
            if (got_status != want_status) {
                problems.add(@"status: corpus says $(name_of(want_status)), "
                    + @"classify_issuer() returned $(name_of(got_status)) for [$shape]");
            }

            /* The other half, and the reason the corpus pins it per vector: quarantine is
             * only honest if it RETRIES. An UNRESOLVED that schedules no fetch is
             * behaviourally identical to REJECTED once the first fold is done, so a
             * status-only assertion would let the two collapse into each other. */
            bool got_fetch = issuer_status_wants_manifest_fetch(got_status, owner_known);
            if (got_fetch != want_fetch) {
                problems.add(@"wants_manifest_fetch: corpus says $want_fetch, "
                    + @"issuer_status_wants_manifest_fetch() returned $got_fetch for [$shape]");
            }

            if (problems.size > 0 && why != null) problems.add(@"vector rationale: $((!) why)");
        } catch (GLib.Error e) {
            problems.add(e.message);
        }
        report(@"vector `$id`", problems);
    }

    private static IssuerAuthStatus parse_status(string s) throws GLib.Error {
        switch (s) {
            case "AUTHORIZED": return IssuerAuthStatus.AUTHORIZED;
            case "REJECTED":   return IssuerAuthStatus.REJECTED;
            case "UNRESOLVED": return IssuerAuthStatus.UNRESOLVED;
            default:
                /* Rule 2: an expectation this harness does not understand is a failure,
                 * never a pass and never a skip. */
                throw new IOError.FAILED(@"unknown `expect.status` value `$s` — this harness "
                    + "cannot map it to an IssuerAuthStatus, so the vector CANNOT be executed");
        }
    }

    private static string name_of(IssuerAuthStatus s) {
        switch (s) {
            case IssuerAuthStatus.AUTHORIZED: return "AUTHORIZED";
            case IssuerAuthStatus.REJECTED:   return "REJECTED";
            case IssuerAuthStatus.UNRESOLVED: return "UNRESOLVED";
            default: return "<unknown>";
        }
    }

    /* Required, not defaulted. Every vector states all four inputs explicitly; a missing
     * one silently defaulted to false would turn a real combination into a duplicate of
     * another row and quietly shrink the truth table. */
    private static bool req_bool(Jv obj, string name) throws GLib.Error {
        Jv v = obj.req(name);
        if (v.kind != Jv.Kind.BOOL) {
            throw new IOError.FAILED(@"input `$name` is not a boolean");
        }
        return v.flag;
    }

    private static bool in_list(string[] list, string needle) {
        foreach (string s in list) if (s == needle) return true;
        return false;
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
}

}
