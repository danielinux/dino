using Dino.Entities;
using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;
using Xmpp;

namespace X3dhpq.Test {

class MembershipDagPersistenceTest : Gee.TestCase {
    private string db_path;

    public MembershipDagPersistenceTest() {
        base("MembershipDagPersistence");
        add_test("v2_entry_raw_persistence", test_v2_entry_raw_persistence);
        add_test("v2_restart_hydration_source", test_v2_restart_hydration_source);
    }

    public override void set_up() {
        db_path = GLib.Path.build_filename(GLib.Environment.get_tmp_dir(),
            "x3dhpq-dag-persist-%u.db".printf(Random.next_int()));
    }

    public override void tear_down() {
        FileUtils.unlink(db_path);
        FileUtils.unlink(db_path + "-shm");
        FileUtils.unlink(db_path + "-wal");
    }

    private Account account() throws GLib.Error {
        Account a = new Account(new Jid("alice@example.test"), "pw");
        a.id = 77;
        return a;
    }

    private uint8[] fp(uint8 seed) {
        uint8[] out_fp = new uint8[20];
        for (int i = 0; i < out_fp.length; i++) out_fp[i] = (uint8) (seed + i);
        return out_fp;
    }

    private uint8[] dummy_v2_blob(uint64 lamport, uint8 signer_seed, uint8 subject_seed) {
        JournalEntryV2 e = new JournalEntryV2();
        e.lamport = lamport;
        e.signer_fp = fp(signer_seed);
        e.parents = new Gee.ArrayList<Bytes>();
        e.action = (uint8) MemberAuditActionV2.ADD_MEMBER;
        e.payload = JournalEntryV2.build_member_payload(fp(subject_seed), 0);
        e.timestamp = 1234 + (int64) lamport;
        e.signature = { 0x01, 0x02, 0x03 };
        e.mldsa_signature = { 0x04, 0x05, 0x06 };
        return e.marshal();
    }

    private uint8[] bytes_to_arr(Bytes b) {
        unowned uint8[] d = b.get_data();
        uint8[] arr = new uint8[d.length];
        Memory.copy(arr, d, d.length);
        return arr;
    }

    private void test_v2_entry_raw_persistence() {
        try {
            Database db = new Database(db_path);
            Account a = account();
            string room = "room@conference.example.test";
            uint8[] blob = dummy_v2_blob(1, 10, 40);
            uint8[] raw_with_tail = new uint8[blob.length + 3];
            Memory.copy(raw_with_tail, blob, blob.length);
            raw_with_tail[blob.length] = 0xaa;
            raw_with_tail[blob.length + 1] = 0xbb;
            raw_with_tail[blob.length + 2] = 0xcc;

            db.store_membership_dag_entry_blob(a, room, raw_with_tail);
            db.store_membership_dag_entry_blob(a, room, raw_with_tail);

            fail_if_not(db.has_membership_dag_entries(a, room), "v2 rows should exist");
            Gee.List<Bytes> rows = db.list_membership_dag_entry_blobs(a, room);
            fail_if_not_eq_int(rows.size, 1, "duplicate hash should upsert");
            fail_if_not_eq_uint8_arr(bytes_to_arr(rows.get(0)), raw_with_tail, "raw blob must roundtrip exactly");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_v2_restart_hydration_source() {
        try {
            Account a = account();
            string room = "room@conference.example.test";
            uint8[] blob = dummy_v2_blob(2, 11, 41);
            {
                Database db = new Database(db_path);
                db.store_membership_dag_entry_blob(a, room, blob);
            }
            Database restarted = new Database(db_path);
            MembershipDag dag = new MembershipDag();
            foreach (Bytes b in restarted.list_membership_dag_entry_blobs(a, room)) {
                dag.ingest(bytes_to_arr(b));
            }
            fail_if_not_eq_int(dag.size, 1, "persisted v2 blob should hydrate a fresh DAG");
            fail_if_not(dag.has_entry(blob), "hydrated DAG should contain stored v2 entry");
        } catch (Error e) { fail_if_reached(e.message); }
    }
}

}
