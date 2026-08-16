namespace X3dhpq.Test {

int main(string[] args) {
    GLib.Test.init(ref args);
    GLib.Test.set_nonfatal_assertions();
    TestSuite.get_root().add_suite(new Pairwise().get_suite());
    TestSuite.get_root().add_suite(new GroupSessionTest().get_suite());
    TestSuite.get_root().add_suite(new MembershipJournalTest().get_suite());
    TestSuite.get_root().add_suite(new MembershipDagTest().get_suite());
    TestSuite.get_root().add_suite(new MembershipDagPersistenceTest().get_suite());
    TestSuite.get_root().add_suite(new RetireMemberTest().get_suite());
    TestSuite.get_root().add_suite(new RotationTransportTest().get_suite());
    TestSuite.get_root().add_suite(new RetirementStrengthTest().get_suite());
    TestSuite.get_root().add_suite(new DeferralQueueTest().get_suite());
    TestSuite.get_root().add_suite(new DeviceDagTest().get_suite());
    TestSuite.get_root().add_suite(new TrustManifestTest().get_suite());
    TestSuite.get_root().add_suite(new DeviceTrackerTest().get_suite());
    TestSuite.get_root().add_suite(new PairingMsgTest().get_suite());
    TestSuite.get_root().add_suite(new PairingCodeTest().get_suite());
    TestSuite.get_root().add_suite(new DeviceListGuardTest().get_suite());
    TestSuite.get_root().add_suite(new CPaceTest().get_suite());
    TestSuite.get_root().add_suite(new PairingTest().get_suite());
    // §19.2.0: the shared corpus is normative and runs like any other suite.
    TestSuite.get_root().add_suite(new ConformanceTest().get_suite());
    return GLib.Test.run();
}

bool fail_if(bool exp, string? reason = null) {
    if (exp) {
        if (reason != null) {
            GLib.Test.message(reason);
        }
        GLib.Test.fail();
        return true;
    }
    return false;
}

bool fail_if_not(bool exp, string? reason = null) {
    return fail_if(!exp, reason);
}

void fail_if_reached(string? reason = null) {
    fail_if(true, reason);
}

bool fail_if_not_eq_str(string left, string right, string? reason = null) {
    return fail_if_not(left == right, reason);
}

bool fail_if_not_eq_int(int left, int right, string? reason = null) {
    return fail_if_not(left == right, reason);
}

bool fail_if_not_eq_uint8_arr(uint8[] left, uint8[] right, string? reason = null) {
    if (fail_if_not_eq_int(left.length, right.length, reason)) {
        return true;
    }
    return fail_if_not_eq_str(Base64.encode(left), Base64.encode(right), reason);
}

}
