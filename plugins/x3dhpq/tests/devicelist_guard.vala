namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

class DeviceListGuardTest : Gee.TestCase {

    public DeviceListGuardTest() {
        base("DeviceListGuard");
        add_test("shrink_without_removal", test_shrink_without_removal);
        add_test("shrink_with_matching_removal", test_shrink_with_matching_removal);
        add_test("identical", test_identical);
        add_test("growth", test_growth);
        add_test("empty_prev", test_empty_prev);
        add_test("null_allow", test_null_allow);
    }

    private static Gee.Set<uint32> set_of(uint32[] ids) {
        var s = new Gee.HashSet<uint32>();
        foreach (uint32 id in ids) {
            s.add(id);
        }
        return s;
    }

    private void test_shrink_without_removal() {
        // prev={1,2}, new={1}, allow=empty → drops 2.
        var missing = devicelist_shrink_drops(set_of({1, 2}), set_of({1}), set_of({}));
        fail_if_not_eq_int(missing.size, 1, "shrink without removal must report exactly one drop");
        fail_if_not(missing.contains(2), "dropped set must contain 2");
    }

    private void test_shrink_with_matching_removal() {
        // prev={1,2}, new={1}, allow={2} → nothing dropped.
        var missing = devicelist_shrink_drops(set_of({1, 2}), set_of({1}), set_of({2}));
        fail_if_not_eq_int(missing.size, 0, "shrink with matching removal must report no drops");
    }

    private void test_identical() {
        // prev={1,2}, new={1,2}, allow=empty → nothing dropped.
        var missing = devicelist_shrink_drops(set_of({1, 2}), set_of({1, 2}), set_of({}));
        fail_if_not_eq_int(missing.size, 0, "identical list must report no drops");
    }

    private void test_growth() {
        // prev={1}, new={1,2}, allow=empty → nothing dropped.
        var missing = devicelist_shrink_drops(set_of({1}), set_of({1, 2}), set_of({}));
        fail_if_not_eq_int(missing.size, 0, "growth must report no drops");
    }

    private void test_empty_prev() {
        // prev={}, new={1}, allow=empty → nothing dropped (first publish).
        var missing = devicelist_shrink_drops(set_of({}), set_of({1}), set_of({}));
        fail_if_not_eq_int(missing.size, 0, "empty prev must report no drops");
    }

    private void test_null_allow() {
        // prev={1,2}, new={1}, allow=null → drops 2 (null treated as empty).
        var missing = devicelist_shrink_drops(set_of({1, 2}), set_of({1}), null);
        fail_if_not_eq_int(missing.size, 1, "null allow must report exactly one drop");
        fail_if_not(missing.contains(2), "dropped set must contain 2");
    }
}

}
