namespace Dino.Plugins.X3dhpq.Protocol {

// Pure set-decision for the publish-time devicelist "shrink guard" (§8.6): a
// publish that DROPS a previously-known account device must never happen by
// accident. Given the ids from the last authoritative own devicelist
// (prev_ids), the ids of the union about to be published (new_ids) and the
// explicitly allowed removal set (allow_removals, null treated as empty),
// return the ids present in prev_ids but absent from BOTH new_ids and
// allow_removals — i.e. the devices that would be silently dropped. An empty
// result means the publish is safe (first publish, identical republish and
// growth all return empty).
public Gee.List<uint32> devicelist_shrink_drops(Gee.Set<uint32> prev_ids, Gee.Set<uint32> new_ids, Gee.Set<uint32>? allow_removals) {
    var missing = new Gee.ArrayList<uint32>();
    foreach (uint32 pid in prev_ids) {
        if (!new_ids.contains(pid) && (allow_removals == null || !allow_removals.contains(pid))) {
            missing.add(pid);
        }
    }
    return missing;
}

}
