// DeviceList hybrid-signing helper (XEP §8.2–§8.5).
//
// Canonical SignedPart (layout A — the bytes that get signed by the account AIK):
//   "X3DHPQ-DeviceList-v1\x00"            21 bytes (20 ASCII + one 0x00)
//   uint64_BE(version)
//   int64_BE(issued_at)                   unix seconds
//   for each device, SORTED BY device_id ASCENDING:
//       uint32_BE(device_id)
//       int64_BE(added_at)                unix seconds
//       uint8(flags)
//       uint32_BE(cert_len)
//       cert_bytes                         raw DeviceCertificate.marshal()
//
// NOTE: there is no version_marker and no num_devices inside the SignedPart —
// exactly the fields above (locked cross-client contract for interop with
// PQonversations). ed_sig = ed25519_sign(AIK ed priv, signed_part);
// mldsa_sig = mldsa65_sign(AIK mldsa priv, signed_part) — both over the same
// bytes, both MUST verify (§7.7).

using Gee;

namespace Dino.Plugins.X3dhpq.Protocol {

public class DeviceListDevice : Object {
    public uint32 device_id { get; set; }
    public int64 added_at { get; set; }
    public uint8 flags { get; set; }
    public uint8[] cert_bytes { get; set; }   // DeviceCertificate.marshal()
}

public class DeviceListSigned : Object {
    // "X3DHPQ-DeviceList-v1\x00" — 20 ASCII chars + one trailing 0x00 = 21 bytes.
    // Domain separator "X3DHPQ-DeviceList-v1\0" (21 bytes). Returned as a fresh
    // LOCAL each call: a `static uint8[]` FIELD initializer reports .length == 0
    // at runtime in this valac (the data initializes but the length metadata does
    // not), which silently dropped this prefix from the signed input and broke
    // cross-client signature verification (Dino↔PQonversations). Built byte-by-byte
    // because a Vala string literal would drop the trailing NUL.
    private static uint8[] prefix() {
        return { 'X','3','D','H','P','Q','-','D','e','v','i','c','e','L','i','s','t','-','v','1', 0x00 };
    }

    private static void put_u64(uint8[] buf, ref int off, uint64 v) {
        for (int i = 7; i >= 0; i--) {
            buf[off++] = (uint8)(v >> (i * 8));
        }
    }

    private static void put_u32(uint8[] buf, ref int off, uint32 v) {
        buf[off++] = (uint8)(v >> 24);
        buf[off++] = (uint8)(v >> 16);
        buf[off++] = (uint8)(v >> 8);
        buf[off++] = (uint8) v;
    }

    // Build the canonical SignedPart (layout A). The device list is sorted by
    // device_id ascending here so callers need not pre-sort.
    public static uint8[] signed_part(uint64 version, int64 issued_at, Gee.List<DeviceListDevice> devices) {
        uint8[] PREFIX = prefix();
        var sorted = new Gee.ArrayList<DeviceListDevice>();
        sorted.add_all(devices);
        sorted.sort((a, b) => {
            if (a.device_id < b.device_id) return -1;
            if (a.device_id > b.device_id) return 1;
            return 0;
        });

        int size = PREFIX.length + 8 + 8;
        foreach (DeviceListDevice d in sorted) {
            size += 4 + 8 + 1 + 4 + d.cert_bytes.length;
        }

        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy(buf, PREFIX, PREFIX.length);
        off += PREFIX.length;
        put_u64(buf, ref off, version);
        put_u64(buf, ref off, (uint64) issued_at);
        foreach (DeviceListDevice d in sorted) {
            put_u32(buf, ref off, d.device_id);
            put_u64(buf, ref off, (uint64) d.added_at);
            buf[off++] = d.flags;
            put_u32(buf, ref off, (uint32) d.cert_bytes.length);
            if (d.cert_bytes.length > 0) {
                Memory.copy((uint8*) buf + off, d.cert_bytes, d.cert_bytes.length);
                off += d.cert_bytes.length;
            }
        }
        return buf;
    }
}

}
