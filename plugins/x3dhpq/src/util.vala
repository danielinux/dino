namespace Dino.Plugins.X3dhpq {

internal string bytes_to_base64(Bytes bytes) {
    return Base64.encode(bytes_to_uint8_array(bytes));
}

internal Bytes bytes_from_base64(string data) {
    return new Bytes(Base64.decode(data));
}

internal uint8[] bytes_to_uint8_array(Bytes bytes) {
    size_t len = bytes.get_size();
    unowned uint8[] source = bytes.get_data();
    uint8[] copy = new uint8[(int) len];
    Memory.copy(copy, source, len);
    return copy;
}

internal uint8[] concat_six_byte_arrays(uint8[] a, uint8[] b, uint8[] c, uint8[] d, uint8[] e, uint8[] f) {
    uint8[] result = new uint8[a.length + b.length + c.length + d.length + e.length + f.length];
    int offset = 0;
    foreach (uint8 value in a) result[offset++] = value;
    foreach (uint8 value in b) result[offset++] = value;
    foreach (uint8 value in c) result[offset++] = value;
    foreach (uint8 value in d) result[offset++] = value;
    foreach (uint8 value in e) result[offset++] = value;
    foreach (uint8 value in f) result[offset++] = value;
    return result;
}

internal uint8[] uint32_to_bytes(uint32 value) {
    return {
        (uint8) ((value >> 24) & 0xff),
        (uint8) ((value >> 16) & 0xff),
        (uint8) ((value >> 8) & 0xff),
        (uint8) (value & 0xff),
    };
}

internal uint8[] uint16_to_bytes(uint16 value) {
    return {
        (uint8) ((value >> 8) & 0xff),
        (uint8) (value & 0xff),
    };
}

internal uint8[] uint64_to_bytes(uint64 value) {
    return {
        (uint8) ((value >> 56) & 0xff),
        (uint8) ((value >> 48) & 0xff),
        (uint8) ((value >> 40) & 0xff),
        (uint8) ((value >> 32) & 0xff),
        (uint8) ((value >> 24) & 0xff),
        (uint8) ((value >> 16) & 0xff),
        (uint8) ((value >> 8) & 0xff),
        (uint8) (value & 0xff),
    };
}

internal uint32 uint32_from_bytes(uint8[] data, int offset = 0) {
    return ((uint32) data[offset] << 24) |
        ((uint32) data[offset + 1] << 16) |
        ((uint32) data[offset + 2] << 8) |
        (uint32) data[offset + 3];
}

internal uint16 uint16_from_bytes(uint8[] data, int offset = 0) {
    return (uint16) (((uint16) data[offset] << 8) | data[offset + 1]);
}

internal uint64 uint64_from_bytes(uint8[] data, int offset = 0) {
    return ((uint64) data[offset] << 56) |
        ((uint64) data[offset + 1] << 48) |
        ((uint64) data[offset + 2] << 40) |
        ((uint64) data[offset + 3] << 32) |
        ((uint64) data[offset + 4] << 24) |
        ((uint64) data[offset + 5] << 16) |
        ((uint64) data[offset + 6] << 8) |
        (uint64) data[offset + 7];
}

internal int64 int64_from_bytes(uint8[] data, int offset = 0) {
    return (int64) uint64_from_bytes(data, offset);
}

internal uint8[] concat_byte_arrays(uint8[] a, uint8[] b) {
    uint8[] result = new uint8[a.length + b.length];
    int offset = 0;
    foreach (uint8 value in a) result[offset++] = value;
    foreach (uint8 value in b) result[offset++] = value;
    return result;
}

internal uint8[] concat_three_byte_arrays(uint8[] a, uint8[] b, uint8[] c) {
    return concat_byte_arrays(concat_byte_arrays(a, b), c);
}

internal uint8[] concat_four_byte_arrays(uint8[] a, uint8[] b, uint8[] c, uint8[] d) {
    return concat_byte_arrays(concat_three_byte_arrays(a, b, c), d);
}

internal Bytes bytes_from_uint8_array(uint8[] data) {
    return new Bytes(data);
}

internal string nullable_string(string? value) {
    return value ?? "";
}

internal uint8[] nullable_base64_bytes(string? value) {
    if (value == null || value == "") {
        return {};
    }
    return bytes_to_uint8_array(bytes_from_base64(value));
}

internal uint8[] string_to_bytes(string value) {
    return ((uint8[]) value.data).copy();
}

internal string account_fingerprint(Bytes ed25519_public_key, Bytes mldsa_public_key) throws GLib.Error {
    uint8[] ed25519 = bytes_to_uint8_array(ed25519_public_key);
    uint8[] mldsa = bytes_to_uint8_array(mldsa_public_key);
    uint8[] encoded = new uint8[3 + ed25519.length + mldsa.length];
    int offset = 3;
    encoded[0] = 0;
    encoded[1] = 1;
    encoded[2] = 1;
    foreach (uint8 b in ed25519) {
        encoded[offset++] = b;
    }
    foreach (uint8 b in mldsa) {
        encoded[offset++] = b;
    }

    Bytes digest = global::X3dhpq.Crypto.blake2b160(new Bytes(encoded));
    unowned uint8[] digest_data = digest.get_data();
    StringBuilder hex = new StringBuilder();
    foreach (uint8 b in digest_data) {
        hex.append_printf("%02X", b);
    }

    string compact = hex.str.substring(0, 30);
    return @"$(compact.substring(0, 5)) $(compact.substring(5, 5)) $(compact.substring(10, 5)) $(compact.substring(15, 5)) $(compact.substring(20, 5)) $(compact.substring(25, 5))";
}

internal int build_random_device_id() throws GLib.Error {
    Bytes random = global::X3dhpq.Crypto.random_bytes(4);
    unowned uint8[] data = random.get_data();
    int device_id = ((int) data[0] << 24) | ((int) data[1] << 16) | ((int) data[2] << 8) | data[3];
    if (device_id == int.MIN) {
        return 1;
    }
    return device_id < 0 ? -device_id : device_id;
}

}
