namespace Dino.Plugins.X3dhpq.Protocol {

public errordomain PairingCodeError {
    MALFORMED,
    BAD_CHECK
}

public class PairingCode : GLib.Object {

    public static string generate() throws GLib.Error {
        Bytes rand = global::X3dhpq.Crypto.random_bytes(9);
        unowned uint8[] buf = rand.get_data();
        uint8[] digits = new uint8[9];
        for (int i = 0; i < 9; i++) {
            digits[i] = '0' + buf[i] % 10;
        }
        char check = luhn_check((string) digits);
        return ((string) digits) + check.to_string();
    }

    public static string format(string code) {
        if (code.length != 10) {
            return code;
        }
        return code[0:3] + "-" + code[3:6] + "-" + code[6:9] + "-" + code[9:10];
    }

    public static string parse(string input) throws PairingCodeError {
        var sb = new StringBuilder();
        for (int i = 0; i < input.length; i++) {
            unichar c = input[i];
            if (c == '-' || c == ' ') {
                continue;
            }
            sb.append_unichar(c);
        }
        string stripped = sb.str;
        if (stripped.length != 10) {
            throw new PairingCodeError.MALFORMED("pairing: malformed code");
        }
        for (int i = 0; i < 10; i++) {
            if (stripped[i] < '0' || stripped[i] > '9') {
                throw new PairingCodeError.MALFORMED("pairing: malformed code");
            }
        }
        char expected;
        try {
            expected = luhn_check(stripped[0:9]);
        } catch (PairingCodeError e) {
            throw e;
        }
        if (stripped[9] != expected) {
            throw new PairingCodeError.BAD_CHECK("pairing: check digit mismatch");
        }
        return stripped;
    }

    public static char luhn_check(string nine_digits) throws PairingCodeError {
        if (nine_digits.length != 9) {
            throw new PairingCodeError.MALFORMED("pairing: malformed code");
        }
        for (int i = 0; i < 9; i++) {
            if (nine_digits[i] < '0' || nine_digits[i] > '9') {
                throw new PairingCodeError.MALFORMED("pairing: malformed code");
            }
        }
        int sum = 0;
        for (int i = 0; i < 9; i++) {
            int d = nine_digits[i] - '0';
            if (i % 2 == 0) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            sum += d;
        }
        int check = (10 - sum % 10) % 10;
        return (char) ('0' + check);
    }
}

}
