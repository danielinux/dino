namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

class PairingCodeTest : Gee.TestCase {

    public PairingCodeTest() {
        base("PairingCode");
        add_test("generate_length_and_digits", test_generate_length_and_digits);
        add_test("generate_luhn_valid", test_generate_luhn_valid);
        add_test("format_known", test_format_known);
        add_test("parse_format_roundtrip", test_parse_format_roundtrip);
        add_test("parse_wrong_check_digit", test_parse_wrong_check_digit);
        add_test("parse_non_digit_throws_malformed", test_parse_non_digit_throws_malformed);
        add_test("parse_strips_dashes_and_spaces", test_parse_strips_dashes_and_spaces);
        add_test("luhn_wikipedia_vector", test_luhn_wikipedia_vector);
    }

    private void test_generate_length_and_digits() {
        try {
            string code = PairingCode.generate();
            fail_if_not_eq_int(code.length, 10, "generate() must return 10 chars");
            for (int i = 0; i < 10; i++) {
                fail_if(code[i] < '0' || code[i] > '9', "generate() char %d not a digit".printf(i));
            }
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_generate_luhn_valid() {
        try {
            string code = PairingCode.generate();
            char expected = PairingCode.luhn_check(code[0:9]);
            fail_if_not_eq_int((int) code[9], (int) expected, "generate() last char must be Luhn check digit");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_format_known() {
        string result = PairingCode.format("1234567890");
        fail_if_not_eq_str(result, "123-456-789-0", "format() produced wrong output");
    }

    private void test_parse_format_roundtrip() {
        try {
            string code = PairingCode.generate();
            string formatted = PairingCode.format(code);
            string parsed = PairingCode.parse(formatted);
            fail_if_not_eq_str(parsed, code, "parse(format(generate())) must equal generate() output");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_parse_wrong_check_digit() {
        try {
            string code = PairingCode.generate();
            // Flip the last digit by incrementing it mod 10.
            char last = code[9];
            char bad = (char) ('0' + ((last - '0' + 1) % 10));
            string bad_code = code[0:9] + bad.to_string();
            PairingCode.parse(bad_code);
            fail_if_reached("parse() with wrong check digit should throw BAD_CHECK");
        } catch (PairingCodeError e) {
            fail_if_not_eq_int((int) e.code, (int) PairingCodeError.BAD_CHECK, "expected BAD_CHECK, got %s".printf(e.message));
        } catch (Error e) {
            fail_if_reached("unexpected error: %s".printf(e.message));
        }
    }

    private void test_parse_non_digit_throws_malformed() {
        try {
            PairingCode.parse("123456789A");
            fail_if_reached("parse() with non-digit should throw MALFORMED");
        } catch (PairingCodeError e) {
            fail_if_not_eq_int((int) e.code, (int) PairingCodeError.MALFORMED, "expected MALFORMED, got %s".printf(e.message));
        } catch (Error e) {
            fail_if_reached("unexpected error: %s".printf(e.message));
        }
    }

    private void test_parse_strips_dashes_and_spaces() {
        // "000000000" → all doubled = 0, sum = 0, check = (10-0)%10 = 0.
        // Full 10-digit code: "0000000000".
        try {
            string result = PairingCode.parse("000-000-000-0");
            fail_if_not_eq_str(result, "0000000000", "parse() should strip dashes");
            string result2 = PairingCode.parse("000 000 000 0");
            fail_if_not_eq_str(result2, "0000000000", "parse() should strip spaces");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_luhn_wikipedia_vector() {
        // The Go implementation doubles even-indexed (0-based from left) positions.
        // For "799273987": doubled positions 0,2,4,6,8 give sum=55, check=(10-5)%10=5.
        try {
            char check = PairingCode.luhn_check("799273987");
            fail_if_not_eq_int((int) check, (int) '5', "Luhn check of 799273987 should be '5'");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }
}

}
