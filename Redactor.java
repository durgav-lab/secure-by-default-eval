import java.util.*;
import java.util.function.Predicate;
import java.util.regex.*;

/**
 * Prototype of the template's pattern-based redaction stage (Algorithm 2, revised).
 * Two configurations are evaluated:
 *   NAIVE     - format-only regular expressions, no validators, account numbers not context-gated.
 *   VALIDATED - the same expressions plus checksum/structure validators and a keyword gate for
 *               bare account numbers (the configuration proposed in the paper).
 * All quantifiers are bounded and there is no nested repetition, to avoid catastrophic backtracking.
 */
public final class Redactor {

    public enum Type { EMAIL, IBAN, CARD, SSN, ROUTING, ACCOUNT, SWIFT_BIC, PHONE, IPV4, IPV6 }

    public record Span(int start, int end, Type type) {}

    record Rule(Type type, Pattern pattern, Predicate<String> validator, Pattern contextGate) {}

    public static final int MAX_INPUT = 65_536;               // longer inputs are truncated before matching
    public static final String TOKEN = "[REDACTED]";

    private static final Set<String> ISO = new HashSet<>(Arrays.asList(Locale.getISOCountries()));

    // ---- patterns (from format specifications, not tuned on the evaluation data) ----
    static final Pattern EMAIL = Pattern.compile(
        "(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\\.[A-Za-z0-9-]{1,63}){0,8}\\.[A-Za-z]{2,24}(?![A-Za-z0-9-])");
    static final Pattern IBAN = Pattern.compile(
        "(?<![A-Za-z0-9])[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Za-z0-9])");
    static final Pattern CARD = Pattern.compile(
        "(?<![0-9])[0-9]{4}(?:[ -]?[0-9]{4}){2}[ -]?[0-9]{1,7}(?![0-9])");
    static final Pattern SSN = Pattern.compile(
        "(?<![0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9])");
    static final Pattern ROUTING = Pattern.compile(
        "(?<![0-9A-Za-z])[0-9]{9}(?![0-9A-Za-z])");
    static final Pattern ACCOUNT = Pattern.compile(
        "(?<![0-9A-Za-z_-])[0-9]{8,17}(?![0-9A-Za-z_-])");
    static final Pattern SWIFT = Pattern.compile(
        "(?<![A-Za-z0-9])[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?(?![A-Za-z0-9])");
    static final Pattern PHONE = Pattern.compile(
        "(?<![0-9A-Za-z])(?:\\+?1[ .-]?)?(?:\\([0-9]{3}\\)|[0-9]{3})[ .-]?[0-9]{3}[ .-]?[0-9]{4}(?:\\s?(?:x|ext\\.?)\\s?[0-9]{1,5})?(?![0-9A-Za-z])"
        + "|(?<![0-9A-Za-z])\\+[1-9][0-9]{0,2}[ .-]?(?:\\(?[0-9]{1,4}\\)?[ .-]?){1,4}[0-9]{2,4}(?![0-9A-Za-z])");
    static final Pattern PHONE_STRICT = Pattern.compile(
        "(?<![0-9A-Za-z])(?:\\+?1[ .-])?(?:\\([0-9]{3}\\) ?|[0-9]{3}[.-])[0-9]{3}[.-][0-9]{4}(?:\\s?(?:x|ext\\.?)\\s?[0-9]{1,5})?(?![0-9A-Za-z])"
        + "|(?<![0-9A-Za-z])\\+[1-9][0-9]{0,2}(?:[ .-][0-9]{1,4}){2,5}(?![0-9A-Za-z])");
    static final Pattern SWIFT_CONTEXT = Pattern.compile("(?i)(?:swift|bic)[^\\n]{0,30}$");
    static final Pattern IPV4 = Pattern.compile(
        "(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?![0-9]|\\.[0-9])");
    static final Pattern IPV6 = Pattern.compile(
        "(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])"
        + "|(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])");
    static final Pattern ACCOUNT_CONTEXT = Pattern.compile(
        "(?i)(?:account|acct|a/c|bban|deposit|iban|beneficiary)[^\\n]{0,30}$");

    // ---- validators ----
    static String digits(String s) { return s.replaceAll("[^0-9]", ""); }

    /** Issuer identification number prefixes of the major card networks (ISO/IEC 7812 ranges). */
    static boolean iin(String d) {
        int p2 = Integer.parseInt(d.substring(0, 2)), p4 = Integer.parseInt(d.substring(0, 4));
        int p3 = Integer.parseInt(d.substring(0, 3)), n = d.length();
        if (d.charAt(0) == '4') return n == 13 || n == 16 || n == 19;                    // Visa
        if ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) return n == 16;       // Mastercard
        if (p2 == 34 || p2 == 37) return n == 15;                                       // Amex
        if (p4 == 6011 || p2 == 65 || (p3 >= 644 && p3 <= 649)) return n >= 16;          // Discover
        if (p4 >= 3528 && p4 <= 3589) return n >= 16;                                   // JCB
        if (p2 == 36 || p2 == 38 || (p3 >= 300 && p3 <= 305)) return n >= 14;            // Diners
        if (p2 == 50 || (p2 >= 56 && p2 <= 69)) return n >= 12;                         // Maestro and others
        return false;
    }

    static boolean card(String s) { String d = digits(s); return luhn(d) && iin(d); }

    static boolean luhn(String s) {
        String d = digits(s);
        if (d.length() < 12 || d.length() > 19) return false;
        int sum = 0; boolean dbl = false;
        for (int i = d.length() - 1; i >= 0; i--) {
            int n = d.charAt(i) - '0';
            if (dbl) { n *= 2; if (n > 9) n -= 9; }
            sum += n; dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    static boolean aba(String s) {
        String d = digits(s);
        if (d.length() != 9) return false;
        int pre = Integer.parseInt(d.substring(0, 2));   // Federal Reserve routing symbol ranges
        if (!((pre <= 12) || (pre >= 21 && pre <= 32) || (pre >= 61 && pre <= 72) || pre == 80)) return false;
        int[] w = {3, 7, 1};
        int sum = 0;
        for (int i = 0; i < 9; i++) sum += (d.charAt(i) - '0') * w[i % 3];
        return sum % 10 == 0;
    }

    static boolean ssn(String s) {
        String[] p = s.split("-");
        int area = Integer.parseInt(p[0]);
        return area != 0 && area != 666 && area < 900 && !p[1].equals("00") && !p[2].equals("0000");
    }

    static boolean iban(String s) {
        String c = s.replace(" ", "");
        if (c.length() < 15 || c.length() > 34 || !ISO.contains(c.substring(0, 2))) return false;
        String r = c.substring(4) + c.substring(0, 4);
        int mod = 0;
        for (char ch : r.toCharArray()) {
            String v = Character.isDigit(ch) ? String.valueOf(ch) : String.valueOf(ch - 'A' + 10);
            for (char x : v.toCharArray()) mod = (mod * 10 + (x - '0')) % 97;
        }
        return mod == 1;
    }

    static boolean bic(String s) { return ISO.contains(s.substring(4, 6)); }

    static boolean phone(String s) { int n = digits(s).length(); return n >= 10 && n <= 15; }

    // ---- configurations ----
    public enum Config { NAIVE, VALIDATED }

    private final List<Rule> rules = new ArrayList<>();
    private final Config config;

    public Redactor(Config config) {
        this.config = config;
        boolean v = config == Config.VALIDATED;
        Predicate<String> any = x -> true;
        rules.add(new Rule(Type.EMAIL, EMAIL, any, null));
        rules.add(new Rule(Type.IBAN, IBAN, v ? Redactor::iban : any, null));
        rules.add(new Rule(Type.CARD, CARD, v ? Redactor::card : any, null));
        rules.add(new Rule(Type.SSN, SSN, v ? Redactor::ssn : any, null));
        rules.add(new Rule(Type.ROUTING, ROUTING, v ? Redactor::aba : any, null));
        rules.add(new Rule(Type.ACCOUNT, ACCOUNT, any, v ? ACCOUNT_CONTEXT : null));
        rules.add(new Rule(Type.SWIFT_BIC, SWIFT, v ? Redactor::bic : any, v ? SWIFT_CONTEXT : null));
        rules.add(new Rule(Type.PHONE, v ? PHONE_STRICT : PHONE, v ? Redactor::phone : any, null));
        rules.add(new Rule(Type.IPV4, IPV4, any, null));
        rules.add(new Rule(Type.IPV6, IPV6, any, null));
    }

    public Config config() { return config; }

    /** Detect spans; earlier rules win on overlap (fixed, documented order). */
    public List<Span> detect(CharSequence in) {
        String text = in.length() > MAX_INPUT ? in.subSequence(0, MAX_INPUT).toString() : in.toString();
        boolean[] taken = new boolean[text.length()];
        List<Span> out = new ArrayList<>();
        for (Rule r : rules) {
            Matcher m = r.pattern.matcher(text);
            while (m.find()) {
                int s = m.start(), e = m.end();
                String g = m.group();
                if (!r.validator.test(g)) continue;
                if (r.contextGate != null) {
                    String before = text.substring(Math.max(0, s - 40), s);
                    if (!r.contextGate.matcher(before).find()) continue;
                }
                boolean clash = false;
                for (int i = s; i < e && !clash; i++) clash = taken[i];
                if (clash) continue;
                for (int i = s; i < e; i++) taken[i] = true;
                out.add(new Span(s, e, r.type));
            }
        }
        out.sort(Comparator.comparingInt(Span::start));
        return out;
    }

    public String redact(CharSequence in) {
        String text = in.length() > MAX_INPUT ? in.subSequence(0, MAX_INPUT).toString() : in.toString();
        List<Span> spans = detect(text);
        if (spans.isEmpty()) return text;
        StringBuilder sb = new StringBuilder(text.length());
        int last = 0;
        for (Span sp : spans) { sb.append(text, last, sp.start()).append(TOKEN); last = sp.end(); }
        return sb.append(text, last, text.length()).toString();
    }
}
