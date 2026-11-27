import java.io.*;
import java.nio.file.*;
import java.util.*;

/** E3: text-level vs field-aware redaction of JSON audit events built from the Gretel documents.
 *  Writes one JSON line per event and strategy; validity and trace-ID integrity are checked in check_e3.py. */
public class EvalStructure {

    static String esc(String s) {
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\""); case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n"); case '\r' -> b.append("\\r"); case '\t' -> b.append("\\t");
                default -> { if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c); }
            }
        }
        return b.toString();
    }

    static String hex(Random r, int n) {
        StringBuilder b = new StringBuilder(n);
        for (int i = 0; i < n; i++) b.append("0123456789abcdef".charAt(r.nextInt(16)));
        return b.toString();
    }

    record Event(String ts, String traceId, String spanId, String service, int status, long accountNumber,
                 String customerEmail, String excerpt) {}

    /** Serialize without redaction (input to text-level strategies). */
    static String plain(Event e) {
        return "{\"timestamp\":\"" + e.ts + "\",\"traceId\":\"" + e.traceId + "\",\"spanId\":\"" + e.spanId
            + "\",\"service\":\"" + e.service + "\",\"status\":" + e.status + ",\"accountNumber\":" + e.accountNumber
            + ",\"customerEmail\":\"" + esc(e.customerEmail) + "\",\"excerpt\":\"" + esc(e.excerpt) + "\"}";
    }

    /** Field-aware: identifiers exempt, annotated fields masked by rule, free text by pattern, then serialize. */
    static String fieldAware(Event e, Redactor r) {
        return "{\"timestamp\":\"" + e.ts + "\",\"traceId\":\"" + e.traceId + "\",\"spanId\":\"" + e.spanId
            + "\",\"service\":\"" + e.service + "\",\"status\":" + e.status + ",\"accountNumber\":\"" + Redactor.TOKEN
            + "\",\"customerEmail\":\"" + Redactor.TOKEN + "\",\"excerpt\":\"" + esc(r.redact(e.excerpt)) + "\"}";
    }

    public static void main(String[] a) throws Exception {
        List<EvalDetection.Doc> docs = EvalDetection.loadGretel("gretel_en.tsv");
        Random rnd = new Random(42);
        Redactor naive = new Redactor(Redactor.Config.NAIVE), val = new Redactor(Redactor.Config.VALIDATED);
        try (PrintWriter meta = new PrintWriter("e3_meta.tsv");
             PrintWriter tn = new PrintWriter("e3_text_naive.jsonl");
             PrintWriter tv = new PrintWriter("e3_text_validated.jsonl");
             PrintWriter fa = new PrintWriter("e3_field_aware.jsonl")) {
            for (EvalDetection.Doc d : docs) {
                String excerpt = d.text().substring(0, Math.min(600, d.text().length()));
                String email = "customer" + rnd.nextInt(100000) + "@example.com";
                long acct = 1_000_000_000L + (long) (rnd.nextDouble() * 8_999_999_999L);   // 10-digit account number
                Event e = new Event("2026-05-14T15:02:11.482Z", hex(rnd, 32), hex(rnd, 16), "payments-api", 400, acct, email, excerpt);
                String p = plain(e);
                tn.println(naive.redact(p));
                tv.println(val.redact(p));
                fa.println(fieldAware(e, val));
                // gold in-scope values that lie fully inside the excerpt (for leak checks)
                StringBuilder g = new StringBuilder();
                for (EvalDetection.Gold go : d.gold())
                    if (EvalDetection.IN_SCOPE.containsKey(go.label()) && go.e() <= excerpt.length())
                        g.append(go.label()).append('\u0001').append(excerpt, go.s(), go.e()).append('\u0002');
                meta.println(e.traceId + "\t" + e.spanId + "\t" + acct + "\t" + email + "\t"
                    + Base64.getEncoder().encodeToString(g.toString().getBytes("UTF-8")));
            }
        }
        System.out.println("done E3");
    }
}
