import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/** E4: catastrophic backtracking (ReDoS) check. E5: redaction latency per document / log line. */
public class EvalPerf {

    /** CharSequence that aborts matching after a deadline (a common mitigation for untrusted input). */
    static final class Deadline implements CharSequence {
        final CharSequence s; final long end;
        Deadline(CharSequence s, long end) { this.s = s; this.end = end; }
        public char charAt(int i) { if (System.nanoTime() > end) throw new RuntimeException("timeout"); return s.charAt(i); }
        public int length() { return s.length(); }
        public CharSequence subSequence(int a, int b) { return new Deadline(s.subSequence(a, b), end); }
        public String toString() { return s.toString(); }
    }

    // Email validation pattern listed as vulnerable on the OWASP ReDoS page (nested quantifiers).
    static final Pattern VULNERABLE = Pattern.compile(
        "^([a-zA-Z0-9])(([\\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$");

    static double timeMs(Pattern p, String in, long budgetMs) {
        long t0 = System.nanoTime();
        try { p.matcher(new Deadline(in, t0 + budgetMs * 1_000_000L)).find(); }
        catch (RuntimeException e) { return -1; }   // -1 = exceeded budget
        return (System.nanoTime() - t0) / 1e6;
    }

    static double pct(long[] v, double q) { long[] c = v.clone(); Arrays.sort(c); return c[(int) Math.min(c.length - 1, Math.floor(q * c.length))] / 1000.0; }

    public static void main(String[] a) throws Exception {
        try (PrintWriter out = new PrintWriter("results_e4.csv")) {
            out.println("test,input,input_chars,time_ms");
            // (a) classic exponential pattern from the OWASP ReDoS page, adversarial input a...a!
            for (int n : new int[]{16, 24, 32}) {
                String evil = "a".repeat(n) + "!";
                out.printf(Locale.ROOT, "owasp_exponential_email,a^n!,%d,%.3f%n", n + 1, timeMs(VULNERABLE, evil, 10_000));
            }
            // (b) unbounded vs bounded email pattern, find() over long input with no '@' (super-linear backtracking)
            Pattern unbounded = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
            for (int w = 0; w < 3; w++) { unbounded.matcher("a".repeat(2000)).find(); Redactor.EMAIL.matcher("a".repeat(2000)).find(); }
            for (int n : new int[]{4096, 8192, 16384, 32768, 65536}) {
                String in = "a".repeat(n);
                out.printf(Locale.ROOT, "unbounded_email,a^n,%d,%.3f%n", n, timeMs(unbounded, in, 60_000));
                out.printf(Locale.ROOT, "template_email_bounded,a^n,%d,%.3f%n", n, timeMs(Redactor.EMAIL, in, 60_000));
            }
            // (c) full template rule set on 64 KiB adversarial inputs (input is capped at 64 KiB)
            Redactor r = new Redactor(Redactor.Config.VALIDATED);
            for (int w = 0; w < 3; w++) r.redact("a".repeat(5000));
            for (String kind : new String[]{"letters", "digits", "hex-colon", "email-like"}) {
                StringBuilder b = new StringBuilder();
                Random rnd = new Random(7);
                while (b.length() < 65_536) switch (kind) {
                    case "letters" -> b.append('a');
                    case "digits" -> b.append((char) ('0' + rnd.nextInt(10)));
                    case "hex-colon" -> b.append("ab12:");
                    default -> b.append("x@y.").append(rnd.nextInt(10)).append(' ');
                }
                String in = b.substring(0, 65_536);
                long best = Long.MAX_VALUE;
                for (int rep = 0; rep < 5; rep++) { long t0 = System.nanoTime(); r.redact(in); best = Math.min(best, System.nanoTime() - t0); }
                out.printf(Locale.ROOT, "template_all_rules,%s,65536,%.3f%n", kind, best / 1e6);
            }
        }

        // E5 latency
        List<EvalDetection.Doc> docs = EvalDetection.loadGretel("gretel_en.tsv");
        List<String> logs = new ArrayList<>();
        for (String line : Files.readAllLines(Path.of("loghub.tsv")))
            logs.add(new String(Base64.getDecoder().decode(line.split("\t", 2)[1]), StandardCharsets.UTF_8));
        List<String> docTexts = docs.stream().map(EvalDetection.Doc::text).toList();
        try (PrintWriter out = new PrintWriter("results_e5.csv")) {
            out.println("workload,config,items,mean_chars,median_us,p95_us,p99_us,mean_us,throughput_MB_s");
            for (String wl : new String[]{"gretel_documents", "loghub_lines"}) {
                List<String> items = wl.startsWith("gretel") ? docTexts : logs;
                for (Redactor.Config c : Redactor.Config.values()) {
                    Redactor r = new Redactor(c);
                    for (int w = 0; w < 3; w++) for (String s : items) r.redact(s);   // warm-up
                    int reps = 5;
                    long[] t = new long[items.size() * reps];
                    long chars = 0, total = 0; int k = 0;
                    for (int rep = 0; rep < reps; rep++)
                        for (String s : items) {
                            long t0 = System.nanoTime(); r.redact(s); long dt = System.nanoTime() - t0;
                            t[k++] = dt; total += dt; chars += s.length();
                        }
                    double mean = total / (double) t.length / 1000.0;
                    out.printf(Locale.ROOT, "%s,%s,%d,%.0f,%.1f,%.1f,%.1f,%.1f,%.1f%n", wl, c, items.size(),
                        chars / (double) t.length, pct(t, 0.5), pct(t, 0.95), pct(t, 0.99), mean,
                        (chars * 2 / 1e6) / (total / 1e9));
                }
            }
        }
        System.out.println("done E4/E5");
    }
}
