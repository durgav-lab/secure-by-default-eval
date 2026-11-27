import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** E1: recall/precision on Gretel synthetic financial PII (English test split).
 *  E2: matches on Loghub 2k samples (real system logs with no payment or identity numbers). */
public class EvalDetection {

    static final Map<String, String> IN_SCOPE = new LinkedHashMap<>();
    static {
        IN_SCOPE.put("email", "EMAIL"); IN_SCOPE.put("phone_number", "PHONE");
        IN_SCOPE.put("ssn", "SSN"); IN_SCOPE.put("credit_card_number", "CARD");
        IN_SCOPE.put("iban", "IBAN"); IN_SCOPE.put("bban", "ACCOUNT");
        IN_SCOPE.put("bank_routing_number", "ROUTING"); IN_SCOPE.put("swift_bic_code", "SWIFT_BIC");
        IN_SCOPE.put("ipv4", "IPV4"); IN_SCOPE.put("ipv6", "IPV6");
    }

    public record Gold(int s, int e, String label) {}
    public record Doc(String id, String type, String text, List<Gold> gold) {}

    static List<Doc> loadGretel(String f) throws IOException {
        List<Doc> docs = new ArrayList<>();
        for (String line : Files.readAllLines(Path.of(f))) {
            String[] p = line.split("\t", -1);
            String text = new String(Base64.getDecoder().decode(p[2]), StandardCharsets.UTF_8);
            List<Gold> g = new ArrayList<>();
            if (!p[3].isEmpty()) for (String sp : p[3].split(";")) {
                String[] q = sp.split(":", 3);
                int st = Integer.parseInt(q[0]), en = Math.min(Integer.parseInt(q[1]), text.length());
                // trim surrounding brackets, quotes and punctuation that annotators included in the span
                while (st < en && "[(<\"' \t\n".indexOf(text.charAt(st)) >= 0) st++;
                while (en > st && "])>\"'.,;: \t\n".indexOf(text.charAt(en - 1)) >= 0) en--;
                if (en > st) g.add(new Gold(st, en, q[2]));
            }
            docs.add(new Doc(p[0], p[1], text, g));
        }
        return docs;
    }

    public static void main(String[] a) throws Exception {
        List<Doc> docs = loadGretel("gretel_en.tsv");
        try (PrintWriter out = new PrintWriter("results_e1.csv")) {
            out.println("config,label,gold,full,partial,recall_full,gold_conformant,full_conformant,recall_conformant");
            PrintWriter prec = new PrintWriter("results_e1_precision.csv");
            prec.println("config,detector,predicted,overlap_gold,precision");
            PrintWriter miss = new PrintWriter("e1_misses.tsv");
            for (Redactor.Config c : Redactor.Config.values()) {
                Redactor r = new Redactor(c);
                Map<String, int[]> perLabel = new TreeMap<>();
                Map<String, int[]> perDet = new TreeMap<>();
                int docsAllInScope = 0, docsWithInScope = 0;
                for (Doc d : docs) {
                    List<Redactor.Span> det = r.detect(d.text);
                    boolean[] cov = new boolean[d.text.length()];
                    for (Redactor.Span s : det) for (int i = s.start(); i < Math.min(s.end(), cov.length); i++) cov[i] = true;
                    boolean anyIn = false, allIn = true;
                    for (Gold g : d.gold) {
                        int need = 0, got = 0;
                        for (int i = g.s; i < Math.min(g.e, cov.length); i++) {
                            if (Character.isWhitespace(d.text.charAt(i))) continue;
                            need++; if (cov[i]) got++;
                        }
                        int[] t = perLabel.computeIfAbsent(g.label, k -> new int[5]);
                        t[0]++; if (need > 0 && got == need) t[1]++; if (got > 0) t[2]++;
                        String val = d.text.substring(g.s, Math.min(g.e, d.text.length()));
                        boolean conform = switch (g.label) {
                            case "credit_card_number" -> Redactor.card(val);
                            case "bank_routing_number" -> Redactor.aba(val);
                            case "iban" -> Redactor.iban(val.replaceAll("[^A-Za-z0-9 ]", ""));
                            default -> true; };
                        if (conform) { t[3]++; if (need > 0 && got == need) t[4]++; }
                        if (IN_SCOPE.containsKey(g.label)) {
                            anyIn = true;
                            if (!(need > 0 && got == need)) {
                                allIn = false;
                                if (c == Redactor.Config.VALIDATED)
                                    miss.println(g.label + "\t" + d.text.substring(g.s, g.e).replace("\n", " ") + "\t" + d.type);
                            }
                        }
                    }
                    if (anyIn) { docsWithInScope++; if (allIn) docsAllInScope++; }
                    for (Redactor.Span s : det) {
                        boolean hit = false;
                        for (Gold g : d.gold) if (s.start() < g.e && g.s < s.end()) { hit = true; break; }
                        int[] t = perDet.computeIfAbsent(s.type().name(), k -> new int[2]);
                        t[0]++; if (hit) t[1]++;
                    }
                }
                int[] inTot = new int[5], outTot = new int[5];
                for (var e : perLabel.entrySet()) {
                    int[] t = e.getValue();
                    out.printf(Locale.ROOT, "%s,%s,%d,%d,%d,%.4f,%d,%d,%.4f%n", c, e.getKey(), t[0], t[1], t[2], t[1] / (double) t[0], t[3], t[4], t[3] == 0 ? 0 : t[4] / (double) t[3]);
                    int[] agg = IN_SCOPE.containsKey(e.getKey()) ? inTot : outTot;
                    for (int i = 0; i < 5; i++) agg[i] += t[i];
                }
                out.printf(Locale.ROOT, "%s,ALL_IN_SCOPE,%d,%d,%d,%.4f,%d,%d,%.4f%n", c, inTot[0], inTot[1], inTot[2], inTot[1] / (double) inTot[0], inTot[3], inTot[4], inTot[4] / (double) inTot[3]);
                out.printf(Locale.ROOT, "%s,ALL_OUT_OF_SCOPE,%d,%d,%d,%.4f%n", c, outTot[0], outTot[1], outTot[2], outTot[1] / (double) outTot[0]);
                out.printf(Locale.ROOT, "%s,DOCS_ALL_IN_SCOPE_REDACTED,%d,%d,0,%.4f%n", c, docsWithInScope, docsAllInScope, docsAllInScope / (double) docsWithInScope);
                int P = 0, TP = 0;
                for (var e : perDet.entrySet()) {
                    int[] t = e.getValue(); P += t[0]; TP += t[1];
                    prec.printf(Locale.ROOT, "%s,%s,%d,%d,%.4f%n", c, e.getKey(), t[0], t[1], t[1] / (double) t[0]);
                }
                prec.printf(Locale.ROOT, "%s,ALL,%d,%d,%.4f%n", c, P, TP, TP / (double) P);
            }
            prec.close(); miss.close();
        }

        // E2: Loghub
        List<String[]> logs = new ArrayList<>();
        for (String line : Files.readAllLines(Path.of("loghub.tsv"))) {
            String[] p = line.split("\t", 2);
            logs.add(new String[]{p[0], new String(Base64.getDecoder().decode(p[1]), StandardCharsets.UTF_8)});
        }
        try (PrintWriter out = new PrintWriter("results_e2.csv"); PrintWriter ex = new PrintWriter("e2_examples.tsv")) {
            out.println("config,detector,matches,lines_with_match,per_10k_lines");
            for (Redactor.Config c : Redactor.Config.values()) {
                Redactor r = new Redactor(c);
                Map<String, int[]> m = new TreeMap<>();
                Map<String, Integer> shown = new HashMap<>();
                int changed = 0;
                for (String[] l : logs) {
                    List<Redactor.Span> det = r.detect(l[1]);
                    if (!det.isEmpty()) changed++;
                    Set<String> seen = new HashSet<>();
                    for (Redactor.Span s : det) {
                        int[] t = m.computeIfAbsent(s.type().name(), k -> new int[2]);
                        t[0]++; if (seen.add(s.type().name())) t[1]++;
                        String key = c + s.type().name() + l[0];
                        if (shown.merge(key, 1, Integer::sum) <= 3)
                            ex.println(c + "\t" + s.type() + "\t" + l[0] + "\t" + l[1].substring(s.start(), s.end()) + "\t" + l[1]);
                    }
                }
                for (var e : m.entrySet())
                    out.printf(Locale.ROOT, "%s,%s,%d,%d,%.1f%n", c, e.getKey(), e.getValue()[0], e.getValue()[1], e.getValue()[0] * 10000.0 / logs.size());
                out.printf(Locale.ROOT, "%s,LINES_CHANGED,%d,%d,%.1f%n", c, changed, changed, changed * 10000.0 / logs.size());
            }
        }
        System.out.println("done E1/E2");
    }
}
