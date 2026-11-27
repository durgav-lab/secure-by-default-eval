"""E3 checks: JSON validity, trace/span ID integrity, and leakage of structured and free-text PII."""
import base64, json, csv

meta = []
for line in open("e3_meta.tsv", encoding="utf-8"):
    t, s, acct, email, g = line.rstrip("\n").split("\t")
    gold = [x.split("\x01") for x in base64.b64decode(g).decode("utf-8").split("\x02") if x]
    meta.append((t, s, acct, email, gold))

rows = []
for name, f in [("text-level, format-only", "e3_text_naive.jsonl"),
                ("text-level, validated", "e3_text_validated.jsonl"),
                ("field-aware, validated", "e3_field_aware.jsonl")]:
    n = invalid = trace_bad = acct_leak = email_leak = gold_n = gold_leak = 0
    for (t, s, acct, email, gold), line in zip(meta, open(f, encoding="utf-8")):
        n += 1
        line = line.rstrip("\n")
        try:
            obj = json.loads(line)
            ok = True
        except json.JSONDecodeError:
            ok = False
            invalid += 1
        if ok:
            if obj.get("traceId") != t or obj.get("spanId") != s:
                trace_bad += 1
            if str(obj.get("accountNumber")) == acct:
                acct_leak += 1
            if obj.get("customerEmail") == email:
                email_leak += 1
            text = obj.get("excerpt", "")
        else:
            if f'"traceId":"{t}"' not in line or f'"spanId":"{s}"' not in line:
                trace_bad += 1
            if acct in line:
                acct_leak += 1
            if email in line:
                email_leak += 1
            text = line
        for label, val in gold:
            v = val.strip("[]()<>\"' .,;:")
            if not v:
                continue
            gold_n += 1
            probe = v if ok else json.dumps(v)[1:-1]
            if probe in text:
                gold_leak += 1
    rows.append([name, n, invalid, trace_bad, acct_leak, email_leak, gold_n, gold_leak])

with open("results_e3.csv", "w", newline="") as fo:
    w = csv.writer(fo)
    w.writerow(["strategy", "events", "invalid_json", "trace_or_span_altered", "account_leaked",
                "email_field_leaked", "excerpt_gold_values", "excerpt_gold_leaked"])
    w.writerows(rows)
for r in rows:
    print(r)
