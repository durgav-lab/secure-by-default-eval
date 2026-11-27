"""Converts the two public datasets into the tab-separated files read by the Java evaluation.

Inputs (place in ./data):
  gretel_pii_finance_test.json  - rows of the test split of gretelai/synthetic_pii_finance_multilingual,
                                  fetched from https://datasets-server.huggingface.co/rows (split=test),
                                  keeping row_idx, document_type, language, generated_text, pii_spans
  loghub_2k_samples.json        - {"<System>": "<contents of <System>/<System>_2k.log>"} for the 16 systems in
                                  https://github.com/logpai/loghub
"""
import base64, json

g = json.load(open("data/gretel_pii_finance_test.json", encoding="utf-8"))
en = [r for r in g if r["language"] == "English"]
u16 = lambda t, i: len(t[:i].encode("utf-16-le")) // 2   # Java uses UTF-16 offsets
dropped = 0
with open("gretel_en.tsv", "w", encoding="utf-8") as f:
    for r in en:
        t = r["generated_text"]; spans = []
        for s in json.loads(r["pii_spans"]):
            if s["start"] < 0 or s["end"] > len(t) or s["start"] >= s["end"]:
                dropped += 1; continue
            spans.append(f"{u16(t, s['start'])}:{u16(t, s['end'])}:{s['label']}")
        f.write(f"{r['row_idx']}\t{r['document_type'].replace(chr(9), ' ')}\t"
                f"{base64.b64encode(t.encode()).decode()}\t{';'.join(spans)}\n")
logs = json.load(open("data/loghub_2k_samples.json", encoding="utf-8"))
with open("loghub.tsv", "w", encoding="utf-8") as f:
    for system, text in logs.items():
        for line in text.split("\n"):
            if line.strip():
                f.write(f"{system}\t{base64.b64encode(line.encode()).decode()}\n")
print(f"English documents: {len(en)}; annotations dropped (offsets out of range): {dropped}")
