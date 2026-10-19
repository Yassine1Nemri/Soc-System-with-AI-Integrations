#!/usr/bin/env python3
"""Build an attack record (attacks/NN-name.md) from real Wazuh alerts.

Needs the SSH tunnel to the Indexer (localhost:9200) and the read-only account:
  export INDEXER_USER=grafana_ro
  read -s INDEXER_PASS && export INDEXER_PASS

Usage (times are your LOCAL time):
  python3 attack_report.py "Cron job persistence" "2026-10-19 21:40" "2026-10-19 21:55" > attacks/02-cron-persistence.md

Optional: AGENT_ID=004 (default), INDEXER_URL, MIN_LEVEL=0 (default: show every level).
Only the facts come from the Indexer. Commands, 'Detected?' and tuning are for you to fill in.
"""
import base64, datetime, json, os, ssl, sys, urllib.request

INDEXER = os.environ.get("INDEXER_URL", "https://127.0.0.1:9200")
AGENT_ID = os.environ.get("AGENT_ID", "004")
MIN_LEVEL = int(os.environ.get("MIN_LEVEL", "0"))


def to_utc(text):
    """'2026-10-19 21:40' (local time) -> '2026-10-19T20:40:00Z'."""
    d = datetime.datetime.strptime(text, "%Y-%m-%d %H:%M").astimezone()
    return d.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def search(start, end):
    q = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"term": {"agent.id": AGENT_ID}},
            {"range": {"rule.level": {"gte": MIN_LEVEL}}},
            {"range": {"timestamp": {"gte": start, "lte": end}}},
        ]}},
        "aggs": {"rules": {
            "terms": {"field": "rule.id", "size": 100, "order": {"_count": "desc"}},
            "aggs": {"sample": {"top_hits": {"size": 1, "_source": [
                "rule.id", "rule.level", "rule.description", "rule.mitre.id",
                "rule.mitre.technique"]}}},
        }},
    }
    req = urllib.request.Request(
        f"{INDEXER}/wazuh-alerts-4.x-*/_search", data=json.dumps(q).encode(),
        headers={"Content-Type": "application/json"})
    tok = base64.b64encode(
        f"{os.environ['INDEXER_USER']}:{os.environ['INDEXER_PASS']}".encode()).decode()
    req.add_header("Authorization", "Basic " + tok)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False          # tunnel to 127.0.0.1, cert name differs
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        return json.load(r)["aggregations"]["rules"]["buckets"]


def render(name, start_txt, end_txt, buckets):
    rows, total, mitre = [], 0, set()
    for b in buckets:
        rule = b["sample"]["hits"]["hits"][0]["_source"]["rule"]
        ids = rule.get("mitre", {}).get("id", []) or []
        tech = rule.get("mitre", {}).get("technique", []) or []
        mitre.update(ids)
        total += b["doc_count"]
        rows.append(f"| {rule['id']} | {rule['level']} | {rule['description']} | "
                    f"{', '.join(ids) or '-'} {('(' + ', '.join(tech) + ')') if tech else ''} | {b['doc_count']} |")
    table = "\n".join(rows) if rows else "| (no alerts in this window) | | | | 0 |"
    return f"""Attack: {name}
Time started / ended: {start_txt} to {end_txt} (local time)
Commands run: TODO (paste the exact commands you ran)

Wazuh alert(s): rule ID, level, description

| Rule ID | Level | Description | MITRE | Count |
|---|---|---|---|---|
{table}

MITRE tag shown by Wazuh (correct?): {', '.join(sorted(mitre)) or 'none shown'}. TODO: compare with the expected technique ID
Number of alerts produced (noise): {total} across {len(buckets)} rule(s)
Detected? TODO yes / partly / no
What I would tune: TODO
"""


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    name, a, b = sys.argv[1:]
    print(render(name, a, b, search(to_utc(a), to_utc(b))))


if __name__ == "__main__":
    main()
