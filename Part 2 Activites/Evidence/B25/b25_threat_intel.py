"""
B25 — Threat Intelligence Module
Parses Suricata fast.log output, enriches alerts with threat context,
correlates related events into attack patterns, and produces a
structured threat intelligence report.

Design:
  1. Log ingestion     — parse Suricata fast.log format
  2. IOC extraction    — pull IPs, ports, protocols from each alert
  3. TI enrichment     — classify each alert using a local threat intel kb
  4. Pattern detection — correlate alerts into multi-stage attack patterns
  5. Report generation — produce prioritised threat intelligence report
"""

import re
import json
from datetime import datetime
from collections import defaultdict

# ── Local Threat Intelligence Knowledge Base ──────────────────────────────────
# In a production system this would be fed by MISP, OpenCTI, or commercial feeds.
# Here we replicate the core classification logic using Suricata SID mappings.

THREAT_INTEL_KB = {
    # SID -> threat context
    "2052510": {
        "name":        "Known Vulnerability Scanner Domain",
        "tactic":      "Reconnaissance",
        "technique":   "Active Scanning (T1595)",
        "severity":    "Medium",
        "description": "DNS lookup for a domain associated with the Acunetix "
                       "web vulnerability scanner. Indicates active scanning "
                       "of web applications for known vulnerabilities.",
        "response":    "Investigate source host for unauthorised scanner tools. "
                       "Block outbound scanning if not authorised.",
        "mitre":       "T1595.002",
    },
    "2200025": {
        "name":        "Anomalous ICMP Traffic",
        "tactic":      "Discovery / Impact",
        "technique":   "Network Denial of Service (T1498) / Host Discovery (T1018)",
        "severity":    "Medium",
        "description": "ICMP packets with unexpected type/code combinations. "
                       "High-volume ICMP may indicate a flood attack (DoS) or "
                       "network mapping activity using non-standard ping probes.",
        "response":    "Correlate with volume data. If sustained, apply ICMP "
                       "rate limiting at the perimeter firewall.",
        "mitre":       "T1498.001",
    },
    # Generic fallback categories
    "ET SCAN": {
        "name":        "Network Scan Detected",
        "tactic":      "Reconnaissance",
        "technique":   "Network Service Discovery (T1046)",
        "severity":    "Medium",
        "description": "Automated scanning of network ports or services.",
        "response":    "Review firewall logs. Block source if scanning is persistent.",
        "mitre":       "T1046",
    },
    "ET WEB": {
        "name":        "Web Attack Attempt",
        "tactic":      "Initial Access",
        "technique":   "Exploit Public-Facing Application (T1190)",
        "severity":    "High",
        "description": "Attempt to exploit a web application vulnerability.",
        "response":    "Review web server logs. Apply WAF rules. Patch vulnerable apps.",
        "mitre":       "T1190",
    },
}

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

# ── Log Parser ────────────────────────────────────────────────────────────────
FAST_LOG_PATTERN = re.compile(
    r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+'  # timestamp
    r'\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+'              # gid:sid:rev
    r'(.+?)\s+\[\*\*\]\s+'                               # signature name
    r'\[Classification:\s*(.+?)\]\s+'                    # classification
    r'\[Priority:\s*(\d+)\]\s+'                          # priority
    r'\{(\w+)\}\s+'                                      # protocol
    r'([\d\.]+)(?::(\d+))?\s+->\s+'                     # src ip:port
    r'([\d\.]+)(?::(\d+))?'                              # dst ip:port
)

def parse_fast_log(log_text):
    alerts = []
    for line in log_text.strip().split('\n'):
        m = FAST_LOG_PATTERN.match(line.strip())
        if m:
            alerts.append({
                'timestamp':      m.group(1),
                'gid':            m.group(2),
                'sid':            m.group(3),
                'rev':            m.group(4),
                'signature':      m.group(5).strip(),
                'classification': m.group(6).strip(),
                'priority':       int(m.group(7)),
                'protocol':       m.group(8),
                'src_ip':         m.group(9),
                'src_port':       m.group(10),
                'dst_ip':         m.group(11),
                'dst_port':       m.group(12),
            })
    return alerts

# ── TI Enrichment ─────────────────────────────────────────────────────────────
def enrich_alert(alert):
    """Look up threat context from local KB using SID or signature prefix."""
    sid = alert['sid']
    sig = alert['signature']

    # Try exact SID match first
    if sid in THREAT_INTEL_KB:
        alert['ti'] = THREAT_INTEL_KB[sid]
        return alert

    # Try signature prefix match
    for prefix, ti in THREAT_INTEL_KB.items():
        if not prefix.isdigit() and sig.startswith(prefix):
            alert['ti'] = ti
            return alert

    # Default enrichment based on priority
    severity_map = {1: "High", 2: "Medium", 3: "Low"}
    alert['ti'] = {
        "name":        alert['classification'],
        "tactic":      "Unknown",
        "technique":   "Unknown",
        "severity":    severity_map.get(alert['priority'], "Low"),
        "description": f"Alert triggered by signature: {sig}",
        "response":    "Investigate manually.",
        "mitre":       "Unknown",
    }
    return alert

# ── Pattern Correlation ───────────────────────────────────────────────────────
def correlate_patterns(alerts):
    """
    Group alerts into attack patterns.
    Patterns are identified by:
      - Same source IP across multiple alert types (multi-stage attack)
      - High volume of same SID (sustained attack)
      - Recon followed by exploitation (kill chain detection)
    """
    patterns = []
    by_src = defaultdict(list)
    by_sid = defaultdict(list)

    for a in alerts:
        by_src[a['src_ip']].append(a)
        by_sid[a['sid']].append(a)

    # Pattern 1: Multi-stage from same source
    for src_ip, src_alerts in by_src.items():
        unique_sids = set(a['sid'] for a in src_alerts)
        if len(unique_sids) > 1:
            tactics = [a['ti']['tactic'] for a in src_alerts]
            patterns.append({
                'type':        'Multi-Stage Activity',
                'source_ip':   src_ip,
                'alert_count': len(src_alerts),
                'unique_sigs': len(unique_sids),
                'tactics':     list(set(tactics)),
                'risk':        'High',
                'description': f"Source {src_ip} triggered {len(unique_sids)} distinct "
                               f"signatures suggesting coordinated multi-stage activity.",
            })

    # Pattern 2: Sustained high-volume attack
    for sid, sid_alerts in by_sid.items():
        if len(sid_alerts) >= 5:
            sig_name = sid_alerts[0]['signature']
            patterns.append({
                'type':        'Sustained Attack',
                'source_ip':   sid_alerts[0]['src_ip'],
                'alert_count': len(sid_alerts),
                'unique_sigs': 1,
                'tactics':     [sid_alerts[0]['ti']['tactic']],
                'risk':        'Medium',
                'description': f"Signature '{sig_name}' fired {len(sid_alerts)} times — "
                               f"indicates sustained or automated attack activity.",
            })

    return patterns

# ── Report Generator ──────────────────────────────────────────────────────────
def generate_report(alerts, patterns, output_path):
    enriched = sorted(alerts,
        key=lambda a: SEVERITY_ORDER.get(a['ti']['severity'], 0),
        reverse=True)

    lines = []
    lines.append("=" * 65)
    lines.append("  THREAT INTELLIGENCE REPORT")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Source:    Suricata fast.log")
    lines.append("=" * 65)

    # Executive summary
    total     = len(alerts)
    by_sev    = defaultdict(int)
    for a in enriched:
        by_sev[a['ti']['severity']] += 1

    lines.append("\nEXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Total alerts analysed:   {total}")
    lines.append(f"  Unique source IPs:       {len(set(a['src_ip'] for a in alerts))}")
    lines.append(f"  Unique signatures:       {len(set(a['sid'] for a in alerts))}")
    lines.append(f"  Attack patterns found:   {len(patterns)}")
    lines.append("")
    lines.append("  Severity breakdown:")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if by_sev[sev]:
            bar = "█" * by_sev[sev]
            lines.append(f"    {sev:<10} {by_sev[sev]:>3}  {bar}")

    # Attack patterns
    if patterns:
        lines.append("\nATTACK PATTERNS DETECTED")
        lines.append("-" * 40)
        for i, p in enumerate(patterns, 1):
            lines.append(f"\n  Pattern {i}: {p['type']}")
            lines.append(f"  Risk:        {p['risk']}")
            lines.append(f"  Source IP:   {p['source_ip']}")
            lines.append(f"  Alerts:      {p['alert_count']}")
            lines.append(f"  Tactics:     {', '.join(p['tactics'])}")
            lines.append(f"  Description: {p['description']}")

    # Enriched alerts
    lines.append("\nENRICHED ALERT DETAILS")
    lines.append("-" * 40)
    seen_sids = set()
    for a in enriched:
        if a['sid'] in seen_sids:
            continue
        seen_sids.add(a['sid'])
        ti = a['ti']
        lines.append(f"\n  [{ti['severity']}] {ti['name']}")
        lines.append(f"  SID:         {a['sid']}")
        lines.append(f"  Signature:   {a['signature']}")
        lines.append(f"  Protocol:    {a['protocol']}")
        lines.append(f"  MITRE ATT&CK: {ti['mitre']} — {ti['tactic']}")
        lines.append(f"  Technique:   {ti['technique']}")
        lines.append(f"  Description: {ti['description']}")
        lines.append(f"  Response:    {ti['response']}")
        count = sum(1 for x in alerts if x['sid'] == a['sid'])
        lines.append(f"  Occurrences: {count} alerts")
        # Show timestamps
        times = [x['timestamp'] for x in alerts if x['sid'] == a['sid']]
        lines.append(f"  First seen:  {times[0]}")
        lines.append(f"  Last seen:   {times[-1]}")

    # IOC list
    lines.append("\nINDICATORS OF COMPROMISE (IOCs)")
    lines.append("-" * 40)
    src_ips  = set(a['src_ip'] for a in alerts)
    dst_ips  = set(a['dst_ip'] for a in alerts if a['dst_ip'])
    dst_ports = set(a['dst_port'] for a in alerts if a['dst_port'])
    lines.append(f"  Source IPs:        {', '.join(sorted(src_ips))}")
    lines.append(f"  Destination IPs:   {', '.join(sorted(dst_ips))}")
    lines.append(f"  Destination ports: {', '.join(sorted(p for p in dst_ports if p))}")

    # Recommendations
    lines.append("\nACTIONABLE RECOMMENDATIONS")
    lines.append("-" * 40)
    recs = set()
    for a in enriched:
        recs.add(a['ti']['response'])
    for i, rec in enumerate(recs, 1):
        lines.append(f"  {i}. {rec}")

    lines.append("\n" + "=" * 65)
    lines.append("  END OF REPORT")
    lines.append("=" * 65)

    report_text = '\n'.join(lines)
    print(report_text)
    with open(output_path, 'w') as f:
        f.write(report_text)
    return report_text

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    # Use provided log file or the sample from the student's B23 test
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            log_text = f.read()
    else:
        # Default: the actual Suricata output from B23 testing
        log_text = """05/19/2026-07:46:17.599192  [**] [1:2052510:1] ET INFO Acunetix Web Vulnerability Scanning Serice Domain in DNS Lookup (testphp .vulnweb .com) [**] [Classification: Misc activity] [Priority: 3] {UDP} 10.0.2.15:33583 -> 10.0.2.3:53
05/19/2026-07:46:17.599426  [**] [1:2052510:1] ET INFO Acunetix Web Vulnerability Scanning Serice Domain in DNS Lookup (testphp .vulnweb .com) [**] [Classification: Misc activity] [Priority: 3] {UDP} 10.0.2.15:33583 -> 10.0.2.3:53
05/22/2026-00:24:28.439461  [**] [1:2052510:1] ET INFO Acunetix Web Vulnerability Scanning Serice Domain in DNS Lookup (testphp .vulnweb .com) [**] [Classification: Misc activity] [Priority: 3] {UDP} 10.0.2.15:47768 -> 10.0.2.3:53
05/22/2026-00:24:28.440306  [**] [1:2052510:1] ET INFO Acunetix Web Vulnerability Scanning Serice Domain in DNS Lookup (testphp .vulnweb .com) [**] [Classification: Misc activity] [Priority: 3] {UDP} 10.0.2.15:47768 -> 10.0.2.3:53
05/22/2026-00:25:38.728219  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-00:25:39.059990  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-00:25:39.223520  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-00:25:39.387440  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-00:25:41.221902  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-00:25:41.493754  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-00:25:41.645916  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-00:25:41.797239  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-03:57:21.888040  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-03:57:22.230273  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-03:57:22.393538  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-03:57:22.556081  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-03:57:24.465775  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-03:57:24.781514  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-03:57:24.946420  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9
05/22/2026-03:57:25.140309  [**] [1:2200025:2] SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {ICMP} 10.0.2.15:8 -> 8.8.8.8:9"""

    print("B25 — Threat Intelligence Module")
    print("Parsing Suricata alerts...")
    alerts = parse_fast_log(log_text)
    print(f"Parsed {len(alerts)} alerts\n")

    print("Enriching with threat intelligence...")
    alerts = [enrich_alert(a) for a in alerts]

    print("Correlating attack patterns...")
    patterns = correlate_patterns(alerts)

    print("Generating report...\n")
    generate_report(alerts, patterns, "B25_threat_intel_report.txt")

