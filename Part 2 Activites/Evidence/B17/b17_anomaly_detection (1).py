"""
B17 — Implementation and Evaluation of AI-Powered Threat Detection
Implements a lightweight anomaly detection system — one of the
state-of-the-art solutions surveyed in B16.

The system uses two complementary ML techniques:
  1. Statistical baseline modelling (Z-score anomaly detection)
     — learns normal traffic patterns and flags statistical outliers
  2. Isolation Forest (unsupervised ML)
     — identifies anomalous points by how easily they can be isolated
     — effective on high-dimensional network feature vectors

Both are trained on simulated normal traffic, then evaluated against
known attack traffic (the events from our B23 Suricata testing).
"""

import numpy as np
from collections import defaultdict
from datetime import datetime

# ── Feature extraction ────────────────────────────────────────────────────────
def extract_features(alert):
    """
    Convert a network event into a numerical feature vector.
    Features chosen to capture behavioural patterns, not just signatures.
    """
    protocol_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'OTHER': 3}
    return [
        protocol_map.get(alert.get('protocol', 'OTHER'), 3),  # protocol type
        int(alert.get('dst_port') or 0),                       # destination port
        alert.get('priority', 3),                              # alert priority
        1 if alert.get('dst_ip') == '8.8.8.8' else 0,        # external destination
        alert.get('packet_rate', 1),                           # packets per second
        alert.get('byte_count', 64),                           # payload size
    ]

# ── Baseline model ────────────────────────────────────────────────────────────
class StatisticalBaselineModel:
    """
    Computes mean and standard deviation for each feature from training data.
    A sample is anomalous if any feature deviates more than threshold std devs.
    """
    def __init__(self, threshold=2.5):
        self.threshold = threshold
        self.means = None
        self.stds  = None

    def fit(self, X):
        X = np.array(X, dtype=float)
        self.means = np.mean(X, axis=0)
        self.stds  = np.std(X, axis=0)
        self.stds[self.stds == 0] = 1e-9  # avoid div by zero
        print(f"  Baseline trained on {len(X)} samples")
        print(f"  Feature means: {self.means.round(2)}")

    def predict(self, X):
        X = np.array(X, dtype=float)
        z_scores = np.abs((X - self.means) / self.stds)
        max_z = np.max(z_scores, axis=1)
        return (max_z > self.threshold).astype(int), max_z

# ── Isolation Forest (from scratch, lightweight) ──────────────────────────────
class IsolationTree:
    """Single isolation tree — splits data randomly until points are isolated."""
    def __init__(self, max_depth=8):
        self.max_depth = max_depth
        self.split_feature = None
        self.split_value = None
        self.left = None
        self.right = None
        self.size = 0
        self.depth = 0

    def fit(self, X, depth=0):
        self.size = len(X)
        self.depth = depth
        if len(X) <= 1 or depth >= self.max_depth:
            return
        n_features = X.shape[1]
        self.split_feature = np.random.randint(n_features)
        col = X[:, self.split_feature]
        col_min, col_max = col.min(), col.max()
        if col_min == col_max:
            return
        self.split_value = np.random.uniform(col_min, col_max)
        left_mask  = col < self.split_value
        right_mask = ~left_mask
        if left_mask.sum() == 0 or right_mask.sum() == 0:
            return
        self.left  = IsolationTree(self.max_depth)
        self.right = IsolationTree(self.max_depth)
        self.left.fit(X[left_mask], depth + 1)
        self.right.fit(X[right_mask], depth + 1)

    def path_length(self, x, depth=0):
        if self.split_feature is None or self.left is None:
            return depth + self._c(self.size)
        if x[self.split_feature] < self.split_value:
            return self.left.path_length(x, depth + 1)
        else:
            return self.right.path_length(x, depth + 1)

    def _c(self, n):
        if n <= 1: return 0
        return 2 * (np.log(n - 1) + 0.5772) - (2 * (n - 1) / n)


class IsolationForestModel:
    """
    Ensemble of isolation trees.
    Anomaly score = average path length across all trees.
    Short path = point was easy to isolate = anomalous.
    """
    def __init__(self, n_trees=50, contamination=0.1):
        self.n_trees = n_trees
        self.contamination = contamination
        self.trees = []
        self.threshold = None

    def fit(self, X):
        X = np.array(X, dtype=float)
        self.trees = []
        sample_size = min(256, len(X))
        for _ in range(self.n_trees):
            idx = np.random.choice(len(X), sample_size, replace=False)
            tree = IsolationTree()
            tree.fit(X[idx])
            self.trees.append(tree)
        # Set threshold from training data
        scores = self._score(X)
        self.threshold = np.percentile(scores, (1 - self.contamination) * 100)
        print(f"  Isolation Forest trained: {self.n_trees} trees, "
              f"threshold={self.threshold:.3f}")

    def _score(self, X):
        X = np.array(X, dtype=float)
        paths = np.array([[t.path_length(x) for t in self.trees] for x in X])
        avg_paths = paths.mean(axis=1)
        c = 2 * (np.log(255) + 0.5772) - (2 * 255 / 256)
        return 2 ** (-avg_paths / c)

    def predict(self, X):
        scores = self._score(np.array(X, dtype=float))
        return (scores > self.threshold).astype(int), scores

# ── Simulate training data (normal traffic) ───────────────────────────────────
def generate_normal_traffic(n=500):
    """
    Simulate normal network traffic feature vectors.
    Normal traffic: mix of TCP/UDP, common ports, low rates, small packets.
    """
    np.random.seed(42)
    samples = []
    for _ in range(n):
        samples.append([
            np.random.choice([0, 1], p=[0.7, 0.3]),  # mostly TCP
            np.random.choice([80, 443, 53, 8080, 22, 3306]),  # common ports
            3,                                          # low priority
            0,                                          # internal traffic
            np.random.uniform(0.1, 2.0),               # low packet rate
            np.random.uniform(40, 1500),               # normal packet size
        ])
    return samples

# ── Prepare attack samples from B23 ──────────────────────────────────────────
ATTACK_EVENTS = [
    # DNS scan alerts (curl -> testphp.vulnweb.com)
    {'protocol':'UDP', 'dst_port':53,  'priority':3, 'dst_ip':'10.0.2.3',
     'packet_rate':2.0, 'byte_count':85,  'label':'DNS Recon',         'expected':1},
    # ICMP flood alerts
    {'protocol':'ICMP','dst_port':0,   'priority':3, 'dst_ip':'8.8.8.8',
     'packet_rate':125, 'byte_count':84,  'label':'ICMP Flood',        'expected':1},
    # Normal HTTP (should NOT be flagged)
    {'protocol':'TCP', 'dst_port':443, 'priority':3, 'dst_ip':'1.1.1.1',
     'packet_rate':0.5, 'byte_count':512, 'label':'Normal HTTPS',      'expected':0},
    # Port scan simulation
    {'protocol':'TCP', 'dst_port':22,  'priority':2, 'dst_ip':'8.8.8.8',
     'packet_rate':50,  'byte_count':60,  'label':'Port Scan',         'expected':1},
    # Normal DNS
    {'protocol':'UDP', 'dst_port':53,  'priority':3, 'dst_ip':'8.8.8.8',
     'packet_rate':0.1, 'byte_count':64,  'label':'Normal DNS',        'expected':0},
]

# ── Evaluation ────────────────────────────────────────────────────────────────
def evaluate(name, predictions, labels):
    tp = sum(p==1 and l==1 for p,l in zip(predictions, labels))
    fp = sum(p==1 and l==0 for p,l in zip(predictions, labels))
    tn = sum(p==0 and l==0 for p,l in zip(predictions, labels))
    fn = sum(p==0 and l==1 for p,l in zip(predictions, labels))
    precision = tp/(tp+fp) if (tp+fp) > 0 else 0
    recall    = tp/(tp+fn) if (tp+fn) > 0 else 0
    f1        = 2*precision*recall/(precision+recall) if (precision+recall) > 0 else 0
    print(f"\n  {name} Results:")
    print(f"    True Positives  (attacks caught):   {tp}")
    print(f"    False Positives (false alarms):      {fp}")
    print(f"    True Negatives  (normal, correct):   {tn}")
    print(f"    False Negatives (attacks missed):    {fn}")
    print(f"    Precision: {precision:.1%}   Recall: {recall:.1%}   F1: {f1:.2f}")
    return {'tp':tp,'fp':fp,'tn':tn,'fn':fn,'precision':precision,'recall':recall,'f1':f1}

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("B17 — AI-Powered Anomaly Detection System")
    print("Implementing state-of-the-art threat detection from B16 survey")
    print("=" * 60)

    # Generate training data
    print("\n[1] Generating normal traffic baseline (500 samples)...")
    normal_data = generate_normal_traffic(500)

    # Extract test features
    test_features = [extract_features(e) for e in ATTACK_EVENTS]
    test_labels   = [e['expected'] for e in ATTACK_EVENTS]
    test_names    = [e['label'] for e in ATTACK_EVENTS]

    # Train and evaluate Statistical Baseline
    print("\n[2] Training Statistical Baseline Model...")
    stat_model = StatisticalBaselineModel(threshold=2.5)
    stat_model.fit(normal_data)
    stat_preds, stat_scores = stat_model.predict(test_features)

    # Train and evaluate Isolation Forest
    print("\n[3] Training Isolation Forest Model (50 trees)...")
    iso_model = IsolationForestModel(n_trees=50, contamination=0.15)
    iso_model.fit(normal_data)
    iso_preds, iso_scores = iso_model.predict(test_features)

    # Per-sample results
    print("\n[4] Per-sample Detection Results:")
    print(f"\n  {'Event':<22} {'Expected':<10} {'Stat Model':<14} {'Iso Forest':<14}")
    print("  " + "-" * 60)
    for i, name in enumerate(test_names):
        exp  = "ATTACK" if test_labels[i] else "normal"
        stat = "ATTACK ⚠" if stat_preds[i] else "normal ✓"
        iso  = "ATTACK ⚠" if iso_preds[i]  else "normal ✓"
        print(f"  {name:<22} {exp:<10} {stat:<14} {iso:<14}")

    # Overall evaluation
    print("\n[5] Model Evaluation:")
    stat_metrics = evaluate("Statistical Baseline", stat_preds, test_labels)
    iso_metrics  = evaluate("Isolation Forest",     iso_preds,  test_labels)

    # Discussion
    print("\n" + "=" * 60)
    print("EVALUATION DISCUSSION")
    print("=" * 60)
    print("""
  Both models were trained exclusively on normal traffic and
  evaluated against 5 labelled events (3 attacks, 2 normal).

  Statistical Baseline (Z-score):
    Simple, fast, and interpretable. Works well when attack
    traffic deviates strongly from normal on measurable features
    like packet rate (ICMP flood: 125 pps vs normal 0.1-2 pps).
    Limitation: assumes Gaussian distribution of normal traffic;
    struggles with slow, low-volume attacks that stay within
    normal statistical bounds.

  Isolation Forest:
    Unsupervised ML — no labelled attack data needed for training.
    Identifies anomalies by how easily they are isolated in
    feature space. More robust to non-Gaussian distributions.
    Limitation: requires tuning of contamination parameter;
    can produce false positives on unusual but legitimate traffic.

  Connection to B16 survey:
    This implementation demonstrates the core principles of
    AI-powered threat detection as surveyed in B16 — specifically
    the use of baseline modelling and unsupervised anomaly detection
    to catch attacks (like zero-days) that have no known signature.
    The ICMP flood from B23 testing was correctly identified by both
    models purely from its anomalous packet rate, without any
    signature rule.
    """)

    # Save report
    with open("/home/kali/Downloads/B17_evaluation_report.txt", "w") as f:
        f.write("B17 — AI-Powered Anomaly Detection Evaluation Report\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("Models: Statistical Baseline + Isolation Forest\n\n")
        f.write("Per-sample results:\n")
        for i, name in enumerate(test_names):
            exp  = "ATTACK" if test_labels[i] else "normal"
            stat = "DETECTED" if stat_preds[i] else "missed"
            iso  = "DETECTED" if iso_preds[i]  else "missed"
            f.write(f"  {name}: expected={exp}, stat={stat}, iso={iso}\n")
        f.write(f"\nStatistical Baseline: P={stat_metrics['precision']:.1%} "
                f"R={stat_metrics['recall']:.1%} F1={stat_metrics['f1']:.2f}\n")
        f.write(f"Isolation Forest:     P={iso_metrics['precision']:.1%} "
                f"R={iso_metrics['recall']:.1%} F1={iso_metrics['f1']:.2f}\n")
    print("  Report saved to B17_evaluation_report.txt")
