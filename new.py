#!/usr/bin/env python3
import argparse
import csv
import math
import signal
import subprocess
import sys
import time

FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.stream",
    "udp.stream",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "tls.handshake.extensions_alpn_str",
    "quic.version",
]

STOP = False

GREEN = "\033[92m"
RESET = "\033[0m"


def handle_sigint(sig, frame):
    global STOP
    STOP = True


signal.signal(signal.SIGINT, handle_sigint)
signal.signal(signal.SIGTERM, handle_sigint)


def to_float(x, default=0.0):
    try:
        if x is None or x == "":
            return default
        return float(x)
    except Exception:
        return default


def to_int(x, default=0):
    try:
        if x is None or x == "":
            return default
        # tshark fields sometimes appear like "443,443" if multiple occurrences sneak in
        if isinstance(x, str) and "," in x:
            x = x.split(",")[0]
        return int(float(x))
    except Exception:
        return default


def first_nonempty(*vals):
    for v in vals:
        if v is not None and str(v) != "":
            return str(v)
    return ""


def parse_packet(row, local_ip=None, target_ip=None):
    ts = to_float(row.get("frame.time_epoch"))
    flen = to_int(row.get("frame.len"))

    src_ip = first_nonempty(row.get("ip.src"), row.get("ipv6.src"))
    dst_ip = first_nonempty(row.get("ip.dst"), row.get("ipv6.dst"))

    if target_ip and src_ip != target_ip and dst_ip != target_ip:
        return None

    tcp_sport = row.get("tcp.srcport", "")
    tcp_dport = row.get("tcp.dstport", "")
    udp_sport = row.get("udp.srcport", "")
    udp_dport = row.get("udp.dstport", "")

    src_port = to_int(tcp_sport) if tcp_sport else to_int(udp_sport)
    dst_port = to_int(tcp_dport) if tcp_dport else to_int(udp_dport)

    proto_str = (row.get("frame.protocols") or "").lower()
    wrapped = ":" + proto_str + ":"
    is_tcp = ":tcp:" in wrapped
    is_udp = ":udp:" in wrapped
    is_tls = ":tls:" in wrapped
    is_quic = ":quic:" in wrapped

    direction = 0
    if local_ip:
        if src_ip == local_ip:
            direction = +1   # Device -> AP (uplink)
        elif dst_ip == local_ip:
            direction = -1   # AP -> Device (downlink)

    flow_key = (src_ip, dst_ip, src_port, dst_port, "tcp" if is_tcp else ("udp" if is_udp else "other"))

    return {
        "ts": ts,
        "len": flen,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "is_tcp": is_tcp,
        "is_udp": is_udp,
        "is_tls": is_tls,
        "is_quic": is_quic,
        "tls_hs_type": to_int(row.get("tls.handshake.type"), default=-1),
        "sni": row.get("tls.handshake.extensions_server_name", "") or "",
        "alpn": row.get("tls.handshake.extensions_alpn_str", "") or "",
        "quic_version": row.get("quic.version", "") or "",
        "direction": direction,
        "flow_key": flow_key,
    }


def mean(vals):
    return sum(vals) / len(vals) if vals else 0.0


def std(vals):
    if not vals:
        return 0.0
    m = mean(vals)
    return math.sqrt(sum((x - m) ** 2 for x in vals) / len(vals))


def summarize_window(pkts, window_s):
    if not pkts:
        return None

    pkts = sorted(pkts, key=lambda p: p["ts"])
    lengths = [p["len"] for p in pkts]
    times = [p["ts"] for p in pkts]

    iats = [times[i] - times[i - 1] for i in range(1, len(times))]
    iat_mean = mean(iats)
    iat_std = std(iats)
    iat_cv = (iat_std / iat_mean) if iat_mean > 0 else 0.0

    total_bytes = sum(lengths)
    pps = len(pkts) / window_s
    bps = total_bytes / window_s  # bytes/sec

    udp_frac = sum(1 for p in pkts if p["is_udp"]) / len(pkts)
    tcp_frac = sum(1 for p in pkts if p["is_tcp"]) / len(pkts)
    tls_frac = sum(1 for p in pkts if p["is_tls"]) / len(pkts)
    quic_frac = sum(1 for p in pkts if p["is_quic"]) / len(pkts)

    small_frac = sum(1 for x in lengths if x < 200) / len(lengths)
    large_frac = sum(1 for x in lengths if x > 1000) / len(lengths)

    # Directional stats (if local IP known)
    up_bytes = sum(p["len"] for p in pkts if p["direction"] == +1)
    down_bytes = sum(p["len"] for p in pkts if p["direction"] == -1)
    down_up_ratio = (down_bytes / (up_bytes + 1.0)) if (down_bytes + up_bytes) > 0 else 0.0
    bidir_balance = 0.0
    if (down_bytes + up_bytes) > 0:
        bidir_balance = 1.0 - abs(down_bytes - up_bytes) / (down_bytes + up_bytes)  # 1 = balanced

    unique_dst_ips = len(set(p["dst_ip"] for p in pkts if p["dst_ip"]))
    unique_dst_ports = len(set(p["dst_port"] for p in pkts if p["dst_port"]))
    unique_flows = len(set(p["flow_key"] for p in pkts))

    tls_hs_count = sum(1 for p in pkts if p["tls_hs_type"] >= 0)
    client_hello_count = sum(1 for p in pkts if p["tls_hs_type"] == 1)
    sni_count = len(set(p["sni"] for p in pkts if p["sni"]))
    alpn_count = len(set(p["alpn"] for p in pkts if p["alpn"]))
    quic_version_count = len(set(p["quic_version"] for p in pkts if p["quic_version"]))

    # Burstiness by 1-second bins inside the window
    t0 = times[0]
    bins = [0] * max(1, int(window_s))
    for p in pkts:
        idx = int(min(window_s - 1, max(0, p["ts"] - t0)))
        bins[idx] += p["len"]
    burst_cv = (std(bins) / mean(bins)) if mean(bins) > 0 else 0.0

    return {
        "pkts": len(pkts),
        "bytes_total": total_bytes,
        "pps": pps,
        "bps": bps,
        "len_mean": mean(lengths),
        "len_std": std(lengths),
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "iat_cv": iat_cv,
        "udp_frac": udp_frac,
        "tcp_frac": tcp_frac,
        "tls_frac": tls_frac,
        "quic_frac": quic_frac,
        "small_frac": small_frac,
        "large_frac": large_frac,
        "up_bytes": up_bytes,
        "down_bytes": down_bytes,
        "down_up_ratio": down_up_ratio,
        "bidir_balance": bidir_balance,
        "unique_dst_ips": unique_dst_ips,
        "unique_dst_ports": unique_dst_ports,
        "unique_flows": unique_flows,
        "tls_hs_count": tls_hs_count,
        "client_hello_count": client_hello_count,
        "sni_count": sni_count,
        "alpn_count": alpn_count,
        "quic_version_count": quic_version_count,
        "burst_cv": burst_cv,
        "start_ts": times[0],
        "end_ts": times[-1],
    }


def classify_heuristic(s, have_direction=True):
    """
    Returns (label, confidence, reasons, scores)
    Labels: idle, browsing, gaming, video_streaming, unknown
    """
    reasons = []
    scores = {
        "idle": 0.0,
        "browsing": 0.0,
        "gaming": 0.0,
        "video_streaming": 0.0,
        "unknown": 0.0,
    }

    # --- Idle ---
    if s["pps"] < 8 and s["bps"] < 8000:
        scores["idle"] += 3.0
        reasons.append("very low traffic")
    if s["pkts"] < 20 and s["bytes_total"] < 40000:
        scores["idle"] += 1.5
    if s["tls_hs_count"] == 0 and s["unique_flows"] <= 3 and s["bps"] < 30000:
        scores["idle"] += 1.0

    # --- Browsing ---
    if s["unique_flows"] >= 6 or s["unique_dst_ips"] >= 3:
        scores["browsing"] += 2.0
        reasons.append("many short flows/destinations")
    if 10000 <= s["bps"] <= 500000:
        scores["browsing"] += 1.0
    if s["burst_cv"] > 0.8:
        scores["browsing"] += 1.0
        reasons.append("bursty transfer pattern")
    if s["client_hello_count"] >= 1 or s["sni_count"] >= 1:
        scores["browsing"] += 1.0
        reasons.append("new TLS handshakes")
    if s["tcp_frac"] + s["tls_frac"] > 0.5 or s["quic_frac"] > 0.2:
        scores["browsing"] += 0.5

    # --- Gaming ---
    if s["udp_frac"] > 0.5:
        scores["gaming"] += 2.0
        reasons.append("UDP-heavy")
    if s["small_frac"] > 0.5 and s["large_frac"] < 0.2:
        scores["gaming"] += 1.5
        reasons.append("mostly small packets")
    if 10 <= s["pps"] <= 300:
        scores["gaming"] += 1.0
    if s["unique_flows"] > 140:
        scores["gaming"] -= 2.0
    if s["iat_cv"] < 1.2:
        scores["gaming"] += 1.0
        reasons.append("steady packet timing")
    if have_direction and (s["up_bytes"] + s["down_bytes"]) > 0:
        if s["bidir_balance"] > 0.35:
            scores["gaming"] += 1.5
            reasons.append("bidirectional traffic is relatively balanced")
        if s["down_up_ratio"] < 8.0:
            scores["gaming"] += 0.5

    # --- Video streaming ---
    if s["bps"] > 250000:
        scores["video_streaming"] += 2.0
        reasons.append("high sustained throughput")
    if s["large_frac"] > 0.25:
        scores["video_streaming"] += 1.5
        reasons.append("many large packets")
    if s["quic_frac"] > 0.2 or s["tls_frac"] > 0.2:
        scores["video_streaming"] += 1.0
    if s["pkts"] > 50 and s["bps"] > 120000:
        scores["video_streaming"] += 1.0
    if have_direction and (s["up_bytes"] + s["down_bytes"]) > 0:
        if s["down_up_ratio"] > 5.0:
            scores["video_streaming"] += 2.0
            reasons.append("downlink dominates uplink")
        elif s["down_up_ratio"] > 2.5:
            scores["video_streaming"] += 1.0
    if s["burst_cv"] > 0.6 and s["bps"] > 120000:
        scores["video_streaming"] += 0.5

    # Conflict resolution
    if scores["video_streaming"] > 0 and scores["gaming"] > 0:
        if s["udp_frac"] > 0.7 and s["small_frac"] > 0.6 and s["large_frac"] < 0.15:
            scores["video_streaming"] -= 1.5
            scores["gaming"] += 0.5

    # Strong idle floor
    if s["pps"] < 3 and s["bps"] < 3000:
        scores["idle"] += 5.0

    best_label = max(scores, key=scores.get)
    best_score = scores[best_label]
    sorted_scores = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    second_score = sorted_scores[1][1] if len(sorted_scores) > 1 else 0.0
    margin = best_score - second_score

    confidence = max(0.0, min(1.0, 0.15 * best_score + 0.12 * margin))

    # Weak or ambiguous => unknown
    if best_score < 1.5 or margin < 1.5:
        best_label = "unknown"
        confidence = 0.2

    # Deduplicate reasons while preserving order
    seen = set()
    reasons_clean = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            reasons_clean.append(r)

    return best_label, confidence, reasons_clean, scores


def fmt_ts(epoch):
    try:
        return time.strftime("%H:%M:%S", time.localtime(epoch))
    except Exception:
        return f"{epoch:.3f}"


def run_tshark_live(interface, bpf_filter, fields):
    cmd = [
        "tshark",
        "-l",
        "-n",
        "-i",
        interface,
        "-f",
        bpf_filter,
        "-Y",
        "(ip or ipv6) and (tcp or udp)",
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for f in fields:
        cmd += ["-e", f]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    return proc, cmd


def is_ignored_video_false_positive(summary, label, conf):
    """
    Suppress a known false-positive pattern that looks like video_streaming
    but is actually QUIC-heavy bursty multi-flow traffic.
    """
    if label != "video_streaming":
        return False

    if (
        conf >= 0.99
        and summary["udp_frac"] >= 0.80
        and summary["large_frac"] >= 0.35
        and summary["unique_flows"] >= 50
        and summary["down_up_ratio"] <= 5.0
        and summary["bidir_balance"] >= 0.30
        and (summary["client_hello_count"] >= 1 or summary["sni_count"] >= 1)
        and summary["bps"] >= 150000
        and summary["bps"] <= 700000
    ):
        return True

    return False


def passes_hard_gate(summary, label):
    """
    Strong class-specific checks before printing.
    If these fail, suppress the prediction (effectively treated as unknown for output).
    """
    if label == "video_streaming":
        if summary["bps"] < 180000:
            return False
        if summary["large_frac"] < 0.20:
            return False
        if (summary["up_bytes"] + summary["down_bytes"]) > 0 and summary["down_up_ratio"] < 5.5:
            return False
        if summary["unique_flows"] > 45 and (summary["client_hello_count"] >= 1 or summary["sni_count"] >= 1):
            return False
        return True

    if label == "gaming":
        if summary["udp_frac"] < 0.45:
            return False
        if summary["small_frac"] < 0.40:
            return False
        if summary["large_frac"] > 0.30:
            return False
        return True

    if label == "browsing":
        if not (
            summary["unique_flows"] >= 4
            or summary["unique_dst_ips"] >= 3
            or summary["client_hello_count"] >= 1
            or summary["sni_count"] >= 1
        ):
            return False
        return True

    # idle / unknown allowed
    return True


class LabelSmoother:
    def __init__(self, required_consecutive=2):
        self.required_consecutive = required_consecutive
        self.last_label = None
        self.streak = 0

    def accept(self, label):
        if label in ("unknown",):
            self.last_label = None
            self.streak = 0
            return False

        if label == self.last_label:
            self.streak += 1
        else:
            self.last_label = label
            self.streak = 1

        return self.streak >= self.required_consecutive


def maybe_print_summary(summary, args, have_direction, smoother=None):
    label, conf, reasons, scores = classify_heuristic(summary, have_direction=have_direction)

    # Ignore known false-positive video_streaming pattern
    if is_ignored_video_false_positive(summary, label, conf):
        return

    # Hard gates for class-specific suppression
    if label != "unknown" and not passes_hard_gate(summary, label):
        return

    # Only print if confidence is strictly greater than threshold
    if conf <= args.conf_threshold:
        return

    # Temporal smoothing: require same label in consecutive windows
    if smoother is not None:
        if not smoother.accept(label):
            return

    t0 = fmt_ts(summary["start_ts"])
    t1 = fmt_ts(summary["end_ts"])
    reason_txt = "; ".join(reasons[:4]) if reasons else "no strong signal"

    label_part = f"{GREEN}label={label:<15}{RESET}"

    print(
        f"[{t0}-{t1}] "
        f"{label_part} conf={conf:.2f} "
        f"pps={summary['pps']:>6.1f} "
        f"Bps={summary['bps']:>8.0f} "
        f"udp={summary['udp_frac']:.2f} "
        f"large={summary['large_frac']:.2f} "
        f"flows={summary['unique_flows']:>3} "
        f"down/up={summary['down_up_ratio']:.2f} "
        f"| {reason_txt}"
    )

    if args.show_scores:
        print("   scores:", {k: round(v, 2) for k, v in scores.items()})


# ---- NEW: cumulative AP<->Device direction dominance (percentages) ----
def fmt_bytes(n: int) -> str:
    n = float(n)
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while n >= 1024.0 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    if i == 0:
        return f"{int(n)} {units[i]}"
    return f"{n:.2f} {units[i]}"


class DirectionStats:
    """
    direction == +1  -> Device -> AP  (uplink)
    direction == -1  -> AP -> Device  (downlink)
    direction ==  0  -> unknown (can't decide without correct --local-ip)
    """
    def __init__(self):
        self.bytes_up = 0
        self.bytes_down = 0
        self.bytes_unknown = 0
        self.pkts_up = 0
        self.pkts_down = 0
        self.pkts_unknown = 0

    def update(self, pkt):
        l = int(pkt.get("len", 0) or 0)
        d = int(pkt.get("direction", 0) or 0)
        if d == 1:
            self.bytes_up += l
            self.pkts_up += 1
        elif d == -1:
            self.bytes_down += l
            self.pkts_down += 1
        else:
            self.bytes_unknown += l
            self.pkts_unknown += 1

    def report(self) -> str:
        known_bytes = self.bytes_up + self.bytes_down
        known_pkts = self.pkts_up + self.pkts_down

        up_pct_b = (100.0 * self.bytes_up / known_bytes) if known_bytes > 0 else 0.0
        down_pct_b = (100.0 * self.bytes_down / known_bytes) if known_bytes > 0 else 0.0
        up_pct_p = (100.0 * self.pkts_up / known_pkts) if known_pkts > 0 else 0.0
        down_pct_p = (100.0 * self.pkts_down / known_pkts) if known_pkts > 0 else 0.0

        dominant = "UNKNOWN"
        if known_bytes > 0:
            dominant = "AP->Device (downlink)" if self.bytes_down > self.bytes_up else "Device->AP (uplink)"

        lines = []
        lines.append("=== Direction dominance (cumulative) ===")
        lines.append(f"Bytes  AP->Device (downlink): {fmt_bytes(self.bytes_down):>10}  ({down_pct_b:6.2f}%)")
        lines.append(f"Bytes  Device->AP (uplink) : {fmt_bytes(self.bytes_up):>10}  ({up_pct_b:6.2f}%)")
        if self.bytes_unknown > 0:
            lines.append(f"Bytes  Unknown              : {fmt_bytes(self.bytes_unknown):>10}  (not counted in %)")
        lines.append(f"Pkts   AP->Device (downlink): {self.pkts_down:>10}  ({down_pct_p:6.2f}%)")
        lines.append(f"Pkts   Device->AP (uplink) : {self.pkts_up:>10}  ({up_pct_p:6.2f}%)")
        if self.pkts_unknown > 0:
            lines.append(f"Pkts   Unknown              : {self.pkts_unknown:>10}  (not counted in %)")
        lines.append(f"Dominant direction (bytes): {dominant}")
        return "\n".join(lines)
# ----------------------------------------------------------------------


def main():
    global STOP

    ap = argparse.ArgumentParser(description="Real-time heuristic activity classifier using tshark (no ML)")
    ap.add_argument("-i", "--interface", required=True, help="Capture interface (e.g., wlan0, eth0). Use `tshark -D` to list.")
    ap.add_argument("--local-ip", default="", help="Device IP used to infer direction (Device->AP vs AP->Device).")
    ap.add_argument("--target-ip", default="", help="Only analyze packets where src or dst matches this IP.")
    ap.add_argument("--window", type=int, default=5, help="Window size in seconds (default: 5)")
    ap.add_argument("--bpf", default="tcp or udp", help='Capture filter passed to tshark -f (default: "tcp or udp")')
    ap.add_argument("--show-scores", action="store_true", help="Print per-class scores for debugging/tuning")
    ap.add_argument(
        "--conf-threshold",
        type=float,
        default=0.7,
        help="Only print windows with confidence > threshold (default: 0.7)",
    )
    args = ap.parse_args()

    local_ip = args.local_ip.strip() or None
    target_ip = args.target_ip.strip() or None
    window_s = args.window

    smoother = LabelSmoother(required_consecutive=2)

    # NEW: cumulative direction stats
    dir_stats = DirectionStats()

    proc, cmd = run_tshark_live(args.interface, args.bpf, FIELDS)

    print("[INFO] Starting tshark...")
    print("[CMD] " + " ".join(cmd))
    if not local_ip:
        print("[WARN] No --local-ip provided. Direction dominance (AP<->Device) will be mostly UNKNOWN.")
    if target_ip:
        print(f"[INFO] Only analyzing packets involving target IP: {target_ip}")
    print(f"[INFO] Window size: {window_s}s")
    print("[INFO] Press Ctrl+C to stop.\n")

    if proc.stdout is None:
        print("[ERROR] Could not read tshark stdout.", file=sys.stderr)
        sys.exit(1)

    reader = csv.DictReader(proc.stdout)
    current_window_idx = None
    current_packets = []

    try:
        for row in reader:
            if STOP:
                break

            p = parse_packet(row, local_ip=local_ip, target_ip=target_ip)
            if p is None:
                continue
            if p["ts"] <= 0 or p["len"] <= 0:
                continue

            # NEW: update cumulative direction stats per packet
            dir_stats.update(p)

            win_idx = int(p["ts"] // window_s)

            if current_window_idx is None:
                current_window_idx = win_idx

            if win_idx != current_window_idx:
                summary = summarize_window(current_packets, window_s)
                if summary:
                    maybe_print_summary(
                        summary,
                        args,
                        have_direction=bool(local_ip),
                        smoother=smoother,
                    )

                current_packets = [p]
                current_window_idx = win_idx
            else:
                current_packets.append(p)

    except KeyboardInterrupt:
        pass
    finally:
        STOP = True

        # Flush last partial window
        if current_packets:
            summary = summarize_window(current_packets, window_s)
            if summary:
                maybe_print_summary(
                    summary,
                    args,
                    have_direction=bool(local_ip),
                    smoother=smoother,
                )

        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

        if proc.stderr:
            err = proc.stderr.read().strip()
            if err:
                print("\n[tshark stderr]")
                print(err)

        # NEW: print cumulative direction dominance summary (percentages)
        print()
        print(dir_stats.report())

        print("\n[INFO] Stopped.")


if __name__ == "__main__":
    main()