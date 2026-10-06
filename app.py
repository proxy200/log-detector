import streamlit as st
import pandas as pd
import re
import random
from datetime import datetime, timedelta
from urllib.parse import unquote

st.set_page_config(
    page_title="Mini-SIEM Log Anomaly Detector",
    layout="wide"
)

MONTHS = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
]

MONTH_MAP = {month: i + 1 for i, month in enumerate(MONTHS)}


WEB_LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
)

SSH_FAILED_RE = re.compile(
    r'(?P<time>[A-Za-z]{3}\s+\d+\s\d{2}:\d{2}:\d{2}).*sshd.*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

SSH_ACCEPTED_RE = re.compile(
    r'(?P<time>[A-Za-z]{3}\s+\d+\s\d{2}:\d{2}:\d{2}).*sshd.*Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

# Attack detection patterns
SQLI_PATTERNS = [
    re.compile(r"union.*select", re.I),
    re.compile(r"select.*from", re.I),
    re.compile(r"insert.*into", re.I),
    re.compile(r"delete.*from", re.I),
    re.compile(r"drop.*table", re.I),
    re.compile(r"information_schema", re.I),
    re.compile(r"or\s+1\s*=\s*1", re.I),
    re.compile(r"'--", re.I),
    re.compile(r"sleep\(", re.I),
    re.compile(r"benchmark\(", re.I),
]

XSS_PATTERNS = [
    re.compile(r"<script", re.I),
    re.compile(r"javascript:", re.I),
    re.compile(r"onerror\s*=", re.I),
    re.compile(r"onload\s*=", re.I),
    re.compile(r"alert\(", re.I),
    re.compile(r"document\.cookie", re.I),
]

TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./", re.I),
    re.compile(r"\.\.\\", re.I),
    re.compile(r"/etc/passwd", re.I),
    re.compile(r"/proc/self", re.I),
    re.compile(r"boot\.ini", re.I),
]

SENSITIVE_PATH_PATTERNS = [
    re.compile(r"/admin", re.I),
    re.compile(r"/wp-admin", re.I),
    re.compile(r"/wp-login", re.I),
    re.compile(r"/phpmyadmin", re.I),
    re.compile(r"\.env", re.I),
    re.compile(r"\.git", re.I),
    re.compile(r"/config", re.I),
    re.compile(r"/backup", re.I),
]

SEVERITY_RANK = {
    "Low": 0,
    "Medium": 1,
    "High": 2,
    "Critical": 3
}


def higher_severity(current, new):
    return current if SEVERITY_RANK.get(current, 0) >= SEVERITY_RANK.get(new, 0) else new


def parse_web_time(time_string):
    """
    Example:
    04/Oct/2026:09:00:01 +0000
    """
    try:
        main = time_string.strip().split()[0]
        day_s, month_s, rest = main.split("/")
        year_s, time_s = rest.split(":", 1)
        hour, minute, second = map(int, time_s.split(":"))
        return datetime(
            int(year_s),
            MONTH_MAP[month_s.title()],
            int(day_s),
            hour,
            minute,
            second
        )
    except Exception:
        return pd.NaT


def parse_ssh_time(time_string):
    """
    Example:
    Oct  4 09:00:01
    """
    try:
        cleaned = re.sub(r"\s+", " ", time_string.strip())
        parts = cleaned.split(" ")
        month_s = parts[0]
        day_s = parts[1]
        time_s = parts[2]

        hour, minute, second = map(int, time_s.split(":"))

        return datetime(
            datetime.now().year,
            MONTH_MAP[month_s.title()],
            int(day_s),
            hour,
            minute,
            second
        )
    except Exception:
        return pd.NaT


def parse_web_logs(text):
    rows = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        match = WEB_LOG_RE.match(line)
        if not match:
            continue

        request = match.group("request")
        parts = request.split()

        method = ""
        path = ""

        if len(parts) >= 3 and parts[-1].startswith("HTTP"):
            method = parts[0]
            path = " ".join(parts[1:-1])
        elif len(parts) == 2:
            method = parts[0]
            path = parts[1]
        elif len(parts) == 1:
            path = parts[0]

        rows.append({
            "timestamp": parse_web_time(match.group("time")),
            "ip": match.group("ip"),
            "method": method,
            "path": path,
            "status": int(match.group("status")),
            "raw": line
        })

    return pd.DataFrame(rows)


def analyze_web_path(path):
    decoded = unquote(path or "").lower()
    matches = []
    severity = "Low"

    for pattern in SQLI_PATTERNS:
        if pattern.search(decoded):
            matches.append(f"SQLi pattern: {pattern.pattern}")
            severity = higher_severity(severity, "Critical")

    for pattern in XSS_PATTERNS:
        if pattern.search(decoded):
            matches.append(f"XSS pattern: {pattern.pattern}")
            severity = higher_severity(severity, "High")

    for pattern in TRAVERSAL_PATTERNS:
        if pattern.search(decoded):
            matches.append(f"Path traversal pattern: {pattern.pattern}")
            severity = higher_severity(severity, "High")

    for pattern in SENSITIVE_PATH_PATTERNS:
        if pattern.search(decoded):
            matches.append(f"Sensitive path: {pattern.pattern}")
            severity = higher_severity(severity, "Medium")

    return matches, severity


def detect_web_attacks(df, brute_threshold=5, scan_threshold=10):
    columns = ["timestamp", "ip", "rule", "severity", "evidence", "request"]
    alerts = []

    if df.empty:
        return pd.DataFrame(columns=columns)

    # Detect payload-based attacks in each request
    for _, row in df.iterrows():
        matches, severity = analyze_web_path(row["path"])

        if matches:
            rule = "Suspicious Web Request"

            if any(x.startswith("SQLi") for x in matches):
                rule = "SQL Injection Attempt"
            elif any(x.startswith("XSS") for x in matches):
                rule = "Cross-Site Scripting Attempt"
            elif any(x.startswith("Path traversal") for x in matches):
                rule = "Path Traversal / LFI Attempt"
            elif any(x.startswith("Sensitive path") for x in matches):
                rule = "Sensitive Path Access"

            alerts.append({
                "timestamp": row["timestamp"],
                "ip": row["ip"],
                "rule": rule,
                "severity": severity,
                "evidence": "; ".join(matches[:4]),
                "request": f"{row['method']} {row['path']}"
            })

    # Detect HTTP brute force based on many 401/403 responses
    failed_auth = df[df["status"].isin([401, 403])].copy()

    if not failed_auth.empty:
        for ip, group in failed_auth.groupby("ip"):
            count = len(group)

            if count >= brute_threshold:
                severity = "Critical" if count >= brute_threshold * 2 else "High"

                alerts.append({
                    "timestamp": group["timestamp"].min(),
                    "ip": ip,
                    "rule": "HTTP Brute Force / Authentication Failure",
                    "severity": severity,
                    "evidence": f"{count} HTTP 401/403 responses from same IP",
                    "request": group["path"].iloc[0]
                })

    # Detect scanning based on many 404 responses
    not_found = df[df["status"] == 404].copy()

    if not not_found.empty:
        for ip, group in not_found.groupby("ip"):
            count = len(group)

            if count >= scan_threshold:
                alerts.append({
                    "timestamp": group["timestamp"].min(),
                    "ip": ip,
                    "rule": "Web Scanning / Enumeration",
                    "severity": "Medium",
                    "evidence": f"{count} HTTP 404 requests from same IP",
                    "request": "Multiple missing resources requested"
                })

    # Detect very high request volume from one IP
    request_counts = df.groupby("ip").size()

    for ip, count in request_counts.items():
        if count >= 100:
            alerts.append({
                "timestamp": df[df["ip"] == ip]["timestamp"].min(),
                "ip": ip,
                "rule": "High Request Volume",
                "severity": "Low",
                "evidence": f"{count} total requests from same IP",
                "request": "Possible rate abuse / DoS behavior"
            })

    return pd.DataFrame(alerts, columns=columns)


def parse_ssh_logs(text):
    rows = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        failed_match = SSH_FAILED_RE.search(line)
        if failed_match:
            rows.append({
                "timestamp": parse_ssh_time(failed_match.group("time")),
                "ip": failed_match.group("ip"),
                "user": failed_match.group("user"),
                "event": "failed",
                "raw": line
            })
            continue

        accepted_match = SSH_ACCEPTED_RE.search(line)
        if accepted_match:
            rows.append({
                "timestamp": parse_ssh_time(accepted_match.group("time")),
                "ip": accepted_match.group("ip"),
                "user": accepted_match.group("user"),
                "event": "accepted",
                "raw": line
            })

    return pd.DataFrame(rows)


def detect_ssh_attacks(df, brute_threshold=5):
    columns = ["timestamp", "ip", "rule", "severity", "evidence", "request"]
    alerts = []

    if df.empty:
        return pd.DataFrame(columns=columns)

    failed = df[df["event"] == "failed"].copy()
    accepted = df[df["event"] == "accepted"].copy()

    # SSH brute force detection
    if not failed.empty:
        for ip, group in failed.groupby("ip"):
            count = len(group)
            unique_users = group["user"].nunique()

            if count >= brute_threshold:
                severity = "High"

                if count >= brute_threshold * 2 or unique_users >= 3:
                    severity = "Critical"

                alerts.append({
                    "timestamp": group["timestamp"].min(),
                    "ip": ip,
                    "rule": "SSH Brute Force Attempt",
                    "severity": severity,
                    "evidence": f"{count} failed SSH logins across {unique_users} username(s)",
                    "request": "Users: " + ", ".join(group["user"].unique()[:5])
                })

    # Suspicious SSH usernames
    suspicious_usernames = [
        "root",
        "admin",
        "administrator",
        "test",
        "guest",
        "oracle",
        "postgres",
        "mysql",
        "ubuntu",
        "pi"
    ]

    if not failed.empty:
        suspicious = failed[failed["user"].str.lower().isin(suspicious_usernames)].copy()

        if not suspicious.empty:
            for ip, group in suspicious.groupby("ip"):
                alerts.append({
                    "timestamp": group["timestamp"].min(),
                    "ip": ip,
                    "rule": "Suspicious SSH Username Attempt",
                    "severity": "Medium",
                    "evidence": "Attempted usernames: " + ", ".join(group["user"].unique()[:5]),
                    "request": "SSH authentication"
                })

    # Possible compromise: successful login after many failures
    if not accepted.empty and not failed.empty:
        for ip, group in accepted.groupby("ip"):
            fail_count = len(failed[failed["ip"] == ip])

            if fail_count >= brute_threshold:
                alerts.append({
                    "timestamp": group["timestamp"].min(),
                    "ip": ip,
                    "rule": "Possible Successful Compromise After Brute Force",
                    "severity": "Critical",
                    "evidence": f"{fail_count} failed SSH logins before successful login",
                    "request": f"Successful user: {group['user'].iloc[0]}"
                })

    return pd.DataFrame(alerts, columns=columns)


def format_web_time(dt):
    return f"{dt.day:02d}/{MONTHS[dt.month - 1]}/{dt.year}:{dt.strftime('%H:%M:%S')} +0000"


def generate_demo_web_logs():
    random.seed(42)

    base_time = datetime(2026, 10, 4, 9, 0, 0)
    lines = []

    normal_ips = [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12"
    ]

    normal_paths = [
        "/index.html",
        "/about",
        "/contact",
        "/products?id=10",
        "/static/app.css",
        "/api/status"
    ]

    # Normal traffic
    for i in range(70):
        current_time = base_time + timedelta(seconds=i * 2)
        ip = random.choice(normal_ips)
        path = random.choice(normal_paths)
        status = random.choice([200, 200, 200, 304])
        size = random.randint(200, 5000)

        lines.append(
            f'{ip} - - [{format_web_time(current_time)}] '
            f'"GET {path} HTTP/1.1" {status} {size}'
        )

    # SQL injection attack
    attack_time = base_time + timedelta(minutes=3)

    lines.append(
        f'203.0.113.45 - - [{format_web_time(attack_time)}] '
        f'"GET /products?id=1%27%20OR%201=1-- HTTP/1.1" 200 512'
    )

    # XSS attack
    attack_time += timedelta(seconds=5)

    lines.append(
        f'203.0.113.45 - - [{format_web_time(attack_time)}] '
        f'"GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 300'
    )

    # Path traversal attack
    attack_time += timedelta(seconds=5)

    lines.append(
        f'203.0.113.45 - - [{format_web_time(attack_time)}] '
        f'"GET /download?file=../../../../etc/passwd HTTP/1.1" 403 162'
    )

    # HTTP brute force attack
    brute_ip = "198.51.100.23"

    for i in range(9):
        current_time = base_time + timedelta(minutes=5, seconds=i * 3)

        lines.append(
            f'{brute_ip} - - [{format_web_time(current_time)}] '
            f'"POST /login HTTP/1.1" 401 123'
        )

    # Web scanning attack
    scanner_ip = "198.51.100.77"

    scan_paths = [
        "/admin",
        "/.env",
        "/.git/config",
        "/wp-login.php",
        "/phpmyadmin/index.php",
        "/backup.zip",
        "/config.php",
        "/api/.env",
        "/old",
        "/test",
        "/debug",
        "/server-status"
    ]

    for i, path in enumerate(scan_paths):
        current_time = base_time + timedelta(minutes=7, seconds=i * 2)

        lines.append(
            f'{scanner_ip} - - [{format_web_time(current_time)}] '
            f'"GET {path} HTTP/1.1" 404 162'
        )

    return "\n".join(lines)


def generate_demo_ssh_logs():
    base_time = datetime(2026, 10, 4, 9, 0, 0)
    lines = []

    # Normal accepted login
    lines.append(
        "Oct  4 08:59:10 server sshd[900]: Accepted publickey for ubuntu from 192.168.1.10 port 50022 ssh2"
    )

    attacker_ip = "203.0.113.9"

    suspicious_users = [
        "root",
        "admin",
        "test",
        "oracle",
        "postgres"
    ]

    # SSH brute force
    for i in range(12):
        current_time = base_time + timedelta(seconds=i * 4)
        user = suspicious_users[i % len(suspicious_users)]

        lines.append(
            f"Oct  4 {current_time.strftime('%H:%M:%S')} server sshd[{1000 + i}]: "
            f"Failed password for invalid user {user} from {attacker_ip} port {51000 + i} ssh2"
        )

    # Possible successful compromise after brute force
    success_time = base_time + timedelta(minutes=1)

    lines.append(
        f"Oct  4 {success_time.strftime('%H:%M:%S')} server sshd[1200]: "
        f"Accepted password for admin from {attacker_ip} port 51200 ssh2"
    )

    return "\n".join(lines)


# Streamlit UI

st.title("Mini-SIEM: Log Anomaly Detector")
st.caption(
    "A lightweight Blue Team proof-of-concept for detecting suspicious activity "
    "in web access logs and SSH authentication logs."
)

if "input_text" not in st.session_state:
    st.session_state.input_text = ""

if "log_type" not in st.session_state:
    st.session_state.log_type = "Web Access Log"

col1, col2 = st.columns(2)

with col1:
    if st.button("Load Web Demo Logs"):
        st.session_state.input_text = generate_demo_web_logs()
        st.session_state.log_type = "Web Access Log"

with col2:
    if st.button("Load SSH Demo Logs"):
        st.session_state.input_text = generate_demo_ssh_logs()
        st.session_state.log_type = "SSH Auth Log"

st.sidebar.header("Settings")

log_type_options = [
    "Web Access Log",
    "SSH Auth Log"
]

default_index = 0 if st.session_state.log_type == "Web Access Log" else 1

log_type = st.sidebar.selectbox(
    "Log type",
    options=log_type_options,
    index=default_index
)

brute_threshold = st.sidebar.slider(
    "Brute-force threshold",
    min_value=3,
    max_value=20,
    value=5,
    help="Number of failed events from one IP before it is considered brute force."
)

scan_threshold = st.sidebar.slider(
    "Web scan threshold (404s)",
    min_value=5,
    max_value=50,
    value=10,
    help="Number of 404 responses from one IP before it is considered scanning."
)

uploaded_file = st.sidebar.file_uploader(
    "Upload log file (optional)",
    type=["log", "txt"]
)

input_text = st.text_area(
    "Paste logs or load demo logs",
    value=st.session_state.get("input_text", ""),
    height=260
)

if uploaded_file is not None:
    input_text = uploaded_file.read().decode("utf-8", errors="ignore")
    st.session_state.input_text = input_text

if st.button("Analyze Logs", type="primary"):
    if not input_text.strip():
        st.warning("Please paste logs, upload a log file, or load demo logs first.")
    else:
        if log_type == "Web Access Log":
            parsed_df = parse_web_logs(input_text)
            alert_df = detect_web_attacks(
                parsed_df,
                brute_threshold=brute_threshold,
                scan_threshold=scan_threshold
            )
        else:
            parsed_df = parse_ssh_logs(input_text)
            alert_df = detect_ssh_attacks(
                parsed_df,
                brute_threshold=brute_threshold
            )

        st.session_state.df = parsed_df
        st.session_state.alerts = alert_df
        st.session_state.log_type_used = log_type

        st.success("Log analysis completed.")

if "alerts" in st.session_state:
    alert_df = st.session_state.alerts.copy()
    parsed_df = st.session_state.df.copy()

    st.subheader("Security Dashboard")

    if alert_df.empty:
        st.success("No alerts detected in the provided logs.")
    else:
        severity_order = ["Critical", "High", "Medium", "Low"]

        alert_df["severity"] = pd.Categorical(
            alert_df["severity"],
            categories=severity_order,
            ordered=True
        )

        alert_df = alert_df.sort_values(
            by=["severity", "timestamp"],
            ascending=[False, True]
        )

        total_events = len(parsed_df)
        total_alerts = len(alert_df)
        critical_alerts = len(alert_df[alert_df["severity"] == "Critical"])
        unique_attacker_ips = alert_df["ip"].nunique()

        metric1, metric2, metric3, metric4 = st.columns(4)

        metric1.metric("Total Events", total_events)
        metric2.metric("Total Alerts", total_alerts)
        metric3.metric("Critical Alerts", critical_alerts)
        metric4.metric("Suspicious IPs", unique_attacker_ips)

        st.markdown("### Detected Alerts")
        st.dataframe(alert_df)

        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.markdown("### Alerts by Severity")
            st.bar_chart(alert_df["severity"].value_counts())

        with chart_col2:
            st.markdown("### Top Suspicious IPs")
            st.bar_chart(alert_df["ip"].value_counts().head(10))

        timeline_df = alert_df.dropna(subset=["timestamp"]).copy()

        if not timeline_df.empty:
            timeline = timeline_df.set_index("timestamp").resample("1min").size()

            st.markdown("### Alerts Over Time")
            st.line_chart(timeline)

        st.markdown("### Recommended Actions")

        high_priority_ips = alert_df[
            alert_df["severity"].isin(["Critical", "High"])
        ]["ip"].unique()

        if len(high_priority_ips) > 0:
            st.write("Consider investigating or blocking the following IPs:")

            for ip in high_priority_ips[:10]:
                st.code(f"sudo iptables -A INPUT -s {ip} -j DROP", language="bash")

            st.warning(
                "Only apply firewall rules in an authorized lab environment. "
                "Blocking IPs in production requires proper change control and monitoring."
            )
        else:
            st.info("No high-priority IPs detected in this analysis.")

        st.download_button(
            label="Download Alerts as CSV",
            data=alert_df.to_csv(index=False).encode("utf-8"),
            file_name="siem_alerts.csv",
            mime="text/csv"
        )

        with st.expander("View Parsed Events"):
            st.dataframe(parsed_df)