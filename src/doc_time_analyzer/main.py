import os
import csv
import json
import sys
import argparse
from collections import defaultdict
from datetime import datetime, timezone
from dateutil.parser import isoparse

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

try:
    from zoneinfo import ZoneInfo  # Py3.9+
except ImportError:
    ZoneInfo = None

# --- Scopes ---
SCOPES = [
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/drive.activity.readonly",
]

DEFAULT_PER_REV_SECONDS = 120
SESSION_GAP_CAP_SECONDS = 30 * 60

# === Config-file bootstrap ===
CONFIG_FILE = "config.json"

def _argv_from_config(conf: dict) -> list[str]:
    argmap = {
        "docs": "--doc",
        "default": "--default",
        "cap": "--cap",
        "explain": "--explain",
        "no_user_breakdown": "--no-user-breakdown",
        "export_csv": "--export-csv",
        "tz": "--tz",
        "dump_raw": "--dump-raw",
        "print_revs": "--print-revs",
        "print_activity": "--print-activity",
        "activity_csv": "--activity-csv",
        "activity_dump_raw": "--activity-dump-raw",
        "activity_events_json": "--activity-events-json",
        "mode": "--mode",
        "idle_gap": "--idle-gap",
        "last_default": "--last-default",
        "min_session": "--min-session",
        "sessions_json": "--sessions-json",
    }
    argv = []
    for k, v in conf.items():
        flag = argmap.get(k)
        if not flag:
            continue
        if isinstance(v, bool):
            if v:
                argv.append(flag)
        elif isinstance(v, list):
            for item in v:
                argv.extend([flag, str(item)])
        else:
            argv.extend([flag, str(v)])
    return argv

if len(sys.argv) == 1 and os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE) as f:
            conf = json.load(f)
        sys.argv.extend(_argv_from_config(conf))
    except Exception as e:
        print(f"[config] Failed to read {CONFIG_FILE}: {e}")

# ---------- Auth / services ----------
def get_credentials():
    token_path = "token.json"
    creds = None
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("client_secret.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_path, "w") as f:
            f.write(creds.to_json())
    return creds

def build_drive(creds):
    return build("drive", "v3", credentials=creds, cache_discovery=False)

def build_activity(creds):
    return build("driveactivity", "v2", credentials=creds, cache_discovery=False)

# ---------- Activity (edit + comment) ----------
def fetch_activity_events(activity_svc, file_id, include_types=("edit", "comment")):
    """
    Returns:
      events: list of dicts: {"timestamp": ISO, "type": "edit|comment|...", "user": str}
      raw_pages: list of raw 'activities' entries (concatenated)
    """
    events = []
    raw_pages = []
    page_token = None
    while True:
        body = {
            "itemName": f"items/{file_id}",
            "pageSize": 100,
            "consolidationStrategy": {"none": {}},
            "pageToken": page_token,
        }
        resp = activity_svc.activity().query(body=body).execute()
        acts = resp.get("activities", [])
        raw_pages.extend(acts)

        for act in acts:
            ts = act.get("timestamp")
            if not ts and "timeRange" in act and "endTime" in act["timeRange"]:
                ts = act["timeRange"]["endTime"]
            if not ts:
                continue
            for action in act.get("actions", []):
                detail = action.get("detail", {})
                if not detail:
                    continue
                action_type = next(iter(detail.keys()))
                if include_types and action_type not in include_types:
                    continue
                who = "Unknown"
                actor = action.get("actor", {})
                if "user" in actor:
                    u = actor["user"]
                    if "knownUser" in u and u["knownUser"].get("personName"):
                        who = u["knownUser"]["personName"]
                    elif "anonymousUser" in u:
                        who = "Anonymous"
                    elif "deletedUser" in u:
                        who = "Deleted User"
                events.append({"timestamp": ts, "type": action_type, "user": who})
        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    events.sort(key=lambda e: isoparse(e["timestamp"]))
    return events, raw_pages

# ---------- Revisions ----------
def fetch_revisions_raw(drive, file_id):
    fields = "nextPageToken, revisions(id, modifiedTime, lastModifyingUser(displayName,emailAddress))"
    raw_revs, page_token = [], None
    while True:
        resp = drive.revisions().list(fileId=file_id, fields=fields, pageToken=page_token).execute()
        raw_revs.extend(resp.get("revisions", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return raw_revs

def list_revisions(drive, file_id):
    raw_revs = fetch_revisions_raw(drive, file_id)
    norm = []
    for r in raw_revs:
        t = isoparse(r["modifiedTime"])
        u = r.get("lastModifyingUser") or {}
        norm.append({
            "id": r["id"],
            "modifiedTime": t,
            "user_name": u.get("displayName") or "Unknown",
            "user_email": u.get("emailAddress") or None,
        })
    norm.sort(key=lambda x: x["modifiedTime"])
    return norm, raw_revs

def durations_from_revisions(revs, default_seconds=DEFAULT_PER_REV_SECONDS, cap_seconds=SESSION_GAP_CAP_SECONDS):
    if not revs:
        return []
    out = []
    for i, r in enumerate(revs):
        this_time = r["modifiedTime"]
        next_time = revs[i + 1]["modifiedTime"] if i < len(revs) - 1 else None
        gap = int((next_time - this_time).total_seconds()) if next_time else None
        dur = default_seconds if gap is None else max(default_seconds, gap)
        if cap_seconds is not None:
            dur = min(dur, cap_seconds)
        out.append({
            "rev_id": r["id"],
            "start": this_time,
            "next": next_time,
            "gap_seconds": gap,
            "default_seconds": default_seconds,
            "cap_seconds": cap_seconds,
            "duration_seconds": int(dur),
            "user_name": r["user_name"],
            "user_email": r["user_email"],
        })
    return out

def summarize(rows, group_by_user=True):
    total = sum(x["duration_seconds"] for x in rows)
    by_user = defaultdict(int)
    if group_by_user:
        for x in rows:
            key = x["user_email"] or x["user_name"]
            by_user[key] += x["duration_seconds"]
    return total, dict(by_user)

# ---------- Combined sessions (your heuristic) ----------
def merge_event_times(revs, activity_events):
    """Collect revision times (datetime) + activity times (ISO→datetime), sort, de-dup within 30s jitter."""
    times = []
    for r in revs:
        times.append(r["modifiedTime"])
    for e in activity_events:
        times.append(isoparse(e["timestamp"]))
    times.sort()
    merged = []
    JITTER = 30  # seconds
    for t in times:
        if not merged or (t - merged[-1]).total_seconds() > JITTER:
            merged.append(t)
    return merged

def sessionize(events_dt, idle_gap_s=600, last_default_s=600, min_session_s=0):
    """
    Build sessions using an idle-gap split. Duration rules:
      - If a session has ≥2 events: duration = last_event - first_event  (NO padding)
      - If a session has exactly 1 event: duration = last_default_s      (singleton default)
    'min_session_s' is ignored for multi-event sessions (kept for API compatibility).
    Returns: list[{start, end, duration_seconds, event_count}]
    """
    if not events_dt:
        return []

    sessions = []
    i = 0
    n = len(events_dt)

    while i < n:
        # grow the session while consecutive gaps are ≤ idle_gap_s
        j = i + 1
        while j < n and (events_dt[j] - events_dt[j - 1]).total_seconds() <= idle_gap_s:
            j += 1

        sess_events = events_dt[i:j]
        ev_count = len(sess_events)

        if ev_count >= 2:
            # accurate span inside the session (no default padding)
            raw = (sess_events[-1] - sess_events[0]).total_seconds()
            dur = int(raw)
        else:
            # singleton session: apply default
            dur = int(last_default_s)

        sessions.append({
            "start": sess_events[0],
            "end": sess_events[-1],
            "duration_seconds": dur,
            "event_count": ev_count,
        })

        i = j

    return sessions

def print_sessions(doc_id, sessions, tzname):
    print(f"\n--- Combined sessions for {doc_id} ---")
    total = 0
    for s in sessions:
        total += s["duration_seconds"]
        print(f"{fmt_dt(s['start'], tzname)}  →  {fmt_dt(s['end'], tzname)}   "
              f"({s['duration_seconds']/60:.1f} min, {s['event_count']} events)")
    print(f"= Combined sessions total: {total/60:.1f} minutes")
    return total

# ---------- Printing / export helpers ----------
def fmt_dt(dt: datetime, tzname: str | None):
    if dt is None:
        return ""
    if tzname and ZoneInfo:
        try:
            return dt.astimezone(ZoneInfo(tzname)).strftime("%Y-%m-%d %H:%M:%S %Z")
        except Exception:
            pass
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def print_explanation(doc_id: str, rows, tzname: str | None):
    print(f"\n--- Explanation for {doc_id} ---")
    print("rev_id,start,next,gap_s,rule(default/cap),applied_duration_s,user")
    for r in rows:
        rule = f"default={r['default_seconds']}"
        if r["cap_seconds"] is not None:
            rule += f", cap={r['cap_seconds']}"
        print(
            f"{r['rev_id']},{fmt_dt(r['start'], tzname)},"
            f"{fmt_dt(r['next'], tzname)},"
            f"{'' if r['gap_seconds'] is None else r['gap_seconds']},"
            f"{rule},{r['duration_seconds']},"
            f"{r['user_email'] or r['user_name']}"
        )

def export_csv(path: str, doc_id: str, rows, tzname: str | None):
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["doc_id","rev_id","start","next","gap_seconds","default_seconds","cap_seconds","duration_seconds","user"])
        for r in rows:
            w.writerow([
                doc_id,
                r["rev_id"],
                fmt_dt(r["start"], tzname),
                fmt_dt(r["next"], tzname),
                r["gap_seconds"] if r["gap_seconds"] is not None else "",
                r["default_seconds"],
                "" if r["cap_seconds"] is None else r["cap_seconds"],
                r["duration_seconds"],
                r["user_email"] or r["user_name"],
            ])

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Estimate time spent on Google Docs via Revisions and/or Activity sessions.")
    parser.add_argument("--doc", dest="docs", action="append", required=True, help="Google Doc file ID. Repeat for multiple.")
    parser.add_argument("--default", type=int, default=DEFAULT_PER_REV_SECONDS, help="Default seconds per revision (no next gap).")
    parser.add_argument("--cap", type=int, default=SESSION_GAP_CAP_SECONDS, help="Cap per-revision gap seconds; -1 disables capping.")
    parser.add_argument("--no-user-breakdown", action="store_true", help="Do not group totals by user.")
    parser.add_argument("--explain", action="store_true", help="Print per-revision reasoning (timestamps, gaps, applied duration).")
    parser.add_argument("--export-csv", type=str, default=None, help="Export per-revision rows to a CSV path.")
    parser.add_argument("--tz", type=str, default="America/Los_Angeles", help="Timezone for displaying timestamps.")
    parser.add_argument("--dump-raw", type=str, default=None, help="Write the raw Google Drive Revisions API payload to this JSON file.")
    parser.add_argument("--print-revs", action="store_true", help="Print normalized revisions (timestamp, user) before duration logic.")
    # Activity flags
    parser.add_argument("--print-activity", action="store_true", help="Print Drive Activity events (NoConsolidation) with action type.")
    parser.add_argument("--activity-csv", type=str, default=None, help="Write Drive Activity events to CSV.")
    parser.add_argument("--activity-dump-raw", type=str, default=None, help="Write raw Drive Activity API JSON (activities array) to a file.")
    parser.add_argument("--activity-events-json", type=str, default=None, help="Write simplified Drive Activity events (timestamp,type,user) to JSON.")
    # Combined sessions
    parser.add_argument("--mode", type=str, choices=["revisions","combined-sessions"], default="revisions",
                        help="Use 'revisions' (default) or 'combined-sessions' to merge Activity+Revisions and sessionize.")
    parser.add_argument("--idle-gap", type=int, default=600, help="Idle gap (seconds) to split sessions. Default 600s (10 min).")
    parser.add_argument("--last-default", type=int, default=300, help="Default seconds for dangling last session. Default 300s (5 min).")
    parser.add_argument("--min-session", type=int, default=60, help="Clamp very short sessions to at least this many seconds.")
    parser.add_argument("--sessions-json", type=str, default=None, help="Write combined session rows (start,end,duration,event_count) to JSON.")

    args = parser.parse_args()
    cap = None if (args.cap is not None and int(args.cap) < 0) else args.cap
    group_by_user = not args.no_user_breakdown

    creds = get_credentials()
    drive = build_drive(creds)
    activity = build_activity(creds)

    report = {
        "docs": {},
        "config": {
            "default_seconds": args.default,
            "cap_seconds": cap,
            "group_by_user": group_by_user,
            "display_tz": args.tz,
            "mode": args.mode,
            "idle_gap": args.idle_gap,
            "last_default": args.last_default,
            "min_session": args.min_session,
        },
    }

    print("\n=== Revisions-based time estimate ===")

    for fid in args.docs:
        file_meta = drive.files().get(fileId=fid, fields="id,name,mimeType,owners(emailAddress)").execute()
        print(f"Analyzing: {file_meta['name']} ({file_meta['mimeType']}) owned by {[o['emailAddress'] for o in file_meta.get('owners', [])]}")

        # ---- Activity (edit + comment) ----
        evs = []
        raw_act = []
        need_activity = (args.print_activity or args.activity_csv or args.activity_dump_raw
                         or args.activity_events_json or args.mode == "combined-sessions")
        if need_activity:
            evs, raw_act = fetch_activity_events(activity, fid, include_types=("edit","comment"))

            if args.print_activity:
                print(f"\n--- Drive Activity (edits + comments) for {fid} ---")
                for e in evs:
                    dt = isoparse(e["timestamp"])
                    print(f"{fmt_dt(dt, args.tz)}\t{e['type']}\t{e['user']}")

            if args.activity_dump_raw:
                base, ext = os.path.splitext(args.activity_dump_raw)
                out_path = args.activity_dump_raw if len(args.docs) == 1 else f"{base}_{fid}{ext or '.json'}"
                with open(out_path, "w") as f:
                    json.dump(raw_act, f, indent=2)
                print(f"    (wrote raw activity JSON to {out_path})")

            if args.activity_events_json:
                base, ext = os.path.splitext(args.activity_events_json)
                out_path = args.activity_events_json if len(args.docs) == 1 else f"{base}_{fid}{ext or '.json'}"
                with open(out_path, "w") as f:
                    json.dump(evs, f, indent=2)
                print(f"    (wrote simplified activity events to {out_path})")

            if args.activity_csv:
                base, ext = os.path.splitext(args.activity_csv)
                out_path = args.activity_csv if len(args.docs) == 1 else f"{base}_{fid}{ext or '.csv'}"
                os.makedirs(os.path.dirname(out_path), exist_ok=True) if os.path.dirname(out_path) else None
                with open(out_path, "w", newline="") as f:
                    w = csv.writer(f)
                    w.writerow(["doc_id","timestamp","timestamp_local","type","user"])
                    for e in evs:
                        dt = isoparse(e["timestamp"])
                        w.writerow([fid, e["timestamp"], fmt_dt(dt, args.tz), e["type"], e["user"]])
                print(f"    (wrote {out_path})")

        # ---- Revisions (as before) ----
        revs, raw_revs = list_revisions(drive, fid)

        if args.dump_raw:
            base, ext = os.path.splitext(args.dump_raw)
            out_path = args.dump_raw if len(args.docs) == 1 else f"{base}_{fid}{ext or '.json'}"
            with open(out_path, "w") as f:
                json.dump(raw_revs, f, indent=2)
            print(f"    (wrote raw revisions to {out_path})")

        if args.print_revs:
            print(f"\n--- Raw normalized revisions for {fid} ---")
            for r in revs:
                who = r["user_email"] or r["user_name"]
                print(f"{r['id']}\t{r['modifiedTime'].isoformat()}\t{who}")

        # Baseline: revisions total
        rows = durations_from_revisions(revs, default_seconds=args.default, cap_seconds=cap)
        rev_total_secs, by_user = summarize(rows, group_by_user=group_by_user)
        print(f"- {fid}: {rev_total_secs/60.0:.1f} minutes (from {len(rows)} revisions)")
        if group_by_user and by_user:
            for who, secs in sorted(by_user.items(), key=lambda kv: kv[1], reverse=True):
                print(f"    • {who}: {secs/60.0:.1f} min")
        if args.explain:
            print_explanation(fid, rows, args.tz)

        # Combined sessions
        sessions = []
        combined_total = None
        if args.mode == "combined-sessions":
            merged_times = merge_event_times(revs, evs)
            sessions = sessionize(
                merged_times,
                idle_gap_s=args.idle_gap,
                last_default_s=args.last_default,
                min_session_s=args.min_session
            )
            combined_total = print_sessions(fid, sessions, args.tz)

            if args.sessions_json:
                base, ext = os.path.splitext(args.sessions_json)
                out_path = args.sessions_json if len(args.docs) == 1 else f"{base}_{fid}{ext or '.json'}"
                with open(out_path, "w") as f:
                    json.dump([
                        {
                            "start": s["start"].isoformat(),
                            "end": s["end"].isoformat(),
                            "duration_seconds": s["duration_seconds"],
                            "event_count": s["event_count"],
                        } for s in sessions
                    ], f, indent=2)
                print(f"    (wrote combined sessions to {out_path})")

        # Report JSON
        report_doc = {
            "total_seconds": rev_total_secs,
            "revision_count": len(rows),
            "by_user": by_user if group_by_user else {},
            "revisions": [
                {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items()}
                for r in rows
            ],
        }
        if sessions:
            report_doc["combined_sessions"] = {
                "total_seconds": combined_total,
                "sessions": [
                    {
                        "start": s["start"].isoformat(),
                        "end": s["end"].isoformat(),
                        "duration_seconds": s["duration_seconds"],
                        "event_count": s["event_count"],
                    } for s in sessions
                ],
                "params": {
                    "idle_gap": args.idle_gap,
                    "last_default": args.last_default,
                    "min_session": args.min_session,
                }
            }
        report["docs"][fid] = report_doc

    with open("doc_time_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\nWrote doc_time_report.json")

if __name__ == "__main__":
    main()
