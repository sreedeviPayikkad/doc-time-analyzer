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

# --- Scopes: Revisions read via Drive API (no file content needed) ---
SCOPES = [
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/drive.activity.readonly",
]

DEFAULT_PER_REV_SECONDS = 120  # your 2-minute default
SESSION_GAP_CAP_SECONDS = 30 * 60  # cap a single gap at 30 min; None disables capping


# === Config-file bootstrap ===
CONFIG_FILE = "config.json"


def _argv_from_config(conf: dict) -> list[str]:
    """Turn config keys into an argv list (so argparse handles them normally)."""
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
        "print_activity": "--print-activity",  # if you add this flag later
    }
    argv = []
    for k, v in conf.items():
        flag = argmap.get(k)
        if not flag:
            continue
        if isinstance(v, bool):
            if v:  # only include true booleans
                argv.append(flag)
        elif isinstance(v, list):
            for item in v:  # repeatable args like --doc
                argv.extend([flag, str(item)])
        else:
            argv.extend([flag, str(v)])
    return argv


# If user didn’t pass any CLI args, load config file and inject as argv
if len(sys.argv) == 1 and os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE) as f:
            conf = json.load(f)
        sys.argv.extend(_argv_from_config(conf))
    except Exception as e:
        print(f"[config] Failed to read {CONFIG_FILE}: {e}")


def get_credentials():
    token_path = "token.json"
    creds = None
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "client_secret.json", SCOPES
            )
            creds = flow.run_local_server(port=0)
        with open(token_path, "w") as f:
            f.write(creds.to_json())
    return creds


def build_drive(creds):
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def build_activity(creds):
    return build("driveactivity", "v2", credentials=creds, cache_discovery=False)


def fetch_activity_events(activity_svc, file_id):
    """Return a list of (timestamp, user) edit events with NoConsolidation."""
    events = []
    page_token = None
    while True:
        body = {
            "itemName": f"items/{file_id}",
            "pageSize": 100,
            "consolidationStrategy": {"none": {}},  # important: finest granularity
            "pageToken": page_token,
        }
        resp = activity_svc.activity().query(body=body).execute()
        for act in resp.get("activities", []):
            # pick a timestamp to show: timestamp or timeRange.endTime
            ts = act.get("timestamp")
            if not ts and "timeRange" in act and "endTime" in act["timeRange"]:
                ts = act["timeRange"]["endTime"]
            if not ts:
                continue
            # collect only edit actions
            for action in act.get("actions", []):
                detail = action.get("detail", {})
                if "edit" in detail:
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
                    events.append((ts, who))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    # sort by time
    from dateutil.parser import isoparse

    events.sort(key=lambda e: isoparse(e[0]))
    return events


def fetch_revisions_raw(drive, file_id):
    """Return a list of raw 'revisions' exactly as the API returns them."""
    fields = "nextPageToken, revisions(id, modifiedTime, lastModifyingUser(displayName,emailAddress))"
    raw_revs, page_token = [], None
    while True:
        resp = (
            drive.revisions()
            .list(fileId=file_id, fields=fields, pageToken=page_token)
            .execute()
        )
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
        norm.append(
            {
                "id": r["id"],
                "modifiedTime": t,
                "user_name": u.get("displayName") or "Unknown",
                "user_email": u.get("emailAddress") or None,
            }
        )
    norm.sort(key=lambda x: x["modifiedTime"])
    return norm, raw_revs


def durations_from_revisions(
    revs, default_seconds=DEFAULT_PER_REV_SECONDS, cap_seconds=SESSION_GAP_CAP_SECONDS
):
    """Compute durations per revision."""
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
        out.append(
            {
                "rev_id": r["id"],
                "start": this_time,
                "next": next_time,
                "gap_seconds": gap,
                "default_seconds": default_seconds,
                "cap_seconds": cap_seconds,
                "duration_seconds": int(dur),
                "user_name": r["user_name"],
                "user_email": r["user_email"],
            }
        )
    return out


def summarize(rows, group_by_user=True):
    total = sum(x["duration_seconds"] for x in rows)
    by_user = defaultdict(int)
    if group_by_user:
        for x in rows:
            key = x["user_email"] or x["user_name"]
            by_user[key] += x["duration_seconds"]
    return total, dict(by_user)


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
        w.writerow(
            [
                "doc_id",
                "rev_id",
                "start",
                "next",
                "gap_seconds",
                "default_seconds",
                "cap_seconds",
                "duration_seconds",
                "user",
            ]
        )
        for r in rows:
            w.writerow(
                [
                    doc_id,
                    r["rev_id"],
                    fmt_dt(r["start"], tzname),
                    fmt_dt(r["next"], tzname),
                    r["gap_seconds"] if r["gap_seconds"] is not None else "",
                    r["default_seconds"],
                    "" if r["cap_seconds"] is None else r["cap_seconds"],
                    r["duration_seconds"],
                    r["user_email"] or r["user_name"],
                ]
            )


def main():
    parser = argparse.ArgumentParser(
        description="Estimate time spent editing Google Docs using Revisions."
    )
    parser.add_argument(
        "--doc",
        dest="docs",
        action="append",
        required=True,
        help="Google Doc file ID. Repeat for multiple.",
    )
    parser.add_argument(
        "--default",
        type=int,
        default=DEFAULT_PER_REV_SECONDS,
        help="Default seconds per revision (no next gap).",
    )
    parser.add_argument(
        "--cap",
        type=int,
        default=SESSION_GAP_CAP_SECONDS,
        help="Cap per-revision gap seconds; -1 disables capping.",
    )
    parser.add_argument(
        "--no-user-breakdown", action="store_true", help="Do not group totals by user."
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Print per-revision reasoning (timestamps, gaps, applied duration).",
    )
    parser.add_argument(
        "--export-csv",
        type=str,
        default=None,
        help="Export per-revision rows to a CSV path.",
    )
    parser.add_argument(
        "--tz",
        type=str,
        default="America/Los_Angeles",
        help="Timezone for displaying timestamps.",
    )
    parser.add_argument(
        "--dump-raw",
        type=str,
        default=None,
        help="Write the raw Google Drive Revisions API payload to this JSON file.",
    )
    parser.add_argument(
        "--print-revs",
        action="store_true",
        help="Print normalized revisions (timestamp, user) before duration logic.",
    )
    parser.add_argument(
        "--print-activity",
        action="store_true",
        help="Print fine-grained Drive Activity edit events (NoConsolidation).",
    )
    parser.add_argument(
        "--activity-csv",
        type=str,
        default=None,
        help="Write fine-grained Drive Activity edit events to CSV.",
    )
    parser.add_argument(
        "--activity-dump-raw",
        type=str,
        default=None,
        help="Write raw Drive Activity API JSON to a file.",
    )

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
        },
    }

    print("\n=== Revisions-based time estimate ===")

    for fid in args.docs:
        # Optional: sanity check that the file exists and you have access
        file_meta = (
            drive.files()
            .get(fileId=fid, fields="id,name,mimeType,owners(emailAddress)")
            .execute()
        )
        print(
            f"Analyzing: {file_meta['name']} ({file_meta['mimeType']}) "
            f"owned by {[o['emailAddress'] for o in file_meta.get('owners', [])]}"
        )

        # ---- Drive Activity (fine-grained) ----


    if args.print_activity or args.activity_csv or args.activity_dump_raw:
        # pull events
        evs = fetch_activity_events(activity, fid)  # list of (ts_iso, user)

        # optional: print to console
        if args.print_activity:
            print(f"\n--- Drive Activity (fine-grained edits) for {fid} ---")
            for ts, who in evs:
                from dateutil.parser import isoparse

                print(f"{fmt_dt(isoparse(ts), args.tz)}\t{who}")

        # optional: dump raw activities JSON (so you can see full payloads later if you expand fetcher)
        if args.activity_dump_raw:
            base, ext = os.path.splitext(args.activity_dump_raw)
            out_path = (
                args.activity_dump_raw
                if len(args.docs) == 1
                else f"{base}_{fid}{ext or '.json'}"
            )
            # We only captured (ts,who); if you want truly raw JSON, modify fetcher to also return resp pages.
            with open(out_path, "w") as f:
                json.dump([{"timestamp": ts, "user": who} for ts, who in evs], f, indent=2)
            print(f"    (wrote activity events to {out_path})")

        # optional: export CSV
        if args.activity_csv:
            base, ext = os.path.splitext(args.activity_csv)
            out_path = (
                args.activity_csv if len(args.docs) == 1 else f"{base}_{fid}{ext or '.csv'}"
            )
            (
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                if os.path.dirname(out_path)
                else None
            )
            import csv
            from dateutil.parser import isoparse

            with open(out_path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["doc_id", "timestamp", "timestamp_local", "user"])
                for ts, who in evs:
                    dt = isoparse(ts)
                    w.writerow([fid, ts, fmt_dt(dt, args.tz), who])
            print(f"    (wrote {out_path})")

        revs, raw = list_revisions(drive, fid)

        if args.dump_raw:
            base, ext = os.path.splitext(args.dump_raw)
            out_path = (
                args.dump_raw
                if len(args.docs) == 1
                else f"{base}_{fid}{ext or '.json'}"
            )
            with open(out_path, "w") as f:
                json.dump(raw, f, indent=2)
            print(f"    (wrote raw revisions to {out_path})")

        if args.print_revs:
            print(f"\n--- Raw normalized revisions for {fid} ---")
            for r in revs:
                who = r["user_email"] or r["user_name"]
                print(f"{r['id']}\t{r['modifiedTime'].isoformat()}\t{who}")

        rows = durations_from_revisions(
            revs, default_seconds=args.default, cap_seconds=cap
        )
        total_secs, by_user = summarize(rows, group_by_user=group_by_user)

        print(f"- {fid}: {total_secs/60.0:.1f} minutes (from {len(rows)} revisions)")
        if group_by_user and by_user:
            for who, secs in sorted(
                by_user.items(), key=lambda kv: kv[1], reverse=True
            ):
                print(f"    • {who}: {secs/60.0:.1f} min")

        if args.explain:
            print_explanation(fid, rows, args.tz)

        if args.export_csv:
            base, ext = os.path.splitext(args.export_csv)
            out_path = (
                args.export_csv
                if len(args.docs) == 1
                else f"{base}_{fid}{ext or '.csv'}"
            )
            export_csv(out_path, fid, rows, args.tz)
            print(f"    (wrote {out_path})")

        report["docs"][fid] = {
            "total_seconds": total_secs,
            "revision_count": len(rows),
            "by_user": by_user if group_by_user else {},
            "revisions": [
                {
                    k: (v.isoformat() if isinstance(v, datetime) else v)
                    for k, v in r.items()
                }
                for r in rows
            ],
        }

    with open("doc_time_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\nWrote doc_time_report.json")


if __name__ == "__main__":
    main()
