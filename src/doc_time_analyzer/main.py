import os
import json
import argparse
from datetime import timedelta
from collections import defaultdict

from dateutil.parser import isoparse

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# --- Scopes: Revisions read via Drive API (no file content needed) ---
SCOPES = ["https://www.googleapis.com/auth/drive.metadata.readonly"]

DEFAULT_PER_REV_SECONDS = 120       # your 2-minute default
SESSION_GAP_CAP_SECONDS = 30 * 60   # cap a single gap at 30 min; use None to disable


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


def list_revisions(drive, file_id):
    """
    Returns revisions sorted by modifiedTime asc with user info when available.
    """
    fields = "nextPageToken, revisions(id, modifiedTime, lastModifyingUser(displayName,emailAddress))"
    revs, page_token = [], None
    while True:
        resp = drive.revisions().list(
            fileId=file_id, fields=fields, pageToken=page_token
        ).execute()
        revs.extend(resp.get("revisions", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    # Normalize & sort
    norm = []
    for r in revs:
        t = isoparse(r["modifiedTime"])
        u = r.get("lastModifyingUser") or {}
        norm.append({
            "id": r["id"],
            "modifiedTime": t,
            "user_name": u.get("displayName") or "Unknown",
            "user_email": u.get("emailAddress") or None,
        })
    norm.sort(key=lambda x: x["modifiedTime"])
    return norm


def durations_from_revisions(revs, default_seconds=DEFAULT_PER_REV_SECONDS, cap_seconds=SESSION_GAP_CAP_SECONDS):
    """
    For each revision i: duration = max(default, gap to next revision).
    Last revision uses 'default'. Optionally cap huge gaps.
    """
    if not revs:
        return []
    out = []
    for i, r in enumerate(revs):
        if i < len(revs) - 1:
            gap = (revs[i+1]["modifiedTime"] - r["modifiedTime"]).total_seconds()
            dur = max(default_seconds, int(gap))
        else:
            dur = default_seconds
        if cap_seconds is not None:
            dur = min(dur, cap_seconds)
        out.append({
            "rev_id": r["id"],
            "start": r["modifiedTime"].isoformat(),
            "duration_seconds": int(dur),
            "user_name": r["user_name"],
            "user_email": r["user_email"],
        })
    return out


def summarize(rev_durations, group_by_user=True):
    total = sum(x["duration_seconds"] for x in rev_durations)
    by_user = defaultdict(int)
    if group_by_user:
        for x in rev_durations:
            key = x["user_email"] or x["user_name"]
            by_user[key] += x["duration_seconds"]
    return total, dict(by_user)


def main():
    parser = argparse.ArgumentParser(description="Estimate time spent editing Google Docs using Revisions.")
    parser.add_argument("--doc", dest="docs", action="append", help="Google Doc file ID. Repeat for multiple.", required=True)
    parser.add_argument("--default", type=int, default=DEFAULT_PER_REV_SECONDS, help="Default seconds per revision (no next gap).")
    parser.add_argument("--cap", type=int, default=SESSION_GAP_CAP_SECONDS, help="Cap per-revision gap seconds (use -1 to disable).")
    parser.add_argument("--no-user-breakdown", action="store_true", help="Do not group totals by user.")
    args = parser.parse_args()

    cap = None if (args.cap is not None and int(args.cap) < 0) else args.cap
    group_by_user = not args.no_user_breakdown

    creds = get_credentials()
    drive = build_drive(creds)

    report = {"docs": {}, "config": {"default_seconds": args.default, "cap_seconds": cap, "group_by_user": group_by_user}}
    print("\n=== Revisions-based time estimate ===")

    for fid in args.docs:
        revs = list_revisions(drive, fid)
        rev_durations = durations_from_revisions(revs, default_seconds=args.default, cap_seconds=cap)
        total_secs, by_user = summarize(rev_durations, group_by_user=group_by_user)

        mins = total_secs / 60.0
        print(f"- {fid}: {mins:.1f} minutes (from {len(rev_durations)} revisions)")
        if group_by_user and by_user:
            for who, secs in sorted(by_user.items(), key=lambda kv: kv[1], reverse=True):
                print(f"    • {who}: {secs/60.0:.1f} min")

        report["docs"][fid] = {
            "total_seconds": total_secs,
            "revision_count": len(rev_durations),
            "by_user": by_user if group_by_user else {},
            "revisions": rev_durations,
        }

    with open("doc_time_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\nWrote doc_time_report.json")


if __name__ == "__main__":
    main()
