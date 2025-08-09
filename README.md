# doc-time-analyzer

Estimate total time spent editing Google Docs by combining:

 - Revisions API timestamps (major saved versions).

 - Drive Activity API events (fine-grained edit/comment activity).


## Setup
1. Enable **Google Drive API** , **Google Drive Activity API** in your Google Cloud project.
2. Create OAuth **Desktop App** credentials adding in necessary scopes from the APIs you have enabled the access for. 
3. Add required google accounts as audience test users. 
4. Download `client_secret.json` to the repo root.

## Install & Run (Poetry)

 - poetry install
 - poetry run doc-time 

 Note: config.json has the arguments including the docID that needs to be adjusted

## Heuristics
The tool supports two calculation modes:

### Revisions-based time

For each revision:
duration = min(cap_seconds, max(default_seconds, gap_to_next_revision))

Good for quick estimates when Activity API is not enabled.

### Combined sessions (Activity + Revisions)

Merge all timestamps from both APIs, sort chronologically.

Group into a session if consecutive events are ≤ session_gap_minutes apart.

Session duration = end_time - start_time.

If a session has only one event or ends without a next event, assign last_event_buffer_minutes.

No default buffer for sessions with both start and end.

Example:
 - 09:15:22 → 09:30:11  (14.8 min, multiple events)
 - 10:11:53 → 10:14:54  (3.0 min, multiple events)

## Output Files
 - raw.json – raw revisions data from Drive API.

 - activity_events.json – simplified events from Drive Activity API.

 - activity.csv – tabular version of activity events.

 - doc_time_report.json – structured summary of revision-based times.

## Notes
The Revisions API only returns major named versions, not micro-edits.

Drive Activity API returns fine-grained timestamps but may not always include actor names.

Combining both gives the most realistic time estimates.



