# Normalised event contract (v1) — JSONL, one event per line

REQUIRED
id         string  EVT-[SYS]<eventId>-<6 hex>  (rule below)
recordId   int     EventRecordID
timestamp  string  UTC ISO-8601, e.g. 2026-10-24T08:00:00Z
host       string  Computer name
source     string  "live" | "simulated"
channel    string  e.g. Microsoft-Windows-Sysmon/Operational, Security
provider   string  Provider Name
eventId    int
data       object  RAW EventData/UserData, field names and values exactly as
                   Windows gives them (Image, CommandLine, ParentImage, ProcessId,
                   TargetFilename, QueryName, IpAddress...). Never rename or drop.

OPTIONAL convenience (derived from data, never instead of it)
category, user, process{image,commandLine,pid,parentImage},
network{destIp,destPort,domain}, file{path}

ID RULE (identical in every parser, so evidence IDs can be verified)
id = "EVT-" + ("SYS" if provider contains "sysmon" else "") + str(eventId)
     + "-" + sha1(f"{salt}|{host}|{channel}|{recordId}").hexdigest()[:6].upper()
salt = "" for live events; the source file name for replayed EVTX/XML files.
