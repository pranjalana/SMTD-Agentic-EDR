
"""Normalize Windows event records into a common SMTD schema."""

import xml.etree.ElementTree as ET

SCHEMA_VERSION = "0.2"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def extract_fields(raw_xml):
    """Extract System metadata and event-specific fields from raw XML."""
    root = ET.fromstring(raw_xml)
    system = root.find("e:System", NS)

    if system is None:
        raise ValueError("Windows event XML has no System element")

    def system_text(path):
        node = system.find(path, NS)
        return node.text if node is not None else None

    provider_node = system.find("e:Provider", NS)
    time_node = system.find("e:TimeCreated", NS)

    event_fields = []
    fields_by_name = {}

    for node in root.findall(".//e:EventData/e:Data", NS):
        name = node.get("Name")
        value = node.text or ""

        event_fields.append({"name": name, "value": value})

        if name:
            if name in fields_by_name:
                if not isinstance(fields_by_name[name], list):
                    fields_by_name[name] = [fields_by_name[name]]
                fields_by_name[name].append(value)
            else:
                fields_by_name[name] = value

    user_data = []
    for node in root.findall(".//e:UserData//*", NS):
        item = {
            "name": node.tag.split("}")[-1],
            "value": node.text or "",
        }
        user_data.append(item)

    return {
        "timestamp": (
            time_node.get("SystemTime") if time_node is not None else None
        ),
        "host": system_text("e:Computer"),
        "provider": (
            provider_node.get("Name") if provider_node is not None else None
        ),
        "channel": system_text("e:Channel"),
        "event_id": (
            int(system_text("e:EventID"))
            if system_text("e:EventID") else None
        ),
        "record_id": (
            int(system_text("e:EventRecordID"))
            if system_text("e:EventRecordID") else None
        ),
        "event_fields": event_fields,
        "user_data": user_data,
        "_fields_by_name": fields_by_name,
    }


def normalize_event(raw_record):
    """Normalize one collector record without discarding original evidence."""
    raw_xml = raw_record.get("raw_xml")
    if not raw_xml:
        raise ValueError("Record is missing raw_xml")

    parsed = extract_fields(raw_xml)
    fields = parsed.pop("_fields_by_name")

    def first(*names):
        for name in names:
            value = fields.get(name)
            if value not in (None, ""):
                return value
        return None

    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": parsed["timestamp"],
        "collected_at": raw_record.get("collected_at"),
        "host": parsed["host"] or raw_record.get("computer"),
        "source": parsed["channel"] or raw_record.get("source_log"),
        "provider": parsed["provider"] or raw_record.get("provider"),
        "event_id": parsed["event_id"] or raw_record.get("event_id"),
        "record_id": parsed["record_id"] or raw_record.get("record_id"),

        "user": first("User", "SubjectUserName", "TargetUserName"),
        "process_id": first("ProcessId", "NewProcessId"),
        "process_guid": first("ProcessGuid"),
        "image": first("Image", "NewProcessName"),
        "command_line": first("CommandLine", "ProcessCommandLine"),
        "parent_process_id": first("ParentProcessId"),
        "parent_process_guid": first("ParentProcessGuid"),
        "parent_image": first("ParentImage"),
        "integrity_level": first("IntegrityLevel"),
        "hashes": first("Hashes"),

        "protocol": first("Protocol"),
        "source_ip": first("SourceIp"),
        "source_port": first("SourcePort"),
        "destination_ip": first("DestinationIp"),
        "destination_port": first("DestinationPort"),
        "target_filename": first("TargetFilename"),

        "event_fields": parsed["event_fields"],
        "user_data": parsed["user_data"],
        "message": raw_record.get("message"),
        "raw_xml": raw_xml,
    }
