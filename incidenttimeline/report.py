# Printing the correlated view: worst first, network and auth findings
# together under the address they belong to.

from . import core


def render(entities, capture_first, capture_last, top=20):
    out = []
    correlated = [e for e in entities if e.verdict == "correlated"]
    out.append(f"{len(entities)} address(es) total, {len(correlated)} seen in both sources")
    out.append("")

    shown = entities[:top]
    for entity in shown:
        out.append(f"{entity.address}  [{entity.verdict}]")
        if entity.network:
            out.append(f"  network: {entity.network['packets']} packet(s), "
                       f"{entity.network['bytes']:,} byte(s)")
        if entity.auth:
            out.append(f"  auth: {entity.auth['events']} event(s), "
                       f"{entity.auth['failures']} failure(s), "
                       f"outcome: {entity.auth['outcome']}")
            overlap = entity.overlaps_capture_window(capture_first, capture_last)
            if overlap is True:
                out.append("  the auth activity falls inside the capture's window")
            elif overlap is False:
                out.append("  the auth activity does not fall inside the capture's window")
        for line in entity.findings:
            out.append(f"  - {line}")
        out.append("")

    if len(entities) > top:
        out.append(f"and {len(entities) - top} more address(es) not shown")
        out.append("")

    return "\n".join(out)


def _csv_field(value):
    # Quote a field if it holds anything that would break the row, the
    # same rule authlog-sessions uses for its own CSV output.
    value = str(value)
    if any(character in value for character in ',"\n'):
        return '"' + value.replace('"', '""') + '"'
    return value


def as_csv(entities, capture_first, capture_last):
    # One row per address, for a spreadsheet or another script. Unlike the
    # text report this does not truncate to --top, since a CSV consumer can
    # do its own filtering and truncating silently here would be a second,
    # hidden --top a script would not know to look for.
    rows = ["address,verdict,network_packets,network_bytes,auth_events,"
            "auth_failures,auth_successes,overlaps_capture_window"]
    for entity in entities:
        overlap = entity.overlaps_capture_window(capture_first, capture_last)
        fields = (
            entity.address,
            entity.verdict,
            str(entity.network["packets"]) if entity.network else "",
            str(entity.network["bytes"]) if entity.network else "",
            str(entity.auth["events"]) if entity.auth else "",
            str(entity.auth["failures"]) if entity.auth else "",
            str(entity.auth["successes"]) if entity.auth else "",
            "" if overlap is None else str(overlap),
        )
        rows.append(",".join(_csv_field(field) for field in fields))
    return "\n".join(rows) + "\n"


def as_dict(entities, capture_first, capture_last):
    return {
        "capture_first": capture_first,
        "capture_last": capture_last,
        "addresses": [
            {
                "address": entity.address,
                "verdict": entity.verdict,
                "network": entity.network,
                "auth": entity.auth,
                "overlaps_capture_window": entity.overlaps_capture_window(
                    capture_first, capture_last),
                "findings": entity.findings,
            }
            for entity in entities
        ],
    }
