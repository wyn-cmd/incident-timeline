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
