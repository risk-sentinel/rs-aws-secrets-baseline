#!/usr/bin/env python3
"""Inject a `passthrough.audit` record into an HDF results document.

Why this exists
---------------
A result that cannot say what produced it, over what, at whose hand, is not
something an assessor can act on. HDF v3 carries `tool` and `components`, but
neither survives every conversion path and neither records the pipeline that
ran the scan. The audit record is written once, here, in a shape that works on
both the native v3 (`baselines[]`) and legacy (`profiles[]`) schemas.

Two rules govern the output, and both matter more than any single field:

  Generated regardless.  Clean scan, failed scan, zero findings, skipped
  upload. Never conditional on results, because the case this exists for is
  precisely the one where there are no results to speak for themselves.

  Absent is not empty.   A field that does not apply is omitted. A field that
  applies but could not be determined is null, with the reason recorded in
  `audit.notes`. "Nobody looked" and "there is nothing" must never render the
  same way.

Verifiability
-------------
Some fields are corroborable against systems we do not control (run id/url and
commit against the forge, raw_digest against the retained artifact,
profile_sha against the profile repository). Others are self-asserted
(scan.mode, actor.triggered_by). The record marks which is which so a reader
does not grant an asserted field the weight of a verified one.

Schema authority: risk-sentinel/dev-sec-ops-baseline#33.
"""

import argparse
import hashlib
import json
import os
import sys

SCHEMA_VERSION = 1

# Fields a reader can check against something we do not control. Recorded in
# the document itself rather than left to tribal knowledge.
CORROBORABLE = [
    "provenance.run_id",
    "provenance.run_url",
    "provenance.commit",
    "provenance.pipeline_sha",
    "conversion.raw_digest",
    "assessment.profile_sha",
    "actor.runner_identity",
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def count_outcomes(doc):
    """Count results across either schema.

    Returns None when the shape is unrecognised rather than zeros. Zero counts
    and "we could not count" are different claims, and reporting the second as
    the first is the failure this whole record exists to prevent.
    """
    buckets = {"total": 0, "passed": 0, "failed": 0, "skipped": 0, "not_applicable": 0}
    found = False

    for baseline in doc.get("baselines") or []:
        for req in baseline.get("requirements") or []:
            for res in req.get("results") or []:
                found = True
                buckets["total"] += 1
                buckets[{"passed": "passed", "failed": "failed",
                         "skipped": "skipped"}.get(res.get("status"), "not_applicable")] += 1

    for profile in doc.get("profiles") or []:
        for ctl in profile.get("controls") or []:
            for res in ctl.get("results") or []:
                found = True
                buckets["total"] += 1
                buckets[{"passed": "passed", "failed": "failed",
                         "skipped": "skipped"}.get(res.get("status"), "not_applicable")] += 1

    return buckets if found else None


# `hdf convert` sets tool.name to the FORMAT rather than the scanner when it
# converts InSpec output — measured: "Heimdall Data Format v1". Recording that
# as the scanner would be worse than recording nothing, because it looks like
# an answer. Fall back to the baseline/profile name, which is what actually
# did the assessing for an InSpec run.
UNINFORMATIVE_TOOL_NAMES = ("heimdall data format", "sarif")


def derive_tool(doc):
    """Scanner identity as the document states it, or None."""
    tool = doc.get("tool")
    if isinstance(tool, dict) and tool.get("name"):
        name = str(tool["name"]).lower()
        if not any(name.startswith(bad) for bad in UNINFORMATIVE_TOOL_NAMES):
            return {k: v for k, v in tool.items() if k in ("name", "version") and v}
    for container, key in (("baselines", "name"), ("profiles", "name")):
        items = doc.get(container) or []
        if items and items[0].get(key):
            return {"name": items[0][key], "version": items[0].get("version")}
    return None


def prune(obj):
    """Drop empty containers and absent keys, but KEEP explicit nulls.

    A null is a statement — "this applies and could not be determined". An
    omitted key means "does not apply here". Collapsing the two would destroy
    the distinction the record is built around.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if v is None:
                out[k] = None
                continue
            pruned = prune(v)
            if pruned in ({}, [], ""):
                continue
            out[k] = pruned
        return out
    if isinstance(obj, list):
        return [prune(v) for v in obj if v is not None]
    return obj


def build(args, doc):
    notes = []

    outcome = count_outcomes(doc)
    if outcome is None:
        notes.append(
            "outcome counts could not be derived: the document matched neither "
            "baselines[] nor profiles[]"
        )

    raw_digest = None
    if args.raw:
        if os.path.isfile(args.raw):
            raw_digest = sha256_file(args.raw)
        else:
            notes.append(f"raw_digest unavailable: {args.raw} not found at audit time")

    env = os.environ.get
    run_id = args.run_id or env("GITHUB_RUN_ID")
    repo = args.repo or env("GITHUB_REPOSITORY")
    server = env("GITHUB_SERVER_URL", "https://github.com")
    run_url = None
    if repo and run_id:
        run_url = f"{server}/{repo}/actions/runs/{run_id}"

    audit = {
        "schema_version": SCHEMA_VERSION,
        "target": {
            "id": args.target,
            "type": args.target_type,
            "boundary": args.boundary,
        },
        "scan": {
            "type": args.scan_type,
            "mode": args.scan_mode,
            "started_at": args.started_at,
            "finished_at": args.finished_at,
        },
        "scanner": derive_tool(doc),
        "assessment": {
            "profile": args.profile_name,
            "profile_version": args.profile_version,
            "profile_sha": args.profile_sha or env("GITHUB_SHA"),
            "benchmark": args.benchmark,
            "benchmark_version": args.benchmark_version,
        },
        "provenance": {
            "forge": args.forge,
            "repo": repo,
            "commit": args.commit or env("GITHUB_SHA"),
            "ref": args.ref or env("GITHUB_REF"),
            "pipeline_sha": env("GITHUB_WORKFLOW_SHA"),
            "workflow": env("GITHUB_WORKFLOW"),
            "run_id": run_id,
            "run_attempt": env("GITHUB_RUN_ATTEMPT"),
            "run_url": run_url,
        },
        "actor": {
            "triggered_by": args.actor or env("GITHUB_ACTOR"),
            "trigger": args.trigger or env("GITHUB_EVENT_NAME"),
            "runner_identity": args.runner_identity,
        },
        "conversion": {
            "converter": (doc.get("generator") or {}).get("name"),
            "converter_version": (doc.get("generator") or {}).get("version"),
            "raw_artifact": os.path.basename(args.raw) if args.raw else None,
            "raw_digest": raw_digest,
        },
        "outcome": outcome,
        "evidence_key": args.evidence_key,
        "corroborable": CORROBORABLE,
    }
    if notes:
        audit["notes"] = notes
    return prune(audit)


def flat_labels(audit):
    """The string->string subset, for readers that only understand labels."""
    out = {}
    for path in ("target.id", "target.type", "target.boundary", "scan.type",
                 "provenance.commit", "provenance.run_id", "assessment.profile"):
        section, key = path.split(".")
        val = (audit.get(section) or {}).get(key)
        if val:
            out[path.split(".")[-1] if key != "id" else "target"] = str(val)
    scanner = audit.get("scanner") or {}
    if scanner.get("name"):
        out["scanner"] = str(scanner["name"])
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hdf", required=True, help="HDF document to annotate")
    ap.add_argument("--out", help="output path (default: in place)")
    ap.add_argument("--raw", help="pre-conversion scanner artifact, hashed into raw_digest")
    ap.add_argument("--target", help="what was assessed (repo, account, host, resource)")
    ap.add_argument("--target-type", default="cloudAccount",
                    choices=["repository", "host", "cloudAccount", "cloudResource",
                             "database", "application"])
    ap.add_argument("--boundary", default=os.environ.get("EVIDENCE_BOUNDARY", "sparc"))
    ap.add_argument("--scan-type", default="runtime")
    ap.add_argument("--scan-mode")
    ap.add_argument("--started-at")
    ap.add_argument("--finished-at")
    ap.add_argument("--profile-name")
    ap.add_argument("--profile-version")
    ap.add_argument("--profile-sha")
    ap.add_argument("--benchmark")
    ap.add_argument("--benchmark-version")
    ap.add_argument("--forge", default="github")
    ap.add_argument("--repo")
    ap.add_argument("--commit")
    ap.add_argument("--ref")
    ap.add_argument("--run-id")
    ap.add_argument("--actor")
    ap.add_argument("--trigger")
    ap.add_argument("--runner-identity")
    ap.add_argument("--evidence-key")
    args = ap.parse_args()

    with open(args.hdf) as fh:
        doc = json.load(fh)

    audit = build(args, doc)

    # Never clobber. Producers already write things here — an OSCAL metadata
    # block, for one — and this record is an addition, not a replacement.
    passthrough = doc.get("passthrough")
    if not isinstance(passthrough, dict):
        passthrough = {}
    passthrough["audit"] = audit
    labels = passthrough.get("labels")
    passthrough["labels"] = {**(labels if isinstance(labels, dict) else {}),
                             **flat_labels(audit)}
    doc["passthrough"] = passthrough

    out = args.out or args.hdf
    with open(out, "w") as fh:
        json.dump(doc, fh, indent=2)

    counts = audit.get("outcome")
    print(f"audit record written to {out}"
          + (f" (outcome: {counts['total']} results)" if counts else " (outcome: UNKNOWN)"),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
