#!/usr/bin/env python3
"""Review cross-source changes and explicit conversion gaps, without changing routes.

Source agreement is not independent corroboration. Decisions below are domain-only
with no DNS answers; representative regex examples do not establish equivalence.
"""
import argparse
from bisect import bisect_left
from collections import defaultdict
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys

import audit_sources
import build
from check_routing_contract import Policy, check

DIRECT = ('direct', 'enhanced', 'regional', 'apple_cn')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class Index:
    def __init__(self, rows):
        self.exact = {h for k, h in rows if k == 'DOMAIN'}
        self.suffix = {h for k, h in rows if k == 'DOMAIN-SUFFIX'}

    def hits(self, host):
        labels = host.split('.')
        found = [('DOMAIN', host)] if host in self.exact else []
        found += [('DOMAIN-SUFFIX', h) for i in range(len(labels))
                  if (h := '.'.join(labels[i:])) in self.suffix]
        return sorted(found)

    def covers(self, row):
        kind, host = row
        return any(k == 'DOMAIN-SUFFIX' or kind == 'DOMAIN' for k, _ in self.hits(host))


def evidence(indexes, host):
    return {name: hits for name, index in indexes.items() if (hits := index.hits(host))}


def decision(policy, host):
    return policy.decide(host, lambda _: [])


def conflicts(raw, policy):
    direct = {name: Index(raw[name]) for name in DIRECT}
    proxy = Index(raw['proxy'])
    # Checking every rule boundary finds exact/suffix and parent/child overlaps.
    hosts = {h for name in (*DIRECT, 'proxy') for _, h in raw[name]}
    result = []
    for host in sorted(hosts):
        p = proxy.hits(host)
        d = evidence(direct, host) if p else {}
        if d:
            result.append({'host': host, 'direct_evidence': d, 'proxy_evidence': p,
                           **decision(policy, host)})
    return result


def transition_review(raw, old, policy, old_policy):
    current_conflicts = conflicts(raw, policy)
    old_conflicts = {r['host']: r for r in conflicts(old, old_policy)}
    findings, changes = [], {}
    indexes = {name: Index(raw[name]) for name in DIRECT}
    known_hosts = {h for name in DIRECT for _, h in raw[name]} | set(policy.exact) | set(policy.suffix)
    reversed_hosts = sorted('.'.join(reversed(h.split('.'))) for h in known_hosts)
    for name in (*DIRECT, 'proxy'):
        added, removed = raw[name] - old[name], old[name] - raw[name]
        changes[name] = {'added': sorted(added), 'removed': sorted(removed)}
        if name not in DIRECT:
            continue
        for row in sorted(removed):
            # Suffix compression / equivalent representation is not a withdrawal.
            if indexes[name].covers(row):
                continue
            host = row[1]
            probes = [host] + (['sr-review-subdomain.' + host] if row[0] == 'DOMAIN-SUFFIX' else [])
            if row[0] == 'DOMAIN-SUFFIX':
                prefix = '.'.join(reversed(host.split('.'))) + '.'
                probes += ['.'.join(reversed(h.split('.'))) for h in
                           reversed_hosts[bisect_left(reversed_hosts, prefix):bisect_left(reversed_hosts, prefix + '~')]]
            retained = [{'host': h, 'remaining_sources': evidence(indexes, h), **decision(policy, h)}
                        for h in probes if decision(policy, h)['policy'] == 'DIRECT']
            if retained:
                findings.append({'type': 'removed-but-still-direct', 'source': name,
                                 'removed': row, 'retained_samples': retained,
                                 'interpretation': 'Removal intent unknown; review reclassification, refactoring or cross-source lag.'})
    for row in current_conflicts:
        previous = old_conflicts.get(row['host'])
        if row['policy'] == 'DIRECT' and (previous is None or previous['policy'] != 'DIRECT'
                or digest(row['direct_evidence']) != digest(previous['direct_evidence'])
                or digest(row['proxy_evidence']) != digest(previous['proxy_evidence'])):
            findings.append({'type': 'new-direct-conflict', **row})
    return current_conflicts, changes, findings


def gap_review(specs, inputs, manifest, reviews, policy):
    actual = defaultdict(list)
    for spec in specs['sources']:
        if spec['id'] not in DIRECT:
            continue
        _, stats = build.parse_source(inputs[spec['id']], spec)
        omitted = stats['omitted_direct_regex']
        if omitted != manifest['sources'][spec['id']]['omitted_direct_regex']:
            raise ValueError('Gap manifest differs from verified source: ' + spec['id'])
        for pattern in omitted:
            actual[pattern].append(spec['id'])
    if reviews.get('schema') != 1:
        raise ValueError('Invalid gap review schema')
    reviewed = {}
    for entry in reviews['entries']:
        pattern = entry['pattern']
        if pattern in reviewed or not entry.get('reason') or not entry.get('evidence') or not entry.get('samples'):
            raise ValueError('Missing or duplicate gap review evidence')
        if entry.get('disposition') != 'omit-with-visible-gap':
            raise ValueError('Unsupported gap disposition')
        reviewed[pattern] = entry
    rows, blockers = [], []
    for pattern, sources in sorted(actual.items()):
        entry = reviewed.get(pattern)
        row = {'pattern': pattern, 'sources': sorted(sources), 'reviewed': entry is not None,
               'coverage': 'UNKNOWN: samples are not a proof of regex-language coverage', 'samples': []}
        if entry:
            row.update(reason=entry['reason'], evidence=entry['evidence'])
            for sample in entry['samples']:
                result = decision(policy, sample['host'])
                passed = result['policy'] == sample['policy']
                row['samples'].append({**sample, 'actual': result, 'passed': passed})
                if not passed:
                    blockers.append({'type': 'gap-sample-regression', 'pattern': pattern, 'host': sample['host']})
        else:
            blockers.append({'type': 'unreviewed-conversion-gap', 'pattern': pattern})
        rows.append(row)
    return rows, blockers, sorted(set(reviewed) - set(actual))


def incident_review(root, text):
    entries = json.loads((root / 'tests/incidents.json').read_text())
    cases = json.loads((root / 'tests/routing_cases.json').read_text())
    by_id = {c['id']: c for c in cases}
    if len(by_id) != len(cases):
        raise ValueError('Duplicate routing case ID')
    seen, rows = set(), []
    for incident in entries:
        if incident['id'] in seen or any(not incident.get(k) for k in ('problem', 'evidence', 'case_ids', 'validation_scope')):
            raise ValueError('Incomplete incident record')
        seen.add(incident['id'])
        for link in incident['evidence']:
            path = (root / link).resolve()
            if not path.is_relative_to(root.resolve()) or not path.is_file():
                raise ValueError('Missing local incident evidence')
        result = check(text, [by_id[i] for i in incident['case_ids']])
        rows.append({**incident, 'failures': result['failures'], 'results': result['results']})
    if not rows:
        raise ValueError('Empty incident registry')
    return rows


def apply_approvals(findings, approval_file, baseline, candidate, today=None):
    if approval_file.get('schema') != 1:
        raise ValueError('Invalid source review schema')
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    approvals, seen = {}, set()
    for item in approval_file['approvals']:
        ident = item['id']
        if ident in seen or not item.get('reason') or not item.get('evidence'):
            raise ValueError('Invalid review approval')
        seen.add(ident)
        expires = datetime.date.fromisoformat(item['expires'])
        if expires >= today:
            approvals[ident] = item
    blockers = []
    for finding in findings:
        finding['id'] = digest({'finding': finding, 'previous': baseline, 'candidate': candidate})
        finding['reviewed'] = finding['id'] in approvals
        if finding['reviewed']:
            finding['review'] = approvals[finding['id']]
        else:
            blockers.append({'type': finding['type'], 'id': finding['id']})
    return blockers


def assess(root, previous=None):
    root = Path(root)
    specs = json.loads((root / 'sources/sources.json').read_text())
    text = (root / 'dist/Shadowrocket.conf').read_text()
    manifest = json.loads((root / 'dist/manifest.json').read_text())
    if build.sha(text.encode()) != manifest['config_sha256']:
        raise ValueError('Candidate configuration checksum mismatch')
    inputs, _ = build.offline_inputs(root / 'dist', specs)
    raw, policy = audit_sources.read_sources(root, specs), Policy(text)
    gaps, blockers, stale_gaps = gap_review(specs, inputs, manifest,
        json.loads((root / 'config/coverage-review.json').read_text()), policy)
    incidents = incident_review(root, text)
    blockers += [{'type': 'incident-regression', 'id': r['id']} for r in incidents if r['failures']]
    findings, changes, baseline = [], {}, None
    if previous is not None:
        previous = Path(previous)
        old_specs = json.loads((previous / 'sources/sources.json').read_text())
        if specs != old_specs:
            raise ValueError('Source specification changed: review migration separately')
        old_text = (previous / 'dist/Shadowrocket.conf').read_text()
        old_manifest = json.loads((previous / 'dist/manifest.json').read_text())
        if build.sha(old_text.encode()) != old_manifest['config_sha256']:
            raise ValueError('Previous configuration checksum mismatch')
        baseline = digest(old_manifest)
        rows, changes, findings = transition_review(raw, audit_sources.read_sources(previous, old_specs),
                                                   policy, Policy(old_text))
    else:
        rows = conflicts(raw, policy)
    approval_file = json.loads((root / 'config/source-reviews.json').read_text())
    blockers += apply_approvals(findings, approval_file, baseline, digest(manifest))
    return {'schema': 1, 'passed': not blockers, 'baseline_present': previous is not None,
            'config_sha256': manifest['config_sha256'], 'source_provenance': manifest['sources'],
            'source_relationship': 'direct/regional derive from v2fly; Loyalsoldier also builds on v2fly. Source count is NOT independent votes.',
            'current_conflicts': rows, 'source_changes': changes, 'review_queue': findings,
            'conversion_gaps': gaps, 'inactive_gap_reviews': stale_gaps,
            'incidents': incidents, 'blockers': blockers,
            'scope': __doc__}


def summary(report):
    lines = ['## Source collection quality', '',
             '**PASS**' if report['passed'] else '**BLOCKED — publication must keep the previous release.**', '']
    if 'error' in report:
        lines.append('Evidence validation failed; inspect source-quality.json for the error.')
    else:
        lines += ['| Check | Result |', '| --- | --- |',
                  f"| Previous snapshots compared | {report['baseline_present']} |",
                  f"| Current overlapping domain boundaries (inventory, not confirmed errors) | {len(report['current_conflicts'])} |",
                  f"| Changes requiring review | {len(report['review_queue'])} |",
                  f"| Conversion gaps (full regex coverage unknown) | {len(report['conversion_gaps'])} |",
                  f"| Tracked real-world regressions | {len(report['incidents'])} |",
                  f"| Blocking findings | {len(report['blockers'])} |", '',
                  'Related upstream projects are not independent votes. Domain decisions here use no DNS answers.', '',
                  'Complete source additions/removals, matching rules, review IDs and gap samples are in source-quality.json.']
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=build.ROOT)
    parser.add_argument('--previous-root', type=Path)
    parser.add_argument('--require-baseline', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.require_baseline and not args.previous_root:
            raise ValueError('Automatic publication requires previous source snapshots')
        report = assess(args.root, args.previous_root)
    except (ValueError, KeyError, TypeError, OSError, build.BuildError) as exc:
        report = {'passed': False, 'error': str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    markdown = summary(report)
    args.output.with_suffix('.md').write_text(markdown)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write(markdown)
    print(json.dumps({k: report[k] for k in ('passed', 'baseline_present', 'blockers', 'error') if k in report}))
    return int(not report['passed'])


if __name__ == '__main__':
    sys.exit(main())
