#!/usr/bin/env python3
"""Check update execution, independent of rule commits (which may be unchanged)."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import sys
import urllib.parse
import urllib.request


def timestamp(value):
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('GitHub timestamp must include a timezone')
    return parsed


def assess(runs, now, max_age_hours=36):
    eligible = [r for r in runs if r.get('event') in {'schedule', 'push', 'workflow_dispatch'}]
    eligible.sort(key=lambda r: timestamp(r['created_at']), reverse=True)
    if not eligible:
        raise ValueError('No update runs found on the default branch')
    latest = eligible[0]
    if latest.get('status') != 'completed':
        age = (now - timestamp(latest.get('run_started_at') or latest['created_at'])).total_seconds() / 3600
        if latest.get('status') == 'in_progress' and age > 1:
            raise ValueError('The latest update has been running for more than one hour')
        if age > max_age_hours:
            raise ValueError('The latest update has remained pending beyond the freshness limit')
    completed = [r for r in eligible if r.get('status') == 'completed']
    if not completed or completed[0].get('conclusion') != 'success':
        raise ValueError('The most recent completed update did not succeed')
    success = completed[0]
    age = (now - timestamp(success['updated_at'])).total_seconds() / 3600
    if age < -0.1 or age > max_age_hours:
        raise ValueError(f'Last successful update is outside the {max_age_hours}-hour freshness limit')
    return {'last_success_run': success['id'], 'age_hours': round(age, 2),
            'latest_status': latest['status'], 'last_success_at': success['updated_at']}


def fetch_runs(repository, branch):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid repository')
    query = urllib.parse.urlencode({'branch': branch, 'per_page': 100, 'exclude_pull_requests': 'true'})
    url = f'https://api.github.com/repos/{repository}/actions/workflows/update.yml/runs?{query}'
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'Shadowrocket-update-health/1',
               'X-GitHub-Api-Version': '2022-11-28'}
    token = os.environ.get('GH_TOKEN')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
        body = response.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024:
        raise ValueError('Oversized GitHub run metadata')
    return json.loads(body)['workflow_runs']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--branch', default='main')
    args = parser.parse_args()
    try:
        result = assess(fetch_runs(args.repository or '', args.branch), dt.datetime.now(dt.timezone.utc))
    except (ValueError, KeyError, TypeError, OSError) as exc:
        # Do not print HTTP error bodies or credentials.
        print('::error title=Rule update health::Update failed, stale, pending too long, or metadata unavailable.')
        print('Inspect the Update Shadowrocket rules workflow and rerun it; keep the last usable configuration.')
        return 1
    print('UPDATE_HEALTH_OK:', json.dumps(result, sort_keys=True))
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with Path(summary).open('a') as f:
            f.write('### Rule update health\n\nLast successful update: ' + result['last_success_at']
                    + '\n\nAge: ' + str(result['age_hours']) + ' hours. '
                    + 'A successful no-change build counts as fresh.\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
