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


def github_json(path, query=None):
    url = 'https://api.github.com/' + path
    if query:
        url += '?' + urllib.parse.urlencode(query)
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'Shadowrocket-update-health/2',
               'X-GitHub-Api-Version': '2022-11-28'}
    token = os.environ.get('GH_TOKEN')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
        body = response.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024:
        raise ValueError('Oversized GitHub metadata')
    return json.loads(body)


def fetch_runs(repository, branch):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid repository')
    return github_json(f'repos/{repository}/actions/workflows/update.yml/runs',
                       {'branch': branch, 'per_page': 100, 'exclude_pull_requests': 'true'})['workflow_runs']


def assess_source(spec, repo, commit, now):
    """Commit activity is a maintenance signal, not a certificate of data accuracy."""
    if repo.get('archived') or repo.get('disabled'):
        raise ValueError(f'{spec["id"]}: upstream repository archived or disabled')
    revision = commit['sha']
    if not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Invalid upstream commit')
    committed = timestamp(commit['commit']['committer']['date'])
    age = (now - committed).total_seconds() / 3600
    limit = spec['max_revision_age_hours']
    if not isinstance(limit, int) or not 24 <= limit <= 720:
        raise ValueError('Invalid source freshness budget')
    if age < -1 or age > limit:
        raise ValueError(f'{spec["id"]}: upstream commit outside {limit}-hour activity budget')
    return {'source': spec['id'], 'revision': revision, 'commit_age_hours': round(age, 2),
            'max_revision_age_hours': limit}


def check_sources(specs, now):
    repositories, commits, results = {}, {}, []
    for spec in specs:
        repository, ref = spec['repository'], spec['ref']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
            raise ValueError('Invalid source repository')
        if repository not in repositories:
            repositories[repository] = github_json(f'repos/{repository}')
        key = (repository, ref)
        if key not in commits:
            commits[key] = github_json(f'repos/{repository}/commits/' + urllib.parse.quote(ref, safe=''))
        results.append(assess_source(spec, repositories[repository], commits[key], now))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--branch', default='main')
    parser.add_argument('--sources', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'sources/sources.json')
    args = parser.parse_args()
    try:
        now = dt.datetime.now(dt.timezone.utc)
        result = assess(fetch_runs(args.repository or '', args.branch), now)
        result['upstreams'] = check_sources(json.loads(args.sources.read_text())['sources'], now)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        # Do not print HTTP error bodies or credentials.
        print('::error title=Rule update health::Update or upstream activity failed, stale, or unavailable.')
        print(str(exc))
        print('Inspect the Update Shadowrocket rules workflow and rerun it; keep the last usable configuration.')
        return 1
    print('UPDATE_HEALTH_OK:', json.dumps(result, sort_keys=True))
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with Path(summary).open('a') as f:
            f.write('### Rule update health\n\nLast successful update: ' + result['last_success_at']
                    + '\n\nAge: ' + str(result['age_hours']) + ' hours. '
                    + 'A successful no-change build counts as fresh.\n')
            for source in result['upstreams']:
                f.write('\n- ' + source['source'] + ': upstream commit age '
                        + str(source['commit_age_hours']) + ' hours.\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
