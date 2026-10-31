import datetime as dt
from pathlib import Path
from unittest.mock import patch
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import check_update_health as h


class HealthTests(unittest.TestCase):
    now = dt.datetime(2026, 10, 31, 4, 0, tzinfo=dt.timezone.utc)

    def run_data(self, age=12, conclusion='success', status='completed', event='schedule', ident=1):
        t = (self.now - dt.timedelta(hours=age)).isoformat()
        return {'id': ident, 'created_at': t, 'updated_at': t, 'run_started_at': t,
                'status': status, 'conclusion': conclusion, 'event': event}

    def test_success_without_commit_is_fresh(self):
        self.assertEqual(h.assess([self.run_data()], self.now)['age_hours'], 12)

    def test_stale_failed_and_missing_runs_fail(self):
        for runs in [[], [self.run_data(age=37)], [self.run_data(conclusion='failure')],
                     [self.run_data(age=1, conclusion='cancelled'), self.run_data(age=12)],
                     [self.run_data(age=-1)]]:
            with self.subTest(runs=runs), self.assertRaises(ValueError):
                h.assess(runs, self.now)

    def test_recent_running_build_does_not_hide_previous_failure(self):
        running = self.run_data(age=0.1, status='in_progress', conclusion=None)
        self.assertEqual(h.assess([running, self.run_data(age=12)], self.now)['latest_status'], 'in_progress')
        with self.assertRaises(ValueError):
            h.assess([running, self.run_data(age=12, conclusion='failure')], self.now)

    def test_stuck_running_and_queued_runs_fail(self):
        for status, age in [('in_progress', 2), ('queued', 37)]:
            with self.subTest(status=status), self.assertRaises(ValueError):
                h.assess([self.run_data(age=age, status=status), self.run_data(age=age + 1)], self.now)

    def test_older_run_retry_is_ordered_by_completion(self):
        retry = self.run_data(age=72, conclusion='failure', ident=2)
        retry['updated_at'] = self.run_data(age=1)['updated_at']
        with self.assertRaisesRegex(ValueError, 'did not succeed'):
            h.assess([self.run_data(age=12), retry], self.now)
        retry['conclusion'] = 'success'
        result = h.assess([self.run_data(age=48), retry], self.now)
        self.assertEqual((result['last_success_run'], result['age_hours']), (2, 1))

    def test_new_queue_does_not_hide_stuck_older_run(self):
        with self.assertRaisesRegex(ValueError, 'more than one hour'):
            h.assess([self.run_data(age=0.1, status='queued', ident=3),
                      self.run_data(age=2, status='in_progress', ident=2),
                      self.run_data(age=12)], self.now)

    def test_future_pending_attempt_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'future'):
            h.assess([self.run_data(age=-1, status='in_progress'), self.run_data()], self.now)

    def test_history_pagination_and_old_pending_runs(self):
        pages = [[self.run_data(age=i, ident=i) for i in range(1, 101)],
                 [self.run_data(age=200, ident=101)]]
        pages[1][0]['updated_at'] = self.run_data(age=1)['updated_at']
        pages[1][0]['conclusion'] = 'failure'
        old_pending = self.run_data(age=1000, status='queued', ident=102)
        def respond(path, query):
            if 'created' in query:
                return {'total_count': 101, 'workflow_runs': pages[query['page'] - 1]}
            rows = [old_pending] if query['status'] == 'queued' else []
            return {'total_count': len(rows), 'workflow_runs': rows}
        with patch.object(h, 'github_json', side_effect=respond) as request:
            runs = h.fetch_runs('owner/repo', 'main', self.now)
        self.assertEqual(len(runs), 102)
        self.assertEqual(request.call_count, 7)
        with self.assertRaises(ValueError):
            h.assess(runs, self.now)

    def test_truncated_history_is_not_healthy(self):
        for response in [{'total_count': 1001, 'workflow_runs': []},
                         {'total_count': 101, 'workflow_runs': []}]:
            with patch.object(h, 'github_json', return_value=response), self.assertRaises(ValueError):
                h.fetch_runs('owner/repo', 'main', self.now)

    def test_pull_request_does_not_refresh_published_update_health(self):
        with self.assertRaises(ValueError):
            h.assess([self.run_data(age=1, event='pull_request'), self.run_data(age=40)], self.now)

    def test_running_workflow_does_not_prove_upstream_maintenance(self):
        spec = {'id': 'proxy', 'max_revision_age_hours': 72}
        commit = {'sha': 'a' * 40, 'commit': {'committer': {'date':
            (self.now - dt.timedelta(hours=80)).isoformat()}}}
        self.assertEqual(h.assess([self.run_data()], self.now)['age_hours'], 12)
        with self.assertRaisesRegex(ValueError, 'activity budget'):
            h.assess_source(spec, {}, commit, self.now)
        commit['commit']['committer']['date'] = (self.now - dt.timedelta(hours=12)).isoformat()
        for repo in [{'archived': True}, {'disabled': True}]:
            with self.assertRaises(ValueError):
                h.assess_source(spec, repo, commit, self.now)
        self.assertEqual(h.assess_source(spec, {}, commit, self.now)['commit_age_hours'], 12)

    def test_upstream_metadata_is_fetched_once_per_repository_and_ref(self):
        specs = [{'id': name, 'repository': 'owner/repo', 'ref': 'release',
                  'max_revision_age_hours': 72} for name in ['china4', 'china6']]
        commit = {'sha': 'a' * 40, 'commit': {'committer': {'date': self.now.isoformat()}}}
        with patch.object(h, 'github_json', side_effect=[{'archived': False}, commit]) as call:
            self.assertEqual(len(h.check_sources(specs, self.now)), 2)
            self.assertEqual(call.call_count, 2)


if __name__ == '__main__':
    unittest.main()
