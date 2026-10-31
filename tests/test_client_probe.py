from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import probe_client_dns as probe


class ResolutionEvidenceTests(unittest.TestCase):
    def test_positive_negative_and_no_answer_are_not_interchangeable(self):
        positive = '->>HEADER<<- status: NOERROR\nexample.com.\t300\tIN\tTXT\t"test"'
        negative = '->>HEADER<<- status: NXDOMAIN\ncom.\t900\tIN\tSOA\ta. b.'
        error = '->>HEADER<<- status: SERVFAIL'
        for mode, stdout, code, passed in [
                ('success', positive, 0, True), ('success', negative, 0, False),
                ('negative', negative, 0, True), ('negative', positive, 0, False),
                ('no-answer', 'timed out', 9, True), ('no-answer', error, 0, False)]:
            reply = subprocess.CompletedProcess([], code, stdout, '')
            with self.subTest(mode=mode, stdout=stdout), \
                    patch.object(probe.subprocess, 'run', return_value=reply) as run:
                self.assertEqual(probe.resolution_probe(mode)['passed'], passed)
                self.assertIn('TXT', run.call_args[0][0])
