from pathlib import Path
import sqlite3
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import verify_client_config as identity
import probe_client_services as services
import probe_client_dns as dns


class ClientIdentityTests(unittest.TestCase):
    def test_selected_profile_is_read_instead_of_assuming_default_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefs = Path(tmp) / 'preferences.plist'
            for name in ['Mixed-Candidate.db', 'Shadowrocket.db']:
                prefs.write_bytes(plistlib.dumps({'group.com.liguangming.CurrentRuleFileName': name}))
                self.assertEqual(identity.selected_database(prefs).name, name)
            for name in ['../wrong.db', '/tmp/wrong.db', 'wrong.conf', None]:
                prefs.write_bytes(plistlib.dumps({'group.com.liguangming.CurrentRuleFileName': name or 0}))
                with self.assertRaises(identity.ClientConfigMismatch):
                    identity.selected_database(prefs)

    def test_read_only_identity_rejects_rule_and_dns_mismatches(self):
        conf = '[General]\ndns-server = system\n[Rule]\nDOMAIN,example.com,PROXY\nFINAL,PROXY\n[Host]\n'
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / 'client.db'
            with sqlite3.connect(database) as conn:
                conn.execute('create table config (docid integer, section text, name text, value text, option text, ext text)')
                conn.executemany('insert into config values (?,?,?,?,?,?)', [
                    (1, 'general', 'dns-server', 'system', None, None),
                    (2, 'rule', 'DOMAIN', 'example.com', 'PROXY', None),
                    (3, 'rule', 'FINAL', '', 'PROXY', None)])
            before = database.read_bytes()
            self.assertTrue(identity.require_active_config(conf, database)['native_rules_and_general_match'])
            for changed in [conf.replace('example.com', 'other.example'),
                            conf.replace('dns-server = system', 'dns-server = https://1.1.1.1/dns-query#proxy')]:
                with self.assertRaises(identity.ClientConfigMismatch):
                    identity.require_active_config(changed, database)
            self.assertEqual(database.read_bytes(), before)

    def test_missing_database_cannot_be_created_or_claimed_as_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / 'absent.db'
            with self.assertRaises(identity.ClientConfigMismatch):
                identity.require_active_config('[Rule]\nFINAL,PROXY', database)
            self.assertFalse(database.exists())

    def test_wrong_client_blocks_live_probes_before_network_requests(self):
        for module in (services, dns):
            with self.subTest(module=module.__name__), patch.object(sys, 'argv', ['probe']), \
                    patch.object(module, 'require_active_config', side_effect=identity.ClientConfigMismatch('wrong profile')), \
                    patch.object(module.subprocess, 'run') as request:
                self.assertEqual(module.main(), 2)
                request.assert_not_called()


if __name__ == '__main__':
    unittest.main()
