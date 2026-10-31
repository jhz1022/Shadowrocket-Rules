import hashlib
from pathlib import Path
import struct
import sys
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from probe_apple_delivery import verify_xar


class PackageEvidenceTests(unittest.TestCase):
    def sample(self):
        content = b'public fixture payload'
        xml = ('<xar><toc><file><data><offset>20</offset><length>' + str(len(content))
               + '</length><archived-checksum style="sha1">' + hashlib.sha1(content).hexdigest()
               + '</archived-checksum></data></file></toc></xar>').encode()
        packed = zlib.compress(xml)
        checksum = hashlib.sha1(packed).digest()
        return struct.pack('>IHHQQI', 0x78617221, 28, 1, len(packed), len(xml), 1) + packed + checksum + content, checksum.hex()

    def test_catalog_digest_is_toc_digest_and_payloads_are_verified(self):
        blob, checksum = self.sample()
        self.assertNotEqual(hashlib.sha1(blob).hexdigest(), checksum)
        self.assertEqual(verify_xar(blob, checksum), 1)

    def test_corrupt_payload_toc_and_bounds_fail(self):
        blob, checksum = self.sample()
        for data, digest in [(blob[:-1] + b'!', checksum), (blob, '0' * 40), (blob[:28], checksum)]:
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                verify_xar(data, digest)
