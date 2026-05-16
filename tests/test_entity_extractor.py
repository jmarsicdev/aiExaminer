"""Tests for src/ai/entity_extractor.py — IOC/entity extraction."""
import unittest

from src.ai.entity_extractor import EntityExtractor, Entity


class TestEntityExtractorExtract(unittest.TestCase):

    def setUp(self):
        self.ex = EntityExtractor()

    def test_returns_list(self):
        self.assertIsInstance(self.ex.extract(''), list)

    def test_email_detected(self):
        hits = self.ex.extract('Contact us at alice@example.org for support.')
        kinds = [e.kind for e in hits]
        self.assertIn('Email', kinds)

    def test_ipv4_detected(self):
        hits = self.ex.extract('Server at 192.168.1.100 responded.')
        kinds = [e.kind for e in hits]
        self.assertIn('IPv4', kinds)

    def test_url_detected(self):
        hits = self.ex.extract('Visit https://malware.example.net/payload.exe')
        kinds = [e.kind for e in hits]
        self.assertIn('URL', kinds)

    def test_domain_detected(self):
        hits = self.ex.extract('Connected to badactor.onion successfully.')
        kinds = [e.kind for e in hits]
        self.assertIn('Domain', kinds)

    def test_ssn_detected(self):
        hits = self.ex.extract('SSN: 123-45-6789 was found in the file.')
        kinds = [e.kind for e in hits]
        self.assertIn('SSN', kinds)

    def test_mac_address_detected(self):
        hits = self.ex.extract('Interface MAC: 00:1A:2B:3C:4D:5E')
        kinds = [e.kind for e in hits]
        self.assertIn('MAC Address', kinds)

    def test_guid_detected(self):
        hits = self.ex.extract('GUID: {550e8400-e29b-41d4-a716-446655440000}')
        kinds = [e.kind for e in hits]
        self.assertIn('GUID / UUID', kinds)

    def test_windows_path_detected(self):
        hits = self.ex.extract(r'File at C:\Users\Alice\Documents\secret.txt')
        kinds = [e.kind for e in hits]
        self.assertIn('Windows Path', kinds)

    def test_registry_key_detected(self):
        hits = self.ex.extract(r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows')
        kinds = [e.kind for e in hits]
        self.assertIn('Registry Key', kinds)

    def test_base64_blob_detected(self):
        # Need >= 40 chars of valid base64
        b64 = 'VGhpcyBpcyBhIHRlc3QgYmFzZTY0IGJsb2IgdGhhdCBpcyBsb25n'
        hits = self.ex.extract(f'Payload: {b64}')
        kinds = [e.kind for e in hits]
        self.assertIn('Base64 Blob', kinds)

    def test_deduplication(self):
        text = 'alice@test.com and alice@test.com again'
        hits = self.ex.extract(text)
        emails = [e for e in hits if e.kind == 'Email']
        self.assertEqual(len(emails), 1)

    def test_noise_domain_skipped(self):
        hits = self.ex.extract('Visit microsoft.com for help.')
        domains = [e for e in hits if e.kind == 'Domain' and 'microsoft' in e.value]
        self.assertEqual(len(domains), 0)

    def test_max_per_kind_respected(self):
        ips = ' '.join(f'10.0.{i}.1' for i in range(600))
        hits = self.ex.extract(ips)
        ipv4_hits = [e for e in hits if e.kind == 'IPv4']
        self.assertLessEqual(len(ipv4_hits), 500)

    def test_entity_has_context(self):
        hits = self.ex.extract('Send mail to user@example.io today.')
        emails = [e for e in hits if e.kind == 'Email']
        if emails:
            self.assertIsInstance(emails[0].context, str)
            self.assertGreater(len(emails[0].context), 0)

    def test_entity_dataclass_fields(self):
        hits = self.ex.extract('IP 10.10.10.10 accessed.')
        for h in hits:
            self.assertIsInstance(h, Entity)
            self.assertIsInstance(h.kind, str)
            self.assertIsInstance(h.value, str)
            self.assertIsInstance(h.context, str)

    def test_empty_text_returns_empty(self):
        self.assertEqual(self.ex.extract(''), [])


class TestEntityExtractorFromBytes(unittest.TestCase):

    def setUp(self):
        self.ex = EntityExtractor()

    def test_ascii_bytes_extracts(self):
        data = b'Contact: admin@corp.io and IP 10.0.0.1'
        hits = self.ex.extract_from_bytes(data)
        kinds = [e.kind for e in hits]
        self.assertIn('Email', kinds)

    def test_utf16_bytes_extracts(self):
        text = 'user@example.net'
        data = text.encode('utf-16-le')
        hits = self.ex.extract_from_bytes(data)
        kinds = [e.kind for e in hits]
        self.assertIn('Email', kinds)

    def test_empty_bytes_returns_empty(self):
        self.assertEqual(self.ex.extract_from_bytes(b''), [])

    def test_deduplication_across_encodings(self):
        email = 'unique@test.org'
        ascii_part = email.encode('ascii')
        latin_part = email.encode('latin-1')
        data = ascii_part + b'\x00' + latin_part
        hits = self.ex.extract_from_bytes(data)
        emails = [e for e in hits if e.kind == 'Email']
        values = [e.value for e in emails]
        self.assertEqual(len(values), len(set(values)))

    def test_truncates_to_max_bytes(self):
        data = b'x@x.io ' * (600 * 1024)
        hits = self.ex.extract_from_bytes(data, max_bytes=1024)
        self.assertIsInstance(hits, list)


class TestEntityExtractorToHtml(unittest.TestCase):

    def setUp(self):
        self.ex = EntityExtractor()

    def test_empty_entities_returns_no_ioc_message(self):
        html = self.ex.to_html([])
        self.assertIn('No IOCs', html)

    def test_html_contains_entity_value(self):
        entities = [Entity(kind='Email', value='test@example.com', context='...')]
        html = self.ex.to_html(entities)
        self.assertIn('test@example.com', html)

    def test_html_escapes_lt_gt(self):
        entities = [Entity(kind='Email', value='<evil>', context='<ctx>')]
        html = self.ex.to_html(entities)
        self.assertNotIn('<evil>', html)
        self.assertIn('&lt;evil&gt;', html)

    def test_html_shows_count(self):
        entities = [Entity(kind='IPv4', value=f'10.0.0.{i}', context='') for i in range(3)]
        html = self.ex.to_html(entities)
        self.assertIn('3', html)

    def test_over_100_shows_more_row(self):
        entities = [Entity(kind='IPv4', value=f'10.0.{i}.1', context='') for i in range(110)]
        html = self.ex.to_html(entities)
        self.assertIn('more', html)


class TestEntityExtractorSummary(unittest.TestCase):

    def setUp(self):
        self.ex = EntityExtractor()

    def test_summary_counts_by_kind(self):
        entities = [
            Entity('Email', 'a@b.com', ''),
            Entity('Email', 'c@d.com', ''),
            Entity('IPv4', '1.2.3.4', ''),
        ]
        s = self.ex.summary(entities)
        self.assertEqual(s['Email'], 2)
        self.assertEqual(s['IPv4'], 1)

    def test_summary_empty_returns_empty_dict(self):
        self.assertEqual(self.ex.summary([]), {})


if __name__ == '__main__':
    unittest.main()
