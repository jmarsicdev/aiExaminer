"""Extended tests for src/ai/anomaly/detector.py — pushing past 80% coverage."""
import unittest

from src.ai.anomaly.detector import (
    LogAnomalyDetector, AnomalyResult,
    _extract_features, _percentile, _render_html, _render_text,
)


_NORMAL_LOG = '\n'.join([
    '2024-01-01 10:00:00 INFO User alice logged in from 192.168.1.10',
    '2024-01-01 10:01:00 INFO Request GET /api/data 200 1234',
    '2024-01-01 10:02:00 INFO Request GET /api/health 200 45',
    '2024-01-01 10:03:00 INFO User bob logged in from 192.168.1.11',
    '2024-01-01 10:04:00 INFO Request POST /api/update 200 890',
    '2024-01-01 10:05:00 ERROR Failed login attempt from 10.0.0.99',
    '2024-01-01 10:06:00 INFO Request GET /api/data 200 1234',
    '2024-01-01 10:07:00 WARN Request DELETE /admin/drop 403 0',
])

_HTTP_LOG = '\n'.join([
    '192.168.1.1 - - [01/Jan/2024:10:00:00] "GET /index.html HTTP/1.1" 200 512',
    '10.0.0.5 - - [01/Jan/2024:10:01:00] "POST /login HTTP/1.1" 401 200',
    '10.0.0.5 - - [01/Jan/2024:10:02:00] "POST /login HTTP/1.1" 401 200',
    '10.0.0.5 - - [01/Jan/2024:10:03:00] "POST /login HTTP/1.1" 200 100',
    '192.168.1.2 - - [01/Jan/2024:10:04:00] "GET /api HTTP/1.1" 500 0',
    '192.168.1.3 - - [01/Jan/2024:10:05:00] "GET /static/js HTTP/1.1" 200 1024',
])


class TestLogAnomalyDetectorBasic(unittest.TestCase):

    def test_analyze_logs_returns_string(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs(_NORMAL_LOG)
        self.assertIsInstance(result, str)

    def test_analyze_logs_empty_returns_message(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs('')
        self.assertIn('No log content', result)

    def test_analyze_logs_whitespace_only(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs('   \n   ')
        self.assertIn('No log content', result)

    def test_analyze_logs_result_contains_lines_analyzed(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs(_NORMAL_LOG)
        self.assertIn('Lines analyzed', result)

    def test_analyze_logs_result_contains_anomalies(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs(_NORMAL_LOG)
        self.assertIn('Anomalies', result)

    def test_analyze_logs_result_contains_error_keywords(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs(_NORMAL_LOG)
        self.assertIn('Error keywords', result)


class TestLogAnomalyDetectorHtml(unittest.TestCase):

    def test_analyze_logs_html_returns_string(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs_html(_NORMAL_LOG)
        self.assertIsInstance(result, str)

    def test_analyze_logs_html_empty_returns_html_message(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs_html('')
        self.assertIn('No log content', result)

    def test_analyze_logs_html_contains_div(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs_html(_NORMAL_LOG)
        self.assertIn('<div', result)

    def test_analyze_logs_html_shows_line_count(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs_html(_NORMAL_LOG)
        self.assertIn(str(len([l for l in _NORMAL_LOG.splitlines() if l.strip()])), result)


class TestLogAnomalyDetectorFewLines(unittest.TestCase):

    def test_two_lines_too_few_note(self):
        det = LogAnomalyDetector()
        short_log = 'line one\nline two'
        result = det.analyze_logs(short_log)
        self.assertIsInstance(result, str)

    def test_one_line_too_few_note(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs('just one log line here')
        self.assertIsInstance(result, str)


class TestLogAnomalyDetectorHttpStatusCodes(unittest.TestCase):

    def test_http_status_codes_detected(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs(_HTTP_LOG)
        self.assertIn('200', result)

    def test_http_status_section_in_text(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs(_HTTP_LOG)
        self.assertIn('HTTP STATUS', result)

    def test_http_status_in_html(self):
        det = LogAnomalyDetector()
        result = det.analyze_logs_html(_HTTP_LOG)
        self.assertIn('HTTP Status', result)


class TestRenderText(unittest.TestCase):

    def test_render_text_with_anomaly_lines(self):
        r = AnomalyResult(
            total_lines=20,
            anomaly_lines=['this is a very suspicious line with unusual pattern'] * 15,
            error_lines=['error: something failed'],
            stats={'total': 20, 'anomalies': 15, 'errors': 1, 'http_status': {'200': 10, '500': 2}},
        )
        text = _render_text(r)
        self.assertIn('TOP ANOMALOUS LINES', text)
        self.assertIn('more', text)  # > 10 anomalies triggers "and N more"
        self.assertIn('HTTP STATUS', text)
        self.assertIn('200', text)

    def test_render_text_no_anomalies(self):
        r = AnomalyResult(
            total_lines=5,
            anomaly_lines=[],
            error_lines=[],
            stats={'total': 5, 'anomalies': 0, 'errors': 0, 'http_status': {}},
        )
        text = _render_text(r)
        self.assertIn('Lines analyzed: 5', text)
        self.assertNotIn('TOP ANOMALOUS', text)


class TestRenderHtml(unittest.TestCase):

    def test_render_html_returns_string(self):
        r = AnomalyResult(
            total_lines=10,
            anomaly_lines=['suspicious line'],
            error_lines=['error: failure'],
            stats={'total': 10, 'anomalies': 1, 'errors': 1, 'http_status': {'404': 3}},
        )
        html = _render_html(r)
        self.assertIsInstance(html, str)

    def test_render_html_contains_line_count(self):
        r = AnomalyResult(total_lines=42, anomaly_lines=[], error_lines=[],
                          stats={'total': 42, 'anomalies': 0, 'errors': 0, 'http_status': {}})
        html = _render_html(r)
        self.assertIn('42', html)

    def test_render_html_escapes_html_in_log_lines(self):
        r = AnomalyResult(
            total_lines=5,
            anomaly_lines=['<script>alert(1)</script>'],
            error_lines=[],
            stats={'total': 5, 'anomalies': 1, 'errors': 0, 'http_status': {}},
        )
        html = _render_html(r)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)

    def test_render_html_shows_status_codes(self):
        r = AnomalyResult(
            total_lines=10,
            anomaly_lines=[],
            error_lines=[],
            stats={'total': 10, 'anomalies': 0, 'errors': 0, 'http_status': {'200': 8, '404': 2}},
        )
        html = _render_html(r)
        self.assertIn('200', html)
        self.assertIn('404', html)


class TestExtractFeatures(unittest.TestCase):

    def test_returns_list_of_9_floats(self):
        features = _extract_features('normal log line 200 1.2.3.4')
        self.assertEqual(len(features), 9)

    def test_has_ip_flag(self):
        features = _extract_features('IP: 10.0.0.1 accessed the server')
        self.assertEqual(features[5], 1.0)

    def test_no_ip_flag(self):
        features = _extract_features('no ip address here at all')
        self.assertEqual(features[5], 0.0)

    def test_error_word_flag(self):
        features = _extract_features('ERROR: connection refused to server')
        self.assertEqual(features[6], 1.0)

    def test_no_error_word(self):
        features = _extract_features('normal successful operation completed')
        self.assertEqual(features[6], 0.0)

    def test_timestamp_flag(self):
        features = _extract_features('2024-01-01T10:00:00 event occurred')
        self.assertEqual(features[7], 1.0)

    def test_length_correct(self):
        line = 'hello world'
        features = _extract_features(line)
        self.assertEqual(features[0], len(line))


class TestPercentile(unittest.TestCase):

    def test_median(self):
        data = [1, 2, 3, 4, 5]
        self.assertAlmostEqual(_percentile(data, 50), 3.0)

    def test_q1(self):
        data = [1, 2, 3, 4, 5]
        self.assertAlmostEqual(_percentile(data, 25), 2.0)

    def test_q3(self):
        data = [1, 2, 3, 4, 5]
        self.assertAlmostEqual(_percentile(data, 75), 4.0)

    def test_single_element(self):
        self.assertAlmostEqual(_percentile([42], 50), 42.0)

    def test_all_same(self):
        self.assertAlmostEqual(_percentile([5, 5, 5, 5], 50), 5.0)


if __name__ == '__main__':
    unittest.main()
