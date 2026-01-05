"""
Unit Test Generation: insightlog.py

Step 1 — Check for an Existing Test Suite
Detected existing test suite:
Location: tests/test_insightlog.py
Framework: Python unittest (run-compatible with pytest)
Conventions: Class-based tests extending unittest.TestCase, importing functions via from insightlog import *, using sample logs from logs-samples/.

Step 2 — Extend the Existing Test Suite
New Behaviors Added
1. Should match case-insensitive substrings via check_match when is_casesensitive=False.
2. Should match case-insensitive regex via check_match with is_regex=True and is_casesensitive=False.
3. Should support reverse matching for regex filters in filter_data to exclude matching lines.
4. Should raise an error for invalid service names in get_service_settings.
5. Should compute previous year at the year boundary for auth logs in _get_auth_year (Jan 1st 00:00 returns previous year).

Required Mocks
datetime.now must be controlled to test year-boundary logic for _get_auth_year without changing system time.
Mock target: insightlog.datetime
Reason: _get_auth_year references datetime.now() multiple times; behavior depends on current time.
No mock for file I/O is required because sample logs are available in logs-samples/. This keeps tests close to real usage and avoids over-mocking internal logic.
Changes Made
Appended a new test class TestInsightLogAdditional to the existing test file.
Tests follow the same unittest style and conventions as the current suite.

Added Tests (Behaviors Implemented)
Case-insensitive substring matching for check_match, including reverse flag behavior.
Case-insensitive regex matching for check_match, including reverse flag behavior.
Reverse filtering with regex in filter_data to exclude specific IP patterns.
Invalid service handling via get_service_settings.
Year boundary logic for auth logs via _get_auth_year using a controlled datetime.now().

Edited File
File: tests/test_insightlog.py
Framework: unittest (compatible with pytest)
Number of tests added: 5

Diff Summary (Conceptual)
Imported patch from unittest.mock.
Appended a new test class TestInsightLogAdditional with five new tests.

Final Test File Snippet (Appended Section)
"""
from unittest.mock import patch


class TestInsightLogAdditional(TestCase):

    def test_check_match_case_insensitive_substring(self):
        # Should match when case-insensitive substring search is enabled
        line = 'error occurred while processing request'
        self.assertTrue(check_match(line, 'ERROR', is_regex=False, is_casesensitive=False))
        # Reverse should invert the result
        self.assertFalse(check_match(line, 'ERROR', is_regex=False, is_casesensitive=False, is_reverse=True))

    def test_check_match_regex_case_insensitive(self):
        # Should match regex regardless of case when case-insensitive is used
        line = 'Request ID: FOO12345 completed'
        self.assertTrue(bool(check_match(line, r'foo\d+', is_regex=True, is_casesensitive=False)))
        # Reverse should invert the result
        self.assertFalse(bool(check_match(line, r'foo\d+', is_regex=True, is_casesensitive=False, is_reverse=True)))

    def test_filter_data_regex_reverse(self):
        # Using a regex filter and reversing should exclude matching lines
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        nginx_log = os.path.join(base_dir, 'logs-samples/nginx1.sample')
        # Filter for any 192.10.1.X address and then reverse to exclude them
        data = filter_data(r'192\.10\.1\.\d+', filepath=nginx_log, is_regex=True, is_reverse=True)
        self.assertTrue(all('192.10.1.' not in line for line in data.splitlines()))

    def test_get_service_settings_invalid(self):
        # Should raise when service does not exist
        with self.assertRaises(Exception):
            get_service_settings('unknown_service')

    def test_get_auth_year_boundary(self):
        # On Jan 1st at 00:00 local time, _get_auth_year should return previous year
        fake_now = datetime(2024, 1, 1, 0, 0, 0)
        with patch('insightlog.datetime') as mock_datetime:
            mock_datetime.now.return_value = fake_now
            self.assertEqual(_get_auth_year(), 2023)