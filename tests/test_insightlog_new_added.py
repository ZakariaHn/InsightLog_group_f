import os
from unittest import TestCase
from datetime import datetime
from insightlog import *


class TestInsightLog(TestCase):

    def test_get_date_filter(self):
        nginx_settings = get_service_settings('nginx')
        self.assertEqual(get_date_filter(nginx_settings, 13, 13, 16, 1, 1989),
                         '[16/Jan/1989:13:13', "get_date_filter#1")
        self.assertEqual(get_date_filter(nginx_settings, '*', '*', 16, 1, 1989),
                         '[16/Jan/1989', "get_date_filter#2")
        self.assertEqual(get_date_filter(nginx_settings, '*'), datetime.now().strftime("[%d/%b/%Y:%H"),
                         "get_date_filter#3")
        apache2_settings = get_service_settings('apache2')
        self.assertEqual(get_date_filter(apache2_settings, 13, 13, 16, 1, 1989),
                         '[16/Jan/1989:13:13', "get_date_filter#4")
        self.assertEqual(get_date_filter(apache2_settings, '*', '*', 16, 1, 1989),
                         '[16/Jan/1989', "get_date_filter#5")
        self.assertEqual(get_date_filter(apache2_settings, '*'), datetime.now().strftime("[%d/%b/%Y:%H"),
                         "get_date_filter#6")
        auth_settings = get_service_settings('auth')
        self.assertEqual(get_date_filter(auth_settings, 13, 13, 16, 1),
                         'Jan 16 13:13:', "get_date_filter#7")
        self.assertEqual(get_date_filter(auth_settings, '*', '*', 16, 1),
                         'Jan 16 ', "get_date_filter#8")

    def test_filter_data(self):
        nginx_settings = get_service_settings('nginx')
        date_filter = get_date_filter(nginx_settings, '*', '*', 27, 4, 2016)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        file_name = os.path.join(base_dir, 'logs-samples/nginx1.sample')
        data = filter_data('192.168.5', filepath=file_name)
        data = filter_data(date_filter, data=data)
        self.assertEqual(len(data.split("\n")), 28, "filter_data#1")
        self.assertRaises(Exception, filter_data, log_filter='192.168.5')
        apache2_settings = get_service_settings('apache2')
        date_filter = get_date_filter(apache2_settings, 27, 11, 4, 5, 2016)
        file_name = os.path.join(base_dir, 'logs-samples/apache1.sample')
        data = filter_data('127.0.0.1', filepath=file_name)
        data = filter_data(date_filter, data=data)
        self.assertEqual(len(data.split("\n")), 34, "filter_data#2")
        self.assertRaises(Exception, filter_data, log_filter='127.0.0.1')
        auth_settings = get_service_settings('auth')
        date_filter = get_date_filter(auth_settings, '*', 22, 4, 5)
        file_name = os.path.join(base_dir, 'logs-samples/auth.sample')
        data = filter_data('120.25.229.167', filepath=file_name)
        data = filter_data(date_filter, data=data)
        self.assertEqual(len(data.split("\n")), 19, "filter_data#3")
        data = filter_data('120.25.229.167', filepath=file_name, is_reverse=True)
        self.assertFalse('120.25.229.167' in data, "filter_data#4")

    def test_get_web_requests(self):
        nginx_settings = get_service_settings('nginx')
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        file_name = os.path.join(base_dir, 'logs-samples/nginx1.sample')
        data = filter_data('192.10.1.1', filepath=file_name)
        requests = get_web_requests(data, nginx_settings['request_model'])
        self.assertEqual(len(requests), 2, "get_web_requests#1")
        self.assertTrue('daedalu5' in requests[0].values(), "get_web_requests#2")
        requests = get_web_requests(data, nginx_settings['request_model'],
                                    nginx_settings['date_pattern'], nginx_settings['date_keys'])
        self.assertEqual(requests[0]['DATETIME'], '2016-04-24 06:26:37', "get_web_requests#3")
        apache2_settings = get_service_settings('apache2')
        file_name = os.path.join(base_dir, 'logs-samples/apache1.sample')
        data = filter_data('127.0.1.1', filepath=file_name)
        requests = get_web_requests(data, apache2_settings['request_model'])
        self.assertEqual(len(requests), 1, "get_web_requests#4")
        self.assertTrue('daedalu5' in requests[0].values(), "get_web_requests#5")
        requests = get_web_requests(data, apache2_settings['request_model'],
                                    apache2_settings['date_pattern'], apache2_settings['date_keys'])
        self.assertEqual(requests[0]['DATETIME'], '2016-05-04 11:31:39', "get_web_requests#3")

    def test_get_auth_requests(self):
        auth_settings = get_service_settings('auth')
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        date_filter = get_date_filter(auth_settings, '*', 22, 4, 5)
        file_name = os.path.join(base_dir, 'logs-samples/auth.sample')
        data = filter_data('120.25.229.167', filepath=file_name)
        data = filter_data(date_filter, data=data)
        requests = get_auth_requests(data, auth_settings['request_model'])
        self.assertEqual(len(requests), 18, "get_auth_requests#1")
        self.assertEqual(requests[17]['INVALID_PASS_USER'], 'root', "get_auth_requests#2")
        self.assertEqual(requests[15]['INVALID_USER'], 'admin', "get_auth_requests#3")
        requests = get_auth_requests(data, auth_settings['request_model'],
                                     auth_settings['date_pattern'], auth_settings['date_keys'])
        self.assertEqual(requests[0]['DATETIME'][4:], '-05-04 22:00:32', "get_auth_requests#4")

    def test_get_requests(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        auth_logfile = os.path.join(base_dir, 'logs-samples/auth.sample')
        nginx_logfile = os.path.join(base_dir, 'logs-samples/nginx1.sample')
        
        # Test auth logs with filters
        auth_settings = get_service_settings('auth')
        date_filter = get_date_filter(auth_settings, minute='*', hour=22, day=4, month=5)
        auth_filters = [
            {'filter_pattern': '120.25.229.167', 'is_casesensitive': True, 'is_regex': False, 'is_reverse': False},
            {'filter_pattern': date_filter, 'is_casesensitive': True, 'is_regex': False, 'is_reverse': False}
        ]
        requests = get_requests('auth', filepath=auth_logfile, filters=auth_filters)
        self.assertEqual(len(requests), 18, "get_requests#1")
        
        # Test nginx logs with filter
        nginx_filters = [
            {'filter_pattern': '192.10.1.1', 'is_casesensitive': True, 'is_regex': False, 'is_reverse': False}
        ]
        requests = get_requests('nginx', filepath=nginx_logfile, filters=nginx_filters)
        self.assertEqual(len(requests), 2, "get_requests#2")

# TODO: Add more tests for edge cases and error handling


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



##### More Added Test Methods:




    def test_get_service_settings_edge_cases(self):
        """Test get_service_settings with invalid service names"""
        self.assertRaises(Exception, get_service_settings, 'invalid_service')
        self.assertRaises(Exception, get_service_settings, '')
        self.assertRaises(Exception, get_service_settings, None)
        # Valid services should not raise exceptions
        self.assertIsNotNone(get_service_settings('nginx'))
        self.assertIsNotNone(get_service_settings('apache2'))
        self.assertIsNotNone(get_service_settings('auth'))

    def test_get_date_filter_invalid_dates(self):
        """Test get_date_filter with invalid date parameters"""
        nginx_settings = get_service_settings('nginx')
        
        # Invalid year - too low
        self.assertRaises(Exception, get_date_filter, nginx_settings, 0, 0, 1, 1, 1970)
        self.assertRaises(Exception, get_date_filter, nginx_settings, 0, 0, 1, 1, 1969)
        
        # Invalid year - too high
        self.assertRaises(Exception, get_date_filter, nginx_settings, 0, 0, 1, 1, 2031)
        
        # Invalid month - too low
        self.assertRaises(Exception, get_date_filter, nginx_settings, 0, 0, 1, 0, 2000)
        
        # Invalid month - too high
        self.assertRaises(Exception, get_date_filter, nginx_settings, 0, 0, 1, 13, 2000)
        
        # Invalid day - too low
        self.assertRaises(Exception, get_date_filter, nginx_settings, 0, 0, 0, 1, 2000)
        
        # Invalid day - too high
        self.assertRaises(Exception, get_date_filter, nginx_settings, 0, 0, 32, 1, 2000)
        
        # Invalid hour - too high
        self.assertRaises(Exception, get_date_filter, nginx_settings, 0, 24, 1, 1, 2000)
        
        # Invalid hour - negative
        self.assertRaises(Exception, get_date_filter, nginx_settings, 0, -1, 1, 1, 2000)
        
        # Invalid minute - too high
        self.assertRaises(Exception, get_date_filter, nginx_settings, 60, 0, 1, 1, 2000)
        
        # Invalid minute - negative
        self.assertRaises(Exception, get_date_filter, nginx_settings, -1, 0, 1, 1, 2000)
        
        # Invalid combination: minute='*' but hour is not '*'
        self.assertRaises(Exception, get_date_filter, nginx_settings, '*', 10, 1, 1, 2000)

    def test_filter_data_edge_cases(self):
        """Test filter_data with edge cases and error conditions"""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Test with non-existent file
        non_existent_file = os.path.join(base_dir, 'logs-samples/nonexistent.log')
        result = filter_data('test', filepath=non_existent_file)
        self.assertIsNone(result, "filter_data should return None for non-existent file")
        
        # Test with empty data string
        empty_data = filter_data('test', data='')
        self.assertEqual(empty_data, '', "filter_data should return empty string for empty data")
        
        # Test with data that doesn't match filter
        test_data = "line1\nline2\nline3\n"
        filtered = filter_data('nonexistent_pattern', data=test_data)
        self.assertEqual(filtered, '', "filter_data should return empty string when no matches")
        
        # Test regex pattern matching
        test_data = "192.168.1.1 test\n10.0.0.1 test\n"
        regex_pattern = r'\d+\.\d+\.\d+\.\d+'
        filtered = filter_data(regex_pattern, data=test_data, is_regex=True)
        self.assertIn('192.168.1.1', filtered, "filter_data should match regex patterns")
        self.assertIn('10.0.0.1', filtered, "filter_data should match regex patterns")
        
        # Test case sensitivity
        test_data = "Test Line\nTEST LINE\ntest line\n"
        filtered_sensitive = filter_data('Test', data=test_data, is_casesensitive=True)
        self.assertIn('Test Line', filtered_sensitive, "Case sensitive filter should match exact case")
        self.assertNotIn('test line', filtered_sensitive, "Case sensitive filter should not match different case")
        
        filtered_insensitive = filter_data('Test', data=test_data, is_casesensitive=False)
        self.assertIn('Test Line', filtered_insensitive, "Case insensitive filter should match all cases")
        self.assertIn('TEST LINE', filtered_insensitive, "Case insensitive filter should match all cases")
        self.assertIn('test line', filtered_insensitive, "Case insensitive filter should match all cases")

    def test_get_web_requests_edge_cases(self):
        """Test get_web_requests with edge cases"""
        nginx_settings = get_service_settings('nginx')
        
        # Test with empty data
        empty_requests = get_web_requests('', nginx_settings['request_model'])
        self.assertEqual(len(empty_requests), 0, "get_web_requests should return empty list for empty data")
        
        # Test with data that doesn't match pattern
        non_matching_data = "This is not a log line\nAnother non-matching line\n"
        requests = get_web_requests(non_matching_data, nginx_settings['request_model'])
        self.assertEqual(len(requests), 0, "get_web_requests should return empty list when no matches")
        
        # Test with date_pattern but no date_keys
        test_data = "192.168.1.1 - - [24/Apr/2016:06:26:37 +0000] \"GET /test HTTP/1.1\" 200 123 \"-\" \"test\""
        self.assertRaises(Exception, get_web_requests, test_data, 
                          nginx_settings['request_model'], 
                          nginx_settings['date_pattern'], 
                          None)

    def test_get_auth_requests_edge_cases(self):
        """Test get_auth_requests with edge cases"""
        auth_settings = get_service_settings('auth')
        
        # Test with empty data
        empty_requests = get_auth_requests('', auth_settings['request_model'])
        self.assertEqual(len(empty_requests), 0, "get_auth_requests should return empty list for empty data")
        
        # Test with data that doesn't match pattern
        non_matching_data = "This is not an auth log line\nAnother non-matching line\n"
        requests = get_auth_requests(non_matching_data, auth_settings['request_model'])
        self.assertEqual(len(requests), 0, "get_auth_requests should return empty list when no matches")

    def test_analyze_auth_request_edge_cases(self):
        """Test analyze_auth_request with various edge cases"""
        # Test with request containing IP
        request_with_ip = "May  4 22:00:32 server sshd[1234]: Failed password for root from 192.168.1.1"
        result = analyze_auth_request(request_with_ip)
        self.assertEqual(result['IP'], '192.168.1.1', "analyze_auth_request should extract IP")
        self.assertEqual(result['INVALID_PASS_USER'], 'root', "analyze_auth_request should extract invalid password user")
        
        # Test with request without IP
        request_no_ip = "May  4 22:00:32 server sshd[1234]: Invalid user admin"
        result = analyze_auth_request(request_no_ip)
        self.assertIsNone(result['IP'], "analyze_auth_request should return None for missing IP")
        self.assertEqual(result['INVALID_USER'], 'admin', "analyze_auth_request should extract invalid user")
        
        # Test with preauth
        request_preauth = "May  4 22:00:32 server sshd[1234]: Connection from 192.168.1.1 port 12345 [preauth]"
        result = analyze_auth_request(request_preauth)
        self.assertTrue(result['IS_PREAUTH'], "analyze_auth_request should detect preauth")
        
        # Test with connection closed
        request_closed = "May  4 22:00:32 server sshd[1234]: Connection closed by 192.168.1.1"
        result = analyze_auth_request(request_closed)
        self.assertTrue(result['IS_CLOSED'], "analyze_auth_request should detect closed connection")
        
        # Test with empty request
        result = analyze_auth_request('')
        self.assertIsNone(result['IP'], "analyze_auth_request should handle empty request")
        self.assertIsNone(result['INVALID_USER'], "analyze_auth_request should handle empty request")
        self.assertFalse(result['IS_PREAUTH'], "analyze_auth_request should handle empty request")
        self.assertFalse(result['IS_CLOSED'], "analyze_auth_request should handle empty request")

    def test_get_requests_edge_cases(self):
        """Test get_requests with edge cases and error conditions"""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Test with invalid service
        self.assertRaises(Exception, get_requests, 'invalid_service', 
                          filepath=os.path.join(base_dir, 'logs-samples/nginx1.sample'))
        
        # Test with non-existent file
        non_existent_file = os.path.join(base_dir, 'logs-samples/nonexistent.log')
        result = get_requests('nginx', filepath=non_existent_file)
        self.assertIsNone(result, "get_requests should return None for non-existent file")
        
        # Test with empty filters list
        nginx_logfile = os.path.join(base_dir, 'logs-samples/nginx1.sample')
        requests = get_requests('nginx', filepath=nginx_logfile, filters=[])
        self.assertIsInstance(requests, list, "get_requests should return list even with empty filters")
        
        # Test with empty data
        requests = get_requests('nginx', data='')
        self.assertEqual(requests, [], "get_requests should return empty list for empty data")
        
        # Test with filters that match nothing
        filters_no_match = [
            {'filter_pattern': 'NONEXISTENT_PATTERN_XYZ', 'is_casesensitive': True, 
             'is_regex': False, 'is_reverse': False}
        ]
        requests = get_requests('nginx', filepath=nginx_logfile, filters=filters_no_match)
        self.assertEqual(requests, [], "get_requests should return empty list when filters match nothing")

    def test_check_match_edge_cases(self):
        """Test check_match function with various edge cases"""
        test_line = "Test Line with IP 192.168.1.1"
        
        # Test simple string match
        self.assertTrue(check_match(test_line, 'IP', is_regex=False, is_casesensitive=True))
        self.assertFalse(check_match(test_line, 'ip', is_regex=False, is_casesensitive=True))
        self.assertTrue(check_match(test_line, 'ip', is_regex=False, is_casesensitive=False))
        
        # Test regex match
        self.assertTrue(check_match(test_line, r'\d+\.\d+\.\d+\.\d+', is_regex=True))
        self.assertFalse(check_match(test_line, r'^\d+$', is_regex=True))
        
        # Test reverse match
        self.assertFalse(check_match(test_line, 'NONEXISTENT', is_regex=False, is_reverse=True))
        self.assertTrue(check_match(test_line, 'NONEXISTENT', is_regex=False, is_reverse=False))
        
        # Test empty string
        self.assertTrue(check_match('', '', is_regex=False))
        self.assertFalse(check_match('', 'test', is_regex=False))

    def test_apply_filters_edge_cases(self):
        """Test apply_filters function with edge cases"""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        nginx_logfile = os.path.join(base_dir, 'logs-samples/nginx1.sample')
        
        # Test with empty filters
        result = apply_filters([], filepath=nginx_logfile)
        self.assertIsNotNone(result, "apply_filters should return data even with empty filters")
        
        # Test with multiple filters (all must match)
        filters = [
            {'filter_pattern': '192.168', 'is_casesensitive': True, 'is_regex': False, 'is_reverse': False},
            {'filter_pattern': 'GET', 'is_casesensitive': True, 'is_regex': False, 'is_reverse': False}
        ]
        result = apply_filters(filters, filepath=nginx_logfile)
        self.assertIsNotNone(result, "apply_filters should handle multiple filters")
        
        # Test with non-existent file
        non_existent_file = os.path.join(base_dir, 'logs-samples/nonexistent.log')
        result = apply_filters([], filepath=non_existent_file)
        self.assertIsNone(result, "apply_filters should return None for non-existent file")
        
        # Test with empty data
        result = apply_filters([], data='')
        self.assertEqual(result, '', "apply_filters should return empty string for empty data")
        
        # Test with neither data nor filepath
        self.assertRaises(Exception, apply_filters, [], data=None, filepath=None)


class TestInsightLogNewBehaviors(TestCase):

    def test_iso_datetime_invalid_pattern_raises(self):
        # Should raise ValueError when date pattern does not match the input string
        with self.assertRaises(ValueError):
            _get_iso_datetime('not a date', r'(\d{4})/(\d{2})/(\d{2})',
                              {'year': 0, 'month': 1, 'day': 2, 'hour': 3, 'minute': 4, 'second': 5})

    def test_check_match_regex_startswith_behavior(self):
        # Regex matching uses re.match, so it must match at the start of the line
        line = 'prefix GET /route'
        self.assertFalse(check_match(line, r'GET', is_regex=True, is_casesensitive=True))
        self.assertTrue(check_match(line, r'.*GET', is_regex=True, is_casesensitive=True))

    def test_get_web_requests_without_date_pattern_returns_raw_datetime(self):
        # When date_pattern is not provided, the raw datetime string from the log should be returned
        nginx_settings = get_service_settings('nginx')
        sample = '192.168.0.1 - - [24/Apr/2016:06:26:37 +0000] "GET /test HTTP/1.1" 200 123 "-" "ua"'
        reqs = get_web_requests(sample, nginx_settings['request_model'])
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0]['DATETIME'], '24/Apr/2016:06:26:37 +0000')

    def test_apply_filters_combination_reverse_case_insensitive(self):
        # Combine a normal filter with a reversed, case-sensitive filter
        sample = 'foo bar\nbaz BAR\nfoo BAR\n'
        filters = [
            {'filter_pattern': 'foo', 'is_casesensitive': False, 'is_regex': False, 'is_reverse': False},
            {'filter_pattern': 'bar', 'is_casesensitive': True, 'is_regex': False, 'is_reverse': True}
        ]
        result = apply_filters(filters, data=sample)
        self.assertEqual(result.strip().splitlines(), ['foo BAR'])

    def test_get_auth_year_non_boundary(self):
        # For non-boundary dates, _get_auth_year should return the current year
        fake_now = datetime(2024, 5, 4, 10, 0, 0)
        from unittest.mock import patch
        with patch('insightlog.datetime') as mock_datetime:
            mock_datetime.now.return_value = fake_now
            self.assertEqual(_get_auth_year(), 2024)
