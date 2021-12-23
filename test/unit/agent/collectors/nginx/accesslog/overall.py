# -*- coding: utf-8 -*-
from hamcrest import *

from amplify.agent.collectors.nginx.accesslog import NginxAccessLogsCollector
from test.base import NginxCollectorTestCase

__author__ = "Mike Belov"
__copyright__ = "Copyright (C) Nginx, Inc. All rights reserved."
__license__ = ""
__maintainer__ = "Mike Belov"
__email__ = "dedm@nginx.com"


class LogsOverallTestCase(NginxCollectorTestCase):

    def test_combined(self):
        lines = [
            '178.23.225.78 - - [18/Jun/2015:17:22:25 +0000] "GET /img/docker.png HTTP/1.1" 304 0 ' +
            '"http://ec2-54-78-3-178.eu-west-1.compute.amazonaws.com:4000/" ' +
            '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) ' +
            'Chrome/43.0.2357.124 Safari/537.36"',

            '178.23.225.78 - - [18/Jun/2015:17:22:25 +0000] "GET /api/inventory/objects/ HTTP/1.1" 200 1093 ' +
            '"http://ec2-54-78-3-178.eu-west-1.compute.amazonaws.com:4000/" ' +
            '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) ' +
            'Chrome/43.0.2357.124 Safari/537.36"',

            '127.0.0.1 - - [18/Jun/2015:17:22:33 +0000] "POST /1.0/589fjinijenfirjf/meta/ HTTP/1.1" ' +
            '202 2 "-" "python-requests/2.2.1 CPython/2.7.6 Linux/3.13.0-48-generic"',

            '52.6.158.18 - - [18/Jun/2015:17:22:40 +0000] "GET /#/objects HTTP/1.1" 416 84 ' +
            '"-" "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"'
        ]

        collector = NginxAccessLogsCollector(object=self.fake_object, tail=lines)
        collector.collect()

        # check
        metrics = self.fake_object.statsd.flush()['metrics']
        assert_that(metrics, has_item('counter'))

        # counters
        counter = metrics['counter']
        for key in ('C|nginx.http.method.get', 'C|nginx.http.request.body_bytes_sent', 'C|nginx.http.status.3xx',
                    'C|nginx.http.status.2xx','C|nginx.http.method.post', 'C|nginx.http.v1_1',
                    'C|nginx.http.status.4xx'):
            assert_that(counter, has_key(key))

        # values
        assert_that(counter['C|nginx.http.method.get'][0][1], equal_to(3))
        assert_that(counter['C|nginx.http.status.2xx'][0][1], equal_to(2))
        assert_that(counter['C|nginx.http.v1_1'][0][1], equal_to(4))
        assert_that(counter['C|nginx.http.request.body_bytes_sent'][0][1], equal_to(84 + 2 + 1093 + 0))

        # check zero values
        for counter_name, counter_key in collector.counters.items():
            if counter_key in collector.parser.keys:
                assert_that(counter, has_key('C|%s' % counter_name))
                if counter_name not in (
                    'nginx.http.method.get',
                    'nginx.http.method.post',
                    'nginx.http.status.2xx',
                    'nginx.http.status.3xx',
                    'nginx.http.status.4xx',
                    'nginx.http.v1_1',
                    'nginx.http.request.body_bytes_sent'
                ):
                    assert_that(counter['C|%s' % counter_name][0][1], equal_to(0))
            elif counter_key is not None:
                if counter_key not in collector.parser.request_variables:
                    assert_that(counter, not_(has_key('C|%s' % counter_name)))

    def test_extended(self):
        log_format = '$remote_addr - $remote_user [$time_local] ' + \
                     '"$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" ' + \
                     'rt=$request_time ut="$upstream_response_time" cs=$upstream_cache_status'

        lines = [
            '1.2.3.4 - - [22/Jan/2010:19:34:21 +0300] "GET /foo/ HTTP/1.1" 200 11078 ' +
            '"http://www.rambler.ru/" "Mozilla/5.0 (Windows; U; Windows NT 5.1" rt=0.010 ut="2.001, 0.345" cs=MISS',

            '1.2.3.4 - - [22/Jan/2010:20:34:21 +0300] "GET /foo/ HTTP/1.1" 300 1078 ' +
            '"http://www.rambler.ru/" "Mozilla/5.0 (Windows; U; Windows NT 5.1" rt=0.010 ut="2.002" cs=HIT',

        ]

        collector = NginxAccessLogsCollector(object=self.fake_object, log_format=log_format, tail=lines)
        collector.collect()

        # check
        metrics = self.fake_object.statsd.flush()['metrics']
        assert_that(metrics, has_item('counter'))
        assert_that(metrics, has_item('timer'))

        # counter keys
        counter = metrics['counter']
        for key in ['C|nginx.http.method.get', 'C|nginx.http.v1_1', 'C|nginx.upstream.next.count',
                    'C|nginx.upstream.request.count', 'C|nginx.http.status.3xx', 'C|nginx.cache.miss',
                    'C|nginx.http.status.2xx', 'C|nginx.http.request.body_bytes_sent', 'C|nginx.cache.hit']:
            assert_that(counter, has_key(key))

        # timer keys
        timer = metrics['timer']
        for key in ['G|nginx.upstream.response.time.pctl95', 'C|nginx.upstream.response.time.count',
                    'C|nginx.http.request.time.count', 'G|nginx.http.request.time',
                    'G|nginx.http.request.time.pctl95', 'G|nginx.http.request.time.median',
                    'G|nginx.http.request.time.max', 'G|nginx.upstream.response.time',
                    'G|nginx.upstream.response.time.median', 'G|nginx.upstream.response.time.max']:
            assert_that(timer, has_key(key))

        # values
        assert_that(counter['C|nginx.http.method.get'][0][1], equal_to(2))
        assert_that(counter['C|nginx.upstream.request.count'][0][1], equal_to(2))
        assert_that(counter['C|nginx.upstream.next.count'][0][1], equal_to(1))
        assert_that(timer['G|nginx.upstream.response.time.max'][0][1], equal_to(2.001+0.345))

        # check zero values
        for counter_name, counter_key in collector.counters.items():
            if counter_key in collector.parser.keys:
                assert_that(counter, has_key('C|%s' % counter_name))
                if counter_name not in (
                    'nginx.http.status.2xx',
                    'nginx.http.status.3xx',
                    'nginx.http.method.get',
                    'nginx.upstream.request.count',
                    'nginx.upstream.next.count',
                    'nginx.upstream.response.time.max',
                    'nginx.http.v1_1',
                    'nginx.cache.miss',
                    'nginx.cache.hit',
                    'nginx.http.request.body_bytes_sent'
                ):
                    assert_that(counter['C|%s' % counter_name][0][1], equal_to(0))
            elif counter_key is not None:
                if counter_key not in collector.parser.request_variables:
                    assert_that(counter, not_(has_key('C|%s' % counter_name)))

    def test_extend_duplicates(self):
        """
        Test a log format that defines duplicate variables.
        """
        log_format = '$remote_addr - $remote_addr - $remote_addr - $remote_user [$time_local] ' + \
                     '"$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" ' + \
                     'rt=$request_time ut="$upstream_response_time" cs=$upstream_cache_status'

        lines = [
            '1.2.3.4 - 1.2.3.4 - 1.2.3.4 - - [22/Jan/2010:19:34:21 +0300] "GET /foo/ HTTP/1.1" 200 11078 ' +
            '"http://www.rambler.ru/" "Mozilla/5.0 (Windows; U; Windows NT 5.1" rt=0.010 ut="2.001, 0.345" cs=MISS',

            '1.2.3.4 - 1.2.3.4 - 1.2.3.4 - - [22/Jan/2010:20:34:21 +0300] "GET /foo/ HTTP/1.1" 300 1078 ' +
            '"http://www.rambler.ru/" "Mozilla/5.0 (Windows; U; Windows NT 5.1" rt=0.010 ut="2.002" cs=HIT',

        ]

        collector = NginxAccessLogsCollector(object=self.fake_object, log_format=log_format, tail=lines)
        collector.collect()

        # check
        metrics = self.fake_object.statsd.flush()['metrics']
        assert_that(metrics, has_item('counter'))
        assert_that(metrics, has_item('timer'))

        # counter keys
        counter = metrics['counter']
        for key in ['C|nginx.http.method.get', 'C|nginx.http.v1_1', 'C|nginx.upstream.next.count',
                    'C|nginx.upstream.request.count', 'C|nginx.http.status.3xx', 'C|nginx.cache.miss',
                    'C|nginx.http.status.2xx', 'C|nginx.http.request.body_bytes_sent', 'C|nginx.cache.hit']:
            assert_that(counter, has_key(key))

        # timer keys
        timer = metrics['timer']
        for key in ['G|nginx.upstream.response.time.pctl95', 'C|nginx.upstream.response.time.count',
                    'C|nginx.http.request.time.count', 'G|nginx.http.request.time',
                    'G|nginx.http.request.time.pctl95', 'G|nginx.http.request.time.median',
                    'G|nginx.http.request.time.max', 'G|nginx.upstream.response.time',
                    'G|nginx.upstream.response.time.median', 'G|nginx.upstream.response.time.max']:
            assert_that(timer, has_key(key))

        # values
        assert_that(counter['C|nginx.http.method.get'][0][1], equal_to(2))
        assert_that(counter['C|nginx.upstream.request.count'][0][1], equal_to(2))
        assert_that(counter['C|nginx.upstream.next.count'][0][1], equal_to(1))
        assert_that(timer['G|nginx.upstream.response.time.max'][0][1], equal_to(2.001+0.345))

        # check zero values
        for counter_name, counter_key in collector.counters.items():
            if counter_key in collector.parser.keys:
                assert_that(counter, has_key('C|%s' % counter_name))
                if counter_name not in (
                    'nginx.http.status.2xx',
                    'nginx.http.status.3xx',
                    'nginx.http.method.get',
                    'nginx.upstream.request.count',
                    'nginx.upstream.next.count',
                    'nginx.upstream.response.time.max',
                    'nginx.http.v1_1',
                    'nginx.cache.miss',
                    'nginx.cache.hit',
                    'nginx.http.request.body_bytes_sent'
                ):
                    assert_that(counter['C|%s' % counter_name][0][1], equal_to(0))
            elif counter_key is not None:
                if counter_key not in collector.parser.request_variables:
                    assert_that(counter, not_(has_key('C|%s' % counter_name)))

    def test_extend_duplicates_reported(self):
        """
        Test the specific reported bug format.
        """
        log_format = '$remote_addr - $remote_user [$time_local]  ' + \
                     '"$request" $status $body_bytes_sent ' + \
                     '"$http_referer" "$http_user_agent" ' + \
                     '$request_length $body_bytes_sent'

        lines = [
            '188.165.1.1 - - [17/Nov/2015:22:07:42 +0100]  ' +
            '"GET /2014/09/quicktipp-phpmyadmin-update-script/?pk_campaign=feed&pk_kwd=quicktipp-' +
            'phpmyadmin-update-script HTTP/1.1" ' +
            '200 41110 "http://www.google.co.uk/url?sa=t&source=web&cd=1" "Mozilla/5.0 (Windows NT 6.1; WOW64) ' +
            'AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.92 Safari/535.2" 327 41110',

            '192.168.100.200 - - [17/Nov/2015:22:09:26 +0100]  "POST /wp-cron.php?doing_wp_cron=1447794566.' +
            '5160338878631591796875 HTTP/1.0" 200 0 "-" "WordPress/4.3.1; http://my.domain.at.private.com" 281 0'
        ]

        collector = NginxAccessLogsCollector(object=self.fake_object, log_format=log_format, tail=lines)
        collector.collect()

        # check
        metrics = self.fake_object.statsd.flush()['metrics']
        assert_that(metrics, has_item('counter'))

        # counter keys
        counter = metrics['counter']
        for key in ['C|nginx.http.method.post', 'C|nginx.http.method.get', 'C|nginx.http.status.2xx',
                    'C|nginx.http.v1_1', 'C|nginx.http.request.body_bytes_sent',
                    'C|nginx.http.v1_0']:
            assert_that(counter, has_key(key))

        # average keys
        averages = metrics['average']
        assert_that(averages, has_key('G|nginx.http.request.length'))

        # values
        assert_that(counter['C|nginx.http.method.post'][0][1], equal_to(1))
        assert_that(counter['C|nginx.http.method.get'][0][1], equal_to(1))
        assert_that(counter['C|nginx.http.status.2xx'][0][1], equal_to(2))
        assert_that(counter['C|nginx.http.request.body_bytes_sent'][0][1], equal_to(41110))
        assert_that(averages['G|nginx.http.request.length'][0][1], equal_to((327+281)/2))

        # check zero values
        for counter_name, counter_key in collector.counters.items():
            if counter_key in collector.parser.keys:
                assert_that(counter, has_key('C|%s' % counter_name))
                if counter_name not in (
                    'nginx.http.status.2xx',
                    'nginx.http.method.post',
                    'nginx.http.method.get',
                    'nginx.http.request.length',
                    'nginx.http.request.body_bytes_sent',
                    'nginx.http.v1_1',
                    'nginx.http.v1_0'
                ):
                    assert_that(counter['C|%s' % counter_name][0][1], equal_to(0))
            elif counter_key is not None:
                if counter_key not in collector.parser.request_variables:
                    assert_that(counter, not_(has_key('C|%s' % counter_name)))

    def test_variables_with_numbers(self):
        """
        Account for nginx variables with numbers in them
        """
        log_format = '$remote_addr [$time_local] $status $geoip_country_code ' + \
                     '$geoip_country_code3 "$geoip_country_name"'

        lines = [
            '10.10.10.102 [29/Jun/2016:23:31:07 +0000] 200 US USA "United States"',
            '10.10.10.46 [29/Jun/2016:23:34:33 +0000] 200 CA CAN "Canada"',
            '10.10.10.189 [29/Jun/2016:23:34:42 +0000] 200 IE IRL "Ireland"',
            '10.10.10.194 [29/Jun/2016:23:35:02 +0000] 200 NL NLD "Netherlands"',
            '10.10.10.198 [29/Jun/2016:23:37:08 +0000] 200 FR FRA "France"',
            '10.10.10.232 [29/Jun/2016:23:37:49 +0000] 200 SG SGP "Singapore"',
            '10.10.10.100 [29/Jun/2016:23:38:19 +0000] 200 ID IDN "Indonesia"'
        ]

        collector = NginxAccessLogsCollector(object=self.fake_object, log_format=log_format, tail=lines)
        collector.collect()

        # Make sure that variable name with number is properly formatted...
        keys = collector.parser.keys
        assert_that(keys, has_item('geoip_country_code'))
        assert_that(keys, has_item('geoip_country_code3'))

        # check
        metrics = self.fake_object.statsd.flush()['metrics']
        assert_that(metrics, has_item('counter'))

        # check some values
        counter = metrics['counter']
        assert_that(counter['C|nginx.http.status.2xx'][0][1], equal_to(7))

    def test_cache_states(self):
        log_format = '$remote_addr - $remote_user [$time_local] ' + \
                     '"$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" ' + \
                     'rt=$request_time ut="$upstream_response_time" cs=$upstream_cache_status'

        lines = [
            '1.2.3.4 - - [22/Jan/2010:19:34:21 +0300] "GET /foo/ HTTP/1.1" 200 11078 ' +
            '"http://www.yandex.ru/" "Mozilla/5.0 (Windows; U; Windows NT 5.1" rt=0.010 ut="2.001, 0.345" cs=MISS',

            '1.2.3.4 - - [22/Jan/2010:20:34:21 +0300] "GET /foo/ HTTP/1.1" 300 1078 ' +
            '"http://www.rambler.ru/" "Mozilla/5.0 (Windows; U; Windows NT 5.1" rt=0.010 ut="2.002" cs=HIT',

            '1.2.3.4 - - [22/Jan/2010:20:34:21 +0300] "GET /foo/ HTTP/1.1" 400 1078 ' +
            '"http://www.mail.ru/" "Mozilla/5.0 (Windows; U; Windows NT 5.1" rt=0.010 ut="2.002" cs=BLAHBLAHFOO',

        ]

        collector = NginxAccessLogsCollector(object=self.fake_object, log_format=log_format, tail=lines)
        collector.collect()

        # check
        metrics = self.fake_object.statsd.flush()['metrics']
        assert_that(metrics, has_item('counter'))
        assert_that(metrics, has_item('timer'))

        # counter keys
        counter = metrics['counter']
        for key in ['C|nginx.http.method.get', 'C|nginx.http.v1_1', 'C|nginx.upstream.next.count',
                    'C|nginx.upstream.request.count', 'C|nginx.http.status.3xx', 'C|nginx.cache.miss',
                    'C|nginx.http.status.2xx', 'C|nginx.http.request.body_bytes_sent', 'C|nginx.cache.hit']:
            assert_that(counter, has_key(key))

        # timer keys
        timer = metrics['timer']
        for key in ['G|nginx.upstream.response.time.pctl95', 'C|nginx.upstream.response.time.count',
                    'C|nginx.http.request.time.count', 'G|nginx.http.request.time',
                    'G|nginx.http.request.time.pctl95', 'G|nginx.http.request.time.median',
                    'G|nginx.http.request.time.max', 'G|nginx.upstream.response.time',
                    'G|nginx.upstream.response.time.median', 'G|nginx.upstream.response.time.max']:
            assert_that(timer, has_key(key))

        # values
        assert_that(counter['C|nginx.http.method.get'][0][1], equal_to(3))
        assert_that(counter['C|nginx.upstream.request.count'][0][1], equal_to(3))
        assert_that(counter['C|nginx.cache.miss'][0][1], equal_to(1))
        assert_that(counter['C|nginx.cache.hit'][0][1], equal_to(1))

    def test_separate_metrics_for_4xx_5xx(self):
        lines = [
            '178.23.225.78 - - [18/Jun/2015:17:22:25 +0000] "GET /img/docker.png HTTP/1.1" 400 0 ' +
            '"http://ec2-54-78-3-178.eu-west-1.compute.amazonaws.com:4000/" ' +
            '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) ' +
            'Chrome/43.0.2357.124 Safari/537.36"',

            '178.23.225.78 - - [18/Jun/2015:17:22:25 +0000] "GET /api/inventory/objects/ HTTP/1.1" 403 1093 ' +
            '"http://ec2-54-78-3-178.eu-west-1.compute.amazonaws.com:4000/" ' +
            '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) ' +
            'Chrome/43.0.2357.124 Safari/537.36"',

            '127.0.0.1 - - [18/Jun/2015:17:22:33 +0000] "POST /1.0/589fjinijenfirjf/meta/ HTTP/1.1" ' +
            '202 2 "-" "python-requests/2.2.1 CPython/2.7.6 Linux/3.13.0-48-generic"',

            '52.6.158.18 - - [18/Jun/2015:17:24:40 +0000] "GET /#/objects HTTP/1.1" 502 84 ' +
            '"-" "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"',

            '52.6.158.18 - - [18/Jun/2015:17:22:40 +0000] "GET /#/objects HTTP/1.1" 503 84 ' +
            '"-" "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"'
        ]

        collector = NginxAccessLogsCollector(object=self.fake_object, tail=lines)
        collector.collect()

        # check
        metrics = self.fake_object.statsd.flush()['metrics']
        assert_that(metrics, has_item('counter'))

        # counters
        counter = metrics['counter']
        for key in ('C|nginx.http.method.get', 'C|nginx.http.request.body_bytes_sent', 'C|nginx.http.status.3xx',
                    'C|nginx.http.status.2xx','C|nginx.http.method.post', 'C|nginx.http.v1_1',
                    'C|nginx.http.status.4xx', 'C|nginx.http.status.5xx', 'C|nginx.http.status.403',
                    'C|nginx.http.status.502', 'C|nginx.http.status.503'):
            assert_that(counter, has_key(key))

        # values
        assert_that(counter['C|nginx.http.status.4xx'][0][1], equal_to(2))
        assert_that(counter['C|nginx.http.status.5xx'][0][1], equal_to(2))
        assert_that(counter['C|nginx.http.status.403'][0][1], equal_to(1))
        assert_that(counter['C|nginx.http.status.502'][0][1], equal_to(1))
        assert_that(counter['C|nginx.http.status.503'][0][1], equal_to(1))

        # check zero values for new metrics
        for counter_name, counter_key in collector.counters.items():
            if counter_key in collector.parser.keys:
                assert_that(counter, has_key('C|%s' % counter_name))
                if counter_name not in (
                    'nginx.http.method.get',
                    'nginx.http.method.post',
                    'nginx.http.status.2xx',
                    'nginx.http.status.3xx',
                    'nginx.http.status.4xx',
                    'nginx.http.status.5xx',
                    'nginx.http.status.403',
                    'nginx.http.status.502',
                    'nginx.http.status.503',
                    'nginx.http.v1_1',
                    'nginx.http.request.body_bytes_sent'
                ):
                    assert_that(counter['C|%s' % counter_name][0][1], equal_to(0))
            elif counter_key is not None:
                if counter_key not in collector.parser.request_variables:
                    assert_that(counter, not_(has_key('C|%s' % counter_name)))

    def test_upstream_status(self):
        log_format = '$remote_addr - $remote_user [$time_local] ' + \
                     '"$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" ' + \
                     'rt=$request_time us="$upstream_status" ut="$upstream_response_time" cs=$upstream_cache_status'

        lines = [
            '1.2.3.4 - - [22/Jan/2010:19:34:21 +0300] "GET /foo/ HTTP/1.1" 200 11078 ' +
            '"http://www.rambler.ru/" "Mozilla/5.0 (Windows; U; Windows NT 5.1" rt=0.010 us="200" ut="2.001, 0.345" cs=MISS',

            '1.2.3.4 - - [22/Jan/2010:20:34:21 +0300] "GET /foo/ HTTP/1.1" 300 1078 ' +
            '"http://www.rambler.ru/" "Mozilla/5.0 (Windows; U; Windows NT 5.1" rt=0.010 us="500" ut="2.002" cs=HIT',

        ]

        collector = NginxAccessLogsCollector(object=self.fake_object,
                                             log_format=log_format, tail=lines)
        collector.collect()

        # check
        metrics = self.fake_object.statsd.flush()['metrics']
        assert_that(metrics, has_item('counter'))
        assert_that(metrics, has_item('timer'))

        # counter keys
        counter = metrics['counter']
        for key in ['C|nginx.http.method.get',
                    'C|nginx.http.v1_1',
                    'C|nginx.upstream.next.count',
                    'C|nginx.upstream.request.count',
                    'C|nginx.http.status.3xx',
                    'C|nginx.cache.miss',
                    'C|nginx.http.status.2xx',
                    'C|nginx.http.request.body_bytes_sent',
                    'C|nginx.cache.hit',
                    'C|nginx.upstream.status.2xx',
                    'C|nginx.upstream.status.5xx']:
            assert_that(counter, has_key(key))

        # timer keys
        timer = metrics['timer']
        for key in ['G|nginx.upstream.response.time.pctl95',
                    'C|nginx.upstream.response.time.count',
                    'C|nginx.http.request.time.count',
                    'G|nginx.http.request.time',
                    'G|nginx.http.request.time.pctl95',
                    'G|nginx.http.request.time.median',
                    'G|nginx.http.request.time.max',
                    'G|nginx.upstream.response.time',
                    'G|nginx.upstream.response.time.median',
                    'G|nginx.upstream.response.time.max']:
            assert_that(timer, has_key(key))

        # values
        assert_that(counter['C|nginx.http.method.get'][0][1], equal_to(2))
        assert_that(counter['C|nginx.upstream.request.count'][0][1],
                    equal_to(2))
        assert_that(counter['C|nginx.upstream.status.2xx'][0][1],
                    equal_to(1))
        assert_that(counter['C|nginx.upstream.status.5xx'][0][1],
                    equal_to(1))
        assert_that(counter['C|nginx.upstream.next.count'][0][1], equal_to(1))
        assert_that(timer['G|nginx.upstream.response.time.max'][0][1],
                    equal_to(2.001 + 0.345))

        # check zero values
        for counter_name, counter_key in collector.counters.items():
            if counter_key in collector.parser.keys:
                assert_that(counter, has_key('C|%s' % counter_name))
                if counter_name not in (
                        'nginx.http.status.2xx',
                        'nginx.http.status.3xx',
                        'nginx.http.method.get',
                        'nginx.upstream.request.count',
                        'nginx.upstream.next.count',
                        'nginx.upstream.response.time.max',
                        'nginx.http.v1_1',
                        'nginx.cache.miss',
                        'nginx.cache.hit',
                        'nginx.http.request.body_bytes_sent',
                        'nginx.upstream.status.2xx',
                        'nginx.upstream.status.5xx'
                ):
                    assert_that(counter['C|%s' % counter_name][0][1],
                                equal_to(0))
            elif counter_key is not None:
                if counter_key not in collector.parser.request_variables:
                    assert_that(counter, not_(has_key('C|%s' % counter_name)))

    def test_upstream_status_multi_value(self):
        log_format = '$remote_addr - $remote_user [$time_local] ' + \
                     '"$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" ' + \
                     'rt=$request_time us="$upstream_status" ut="$upstream_response_time" cs=$upstream_cache_status'

        lines = [
            '1.2.3.4 - - [22/Jan/2010:19:34:21 +0300] "GET /foo/ HTTP/1.1" 200 11078 ' +
            '"http://www.rambler.ru/" "Mozilla/5.0 (Windows; U; Windows NT 5.1" rt=0.010 us="200" ut="2.001, 0.345" cs=MISS',

            '1.2.3.4 - - [22/Jan/2010:20:34:21 +0300] "GET /foo/ HTTP/1.1" 300 1078 ' +
            '"http://www.rambler.ru/" "Mozilla/5.0 (Windows; U; Windows NT 5.1" rt=0.010 us="502, 504" ut="2.002" cs=HIT',

        ]

        collector = NginxAccessLogsCollector(object=self.fake_object,
                                             log_format=log_format, tail=lines)
        collector.collect()

        # check
        metrics = self.fake_object.statsd.flush()['metrics']
        assert_that(metrics, has_item('counter'))
        assert_that(metrics, has_item('timer'))

        # counter keys
        counter = metrics['counter']
        for key in ['C|nginx.http.method.get',
                    'C|nginx.http.v1_1',
                    'C|nginx.upstream.next.count',
                    'C|nginx.upstream.request.count',
                    'C|nginx.http.status.3xx',
                    'C|nginx.cache.miss',
                    'C|nginx.http.status.2xx',
                    'C|nginx.http.request.body_bytes_sent',
                    'C|nginx.cache.hit',
                    'C|nginx.upstream.status.2xx',
                    'C|nginx.upstream.status.5xx']:
            assert_that(counter, has_key(key))

        # timer keys
        timer = metrics['timer']
        for key in ['G|nginx.upstream.response.time.pctl95',
                    'C|nginx.upstream.response.time.count',
                    'C|nginx.http.request.time.count',
                    'G|nginx.http.request.time',
                    'G|nginx.http.request.time.pctl95',
                    'G|nginx.http.request.time.median',
                    'G|nginx.http.request.time.max',
                    'G|nginx.upstream.response.time',
                    'G|nginx.upstream.response.time.median',
                    'G|nginx.upstream.response.time.max']:
            assert_that(timer, has_key(key))

        # values
        assert_that(counter['C|nginx.http.method.get'][0][1], equal_to(2))
        assert_that(counter['C|nginx.upstream.request.count'][0][1],
                    equal_to(2))
        assert_that(counter['C|nginx.upstream.status.2xx'][0][1],
                    equal_to(1))
        assert_that(counter['C|nginx.upstream.status.5xx'][0][1],
                    equal_to(2))
        assert_that(counter['C|nginx.upstream.next.count'][0][1], equal_to(1))
        assert_that(timer['G|nginx.upstream.response.time.max'][0][1],
                    equal_to(2.001 + 0.345))

        # check zero values
        for counter_name, counter_key in collector.counters.items():
            if counter_key in collector.parser.keys:
                assert_that(counter, has_key('C|%s' % counter_name))
                if counter_name not in (
                        'nginx.http.status.2xx',
                        'nginx.http.status.3xx',
                        'nginx.http.method.get',
                        'nginx.upstream.request.count',
                        'nginx.upstream.next.count',
                        'nginx.upstream.response.time.max',
                        'nginx.http.v1_1',
                        'nginx.cache.miss',
                        'nginx.cache.hit',
                        'nginx.http.request.body_bytes_sent',
                        'nginx.upstream.status.2xx',
                        'nginx.upstream.status.5xx'
                ):
                    assert_that(counter['C|%s' % counter_name][0][1],
                                equal_to(0))
            elif counter_key is not None:
                if counter_key not in collector.parser.request_variables:
                    assert_that(counter, not_(has_key('C|%s' % counter_name)))

    # Note: This test case is same as the above, except the log_format & log generated are in multi line
    def test_collector_multi_line_log_format(self):
        log_format = '''$remote_addr - $remote_user [$time_local]
                     "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
                     rt=$request_time us="$upstream_status" ut="$upstream_response_time" cs=$upstream_cache_status'''

        lines = [
            '1.2.3.4 - - [22/Jan/2010:19:34:21 +0300]',
            '                     "GET /foo/ HTTP/1.1" 200 11078 "http://www.rambler.ru/" "Mozilla/5.0 (Windows; U; Windows NT 5.1"',
            '                     rt=0.010 us="200" ut="2.001, 0.345" cs=MISS',
            '1.2.3.4 - - [22/Jan/2010:20:34:21 +0300]',
            '                     "GET /foo/ HTTP/1.1" 300 1078 "http://www.rambler.ru/" "Mozilla/5.0 (Windows; U; Windows NT 5.1"',
            '                     rt=0.010 us="502, 504" ut="2.002" cs=HIT'
        ]

        collector = NginxAccessLogsCollector(object=self.fake_object,
                                             log_format=log_format, tail=lines)
        collector.collect()

        # check
        metrics = self.fake_object.statsd.flush()['metrics']
        assert_that(metrics, has_item('counter'))
        assert_that(metrics, has_item('timer'))

        # counter keys
        counter = metrics['counter']
        for key in ['C|nginx.http.method.get',
                    'C|nginx.http.v1_1',
                    'C|nginx.upstream.next.count',
                    'C|nginx.upstream.request.count',
                    'C|nginx.http.status.3xx',
                    'C|nginx.cache.miss',
                    'C|nginx.http.status.2xx',
                    'C|nginx.http.request.body_bytes_sent',
                    'C|nginx.cache.hit',
                    'C|nginx.upstream.status.2xx',
                    'C|nginx.upstream.status.5xx']:
            assert_that(counter, has_key(key))

        # timer keys
        timer = metrics['timer']
        for key in ['G|nginx.upstream.response.time.pctl95',
                    'C|nginx.upstream.response.time.count',
                    'C|nginx.http.request.time.count',
                    'G|nginx.http.request.time',
                    'G|nginx.http.request.time.pctl95',
                    'G|nginx.http.request.time.median',
                    'G|nginx.http.request.time.max',
                    'G|nginx.upstream.response.time',
                    'G|nginx.upstream.response.time.median',
                    'G|nginx.upstream.response.time.max']:
            assert_that(timer, has_key(key))

        # values
        assert_that(counter['C|nginx.http.method.get'][0][1], equal_to(2))
        assert_that(counter['C|nginx.upstream.request.count'][0][1],
                    equal_to(2))
        assert_that(counter['C|nginx.upstream.status.2xx'][0][1],
                    equal_to(1))
        assert_that(counter['C|nginx.upstream.status.5xx'][0][1],
                    equal_to(2))
        assert_that(counter['C|nginx.upstream.next.count'][0][1], equal_to(1))
        assert_that(timer['G|nginx.upstream.response.time.max'][0][1],
                    equal_to(2.001 + 0.345))

        # check zero values
        for counter_name, counter_key in collector.counters.items():
            if counter_key in collector.parser.keys:
                assert_that(counter, has_key('C|%s' % counter_name))
                if counter_name not in (
                        'nginx.http.status.2xx',
                        'nginx.http.status.3xx',
                        'nginx.http.method.get',
                        'nginx.upstream.request.count',
                        'nginx.upstream.next.count',
                        'nginx.upstream.response.time.max',
                        'nginx.http.v1_1',
                        'nginx.cache.miss',
                        'nginx.cache.hit',
                        'nginx.http.request.body_bytes_sent',
                        'nginx.upstream.status.2xx',
                        'nginx.upstream.status.5xx'
                ):
                    assert_that(counter['C|%s' % counter_name][0][1],
                                equal_to(0))
            elif counter_key is not None:
                if counter_key not in collector.parser.request_variables:
                    assert_that(counter, not_(has_key('C|%s' % counter_name)))

    def test_empty_time_variable(self):
        log_format = (
            '{'
            '"remote_addr":"$remote_addr",'
            '"remote_user":"$remote_user",'
            '"time_local":"$time_local",'
            '"request_method":"$request_method",'
            '"request_uri":"$request_uri",'
            '"status":"$status",'
            '"bytes_sent":$bytes_sent,'
            '"http_referer":"$http_referer",'
            '"http_user_agent":"$http_user_agent",'
            '"http_cookie":"$http_cookie",'
            '"sent_http_cookie":"$sent_http_cookie",'
            '"http_x-forwarded-for":"$http_x_forwarded_for",'
            '"geoip_city":"",'
            '"geoip_region":"",'
            '"geoip_city_country_code":"",'
            '"http_x_reqid":"$http_x_reqid",'
            '"request_id":"$request_id",'
            '"http_cache_control":"$http_cache_control",'
            '"sent_http_cache_control":"$sent_http_cache_control",'
            '"host":"$host",'
            '"sent_http_x_cache_info":"$sent_http_x_cache_info",'
            '"http_accept_language":"$http_accept_language",'
            '"sent_http_lf_error":"$sent_http_lf_error",'
            '"http_device_id":"$http_device_id",'
            '"http_device_type":"$http_device_type",'
            '"upstream_connect_time":"$upstream_connect_time",'
            '"upstream_header_time":"$upstream_header_time",'
            '"upstream_response_time":"$upstream_response_time",'
            '"request_time":"$request_time",'
            '"server_name":"$server_name",'
            '"http_vsapptype":"$http_vsapptype",'
            '"http_vsappversion":"$http_vsappversion",'
            '"http_headers":"$http_headers",'
            '"sent_http_headers":"$sent_http_headers",'
            '"upstream_cache_status":"$upstream_cache_status",'
            '"request_body_masked":"$request_body_masked", '
            '"http_content_type":"$http_content_type"'
            '}'
        )

        lines = [
            (
                '{'
                '"remote_addr":"11.111.11.111",'
                '"remote_user":"",'
                '"time_local":"21/Sep/2018:20:41:39 +0000",'
                '"request_method":"GET",'
                '"request_uri":"/some/request/uri/",'
                '"status":"200",'
                '"bytes_sent":410,'
                '"http_referer":"https://example.com",'
                '"http_user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:62.0) Gecko/20100101 Firefox/62.0",'
                '"http_cookie":"",'
                '"sent_http_cookie":"",'
                '"http_x-forwarded-for":"",'
                '"geoip_city":"",'
                '"geoip_region":"",'
                '"geoip_city_country_code":"",'
                '"http_x_reqid":"",'
                '"request_id":"abcdef0123456789",'
                '"http_cache_control":"",'
                '"sent_http_cache_control":"no-cache",'
                '"host":"example.com",'
                '"sent_http_x_cache_info":"",'
                '"http_accept_language":"en-US,en;q=0.5",'
                '"sent_http_lf_error":"",'
                '"http_device_id":"",'
                '"http_device_type":"",'
                '"upstream_connect_time":"",'
                '"upstream_header_time":"",'
                '"upstream_response_time":"",'
                '"request_time":"0.000",'
                '"server_name":"_",'
                '"http_vsapptype":"",'
                '"http_vsappversion":"",'
                '"http_headers":"",'
                '"sent_http_headers":"",'
                '"upstream_cache_status":"",'
                '"request_body_masked":"", '
                '"http_content_type":""'
                '}'
            )
        ]

        collector = NginxAccessLogsCollector(object=self.fake_object, log_format=log_format, tail=lines)
        collector.collect()

        # check
        metrics = self.fake_object.statsd.flush()['metrics']
        assert_that(metrics, has_item('counter'))
        assert_that(metrics, has_item('timer'))

        counter = metrics['counter']
        timer = metrics['timer']

        assert_that(counter, has_items(
            'C|nginx.cache.bypass',
            'C|nginx.cache.expired',
            'C|nginx.cache.hit',
            'C|nginx.cache.miss',
            'C|nginx.cache.revalidated',
            'C|nginx.cache.stale',
            'C|nginx.cache.updating',
            'C|nginx.http.method.delete',
            'C|nginx.http.method.get',
            'C|nginx.http.method.head',
            'C|nginx.http.method.options',
            'C|nginx.http.method.other',
            'C|nginx.http.method.post',
            'C|nginx.http.method.put',
            'C|nginx.http.request.bytes_sent',
            'C|nginx.http.status.1xx',
            'C|nginx.http.status.2xx',
            'C|nginx.http.status.3xx',
            'C|nginx.http.status.403',
            'C|nginx.http.status.404',
            'C|nginx.http.status.4xx',
            'C|nginx.http.status.500',
            'C|nginx.http.status.502',
            'C|nginx.http.status.503',
            'C|nginx.http.status.504',
            'C|nginx.http.status.5xx',
            'C|nginx.http.status.discarded',
            'C|nginx.upstream.next.count',
            'C|nginx.upstream.request.count'
        ))

        assert_that(timer, has_items(
            'G|nginx.http.request.time',
            'C|nginx.http.request.time.count',
            'G|nginx.http.request.time.max',
            'G|nginx.http.request.time.median',
            'G|nginx.http.request.time.pctl95'
        ))

        # values
        assert_that(counter['C|nginx.http.method.get'][0][1], equal_to(1))
        assert_that(counter['C|nginx.http.status.2xx'][0][1], equal_to(1))
        assert_that(counter['C|nginx.http.request.bytes_sent'][0][1], equal_to(410))
        assert_that(timer['C|nginx.http.request.time.count'][0][1], equal_to(1))

        # check zero values
        for counter_name, counter_key in collector.counters.items():
            if counter_key in collector.parser.keys:
                assert_that(counter, has_key('C|%s' % counter_name))
                if counter_name not in (
                    'nginx.http.method.get',
                    'nginx.http.status.2xx',
                    'nginx.http.request.bytes_sent'
                ):
                    assert_that(counter['C|%s' % counter_name][0][1], equal_to(0))
            elif counter_key is not None:
                if counter_key not in collector.parser.request_variables:
                    assert_that(counter, not_(has_key('C|%s' % counter_name)))
