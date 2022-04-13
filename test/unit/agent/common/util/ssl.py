# -*- coding: utf-8 -*-
from hamcrest import *

from amplify.agent.common.util import ssl
from test.base import BaseTestCase

__author__ = "Grant Hulegaard"
__copyright__ = "Copyright (C) Nginx, Inc. All rights reserved."
__license__ = ""
__maintainer__ = "Grant Hulegaard"
__email__ = "grant.hulegaard@nginx.com"


class SSLAnalysisTestCase(BaseTestCase):

    def test_issuer_with_apostrophe(self):
        """
        Old regex method test.
        """
        result = {}
        line = "issuer= /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X1"

        for regex in ssl.ssl_regexs:
            match_obj = regex.match(line)
            if match_obj:
                result.update(match_obj.groupdict())

        assert_that(result, has_key('organization'))
        assert_that(result['organization'], equal_to("Let's Encrypt"))
        assert_that(result, has_key('common_name'))
        assert_that(result['common_name'], equal_to("Let's Encrypt Authority X1"))

    def test_structured_parse(self):
        lines = ["subject= CN=another.domain.com,OU=Domain Control Validated"]
        result = ssl.parse_raw_certificate_subject(lines)

        assert_that(result, has_key('common_name'))
        assert_that(result['common_name'], equal_to('another.domain.com'))
        assert_that(result, has_key('unit'))
        assert_that(result['unit'], equal_to('Domain Control Validated'))

    def test_complicated_common_name(self):
        lines = ["Subject: C=RU, ST=SPb, L=SPb, O=Fake Org, OU=D, CN=*.fake.domain.ru/emailAddress=fake@email.cc"]
        result = ssl.parse_raw_certificate_subject(lines)

        assert_that(result, has_length(6))

        assert_that(result, has_key('common_name'))
        assert_that(result['common_name'], equal_to('*.fake.domain.ru/emailAddress=fake@email.cc'))
        assert_that(result, has_key('unit'))
        assert_that(result['unit'], equal_to('D'))
        assert_that(result, has_key('organization'))
        assert_that(result['organization'], equal_to('Fake Org'))

    def test_international_common_name(self):
        results = ssl.certificate_subject("test/fixtures/nginx/ssl/idn/idn_cert.pem")
        assert_that(results['common_name'], equal_to('АБВГҐ.あいうえお'))
        assert_that(results['organization'], equal_to('АҐДЂ我要شث'))
        assert_that(results['state'], equal_to('FakeState'))
        assert_that(results['country'], equal_to('RU'))
        assert_that(results['unit'], equal_to('IT'))

    def test_subject_alternative_name(self):
        results = ssl.certificate_full(
            "test/fixtures/nginx/ssl/san_cert/single-san.crt")
        assert results is not None
        assert results['signature_algorithm'] == 'sha256WithRSAEncryption'
        assert results['public_key_algorithm'] == 'rsaEncryption'
        assert results['length'] == '2048'
        assert type(results['names']) is list
        assert len(results['names']) == 1
        assert results['names'][0] == 'mock.amplify-url.com'

    def test_ssl_analysis(self):
        results = ssl.ssl_analysis(
            "test/fixtures/nginx/ssl/san_cert/single-san.crt")
        assert results is not None
        assert 'dates' in results
        assert results['dates'] == {'start': 1645077096, 'end': 1952661096}
        assert 'subject' in results
        assert results['subject'] == {
            'common_name': 'mock.cn.amplify-url.com',
            'organization': 'MyOrg',
            'location': 'MyCity',
            'state': 'MyState',
            'country': 'ES'}
        assert results['issuer'] is None
        assert 'purpose' in results
        assert results['purpose'] == {
            'SSL client': 'Yes',
            'SSL client CA': 'No',
            'SSL server': 'Yes',
            'SSL server CA': 'No',
            'Netscape SSL server': 'Yes',
            'Netscape SSL server CA': 'No',
            'S/MIME signing': 'Yes',
            'S/MIME signing CA': 'No',
            'S/MIME encryption': 'Yes',
            'S/MIME encryption CA': 'No',
            'CRL signing': 'Yes',
            'CRL signing CA': 'No',
            'Any Purpose': 'Yes',
            'Any Purpose CA': 'Yes',
            'OCSP helper': 'Yes',
            'OCSP helper CA': 'No',
            'Time Stamp signing': 'No',
            'Time Stamp signing CA': 'No'
        }
        assert results['ocsp_uri'] is None
        assert results['signature_algorithm'] == 'sha256WithRSAEncryption'
        assert results['public_key_algorithm'] == 'rsaEncryption'
        assert results['length'] == 2048
        assert type(results['names']) is list
        assert len(results['names']) == 2
        assert results['names'] == [
            'mock.amplify-url.com',
            'mock.cn.amplify-url.com'
        ]
