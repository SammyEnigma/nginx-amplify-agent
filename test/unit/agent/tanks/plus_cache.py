# -*- coding: utf-8 -*-
import time
from collections import deque

from hamcrest import *

from amplify.agent.common.context import context
from amplify.agent.tanks.plus_cache import PlusCache
from amplify.agent.managers.nginx import NginxManager
from test.base import (
    BaseTestCase, RealNginxTestCase, nginx_plus_test, nginx_plus_before_release
)

__author__ = "Grant Hulegaard"
__copyright__ = "Copyright (C) Nginx, Inc. All rights reserved."
__license__ = ""
__maintainer__ = "Grant Hulegaard"
__email__ = "grant.hulegaard@nginx.com"


class PlusCacheTestCase(BaseTestCase):
    def setup_method(self, method):
        super(PlusCacheTestCase, self).setup_method(method)

        context.plus_cache = None
        self.plus_cache = PlusCache()

    def teardown_method(self, method):
        self.plus_cache = None
        context.plus_cache = PlusCache()

        super(PlusCacheTestCase, self).teardown_method(method)

    def test_init(self):
        assert_that(self.plus_cache, is_not(equal_to(None)))

    def test_get(self):
        assert_that(self.plus_cache['new'], equal_to(deque(maxlen=3)))

    def test_put(self):
        self.plus_cache.put('new', 'data')
        assert_that(self.plus_cache['new'], has_length(1))
        assert_that(self.plus_cache['new'], has_item('data'))

    def test_del(self):
        self.plus_cache.put('new', 'data')
        assert_that(self.plus_cache['new'], has_length(1))

        del self.plus_cache['new']
        assert_that(self.plus_cache['new'], equal_to(deque(maxlen=3)))

    def test_limit(self):
        for x in range(10):
            self.plus_cache.put('new', x)

        assert_that(self.plus_cache['new'], has_length(3))
        assert_that(self.plus_cache['new'], equal_to(deque([x for x in range(10)][-3:])))

    def test_get_last_none(self):
        last = self.plus_cache.get_last('new')
        assert_that(last, equal_to((None, None)))

    def test_get_last_empty(self):
        new_deque = self.plus_cache['new']
        assert_that(new_deque, equal_to(deque(maxlen=3)))

        last = self.plus_cache.get_last('new')
        assert_that(last, equal_to((None, None)))

    def test_get_last(self):
        self.plus_cache.put('new', 'data')
        last = self.plus_cache.get_last('new')
        assert_that(last, equal_to('data'))


class PlusCacheCollectTestCase(RealNginxTestCase):
    @nginx_plus_test
    @nginx_plus_before_release(r=16)
    def test_plus_status_cache(self):
        time.sleep(1)  # Give N+ some time to start
        manager = NginxManager()
        manager._discover_objects()
        assert_that(manager.objects.objects_by_type[manager.type], has_length(1))

        # get nginx object
        nginx_obj = manager.objects.objects[manager.objects.objects_by_type[manager.type][0]]

        # get metrics collector - the third in the list
        metrics_collector = nginx_obj.collectors[2]

        # run plus status - twice, because counters will appear only on the second run
        metrics_collector.plus_status()
        time.sleep(1)
        metrics_collector.plus_status()

        assert_that(context.plus_cache['https://127.0.0.1:443/plus_status'], not_(has_length(0)))

    @nginx_plus_test
    def test_plus_api_cache(self):
        time.sleep(1)
        manager = NginxManager()
        manager._discover_objects()
        assert_that(manager.objects.objects_by_type[manager.type], has_length(1))

        # get nginx object
        nginx_obj = manager.objects.objects[manager.objects.objects_by_type[manager.type][0]]

        # get metrics collector - the third in the list
        metrics_collector = nginx_obj.collectors[2]

        # run plus api - twice, because counters will appear only on the second run
        metrics_collector.plus_api()
        time.sleep(1)
        metrics_collector.plus_api()

        assert_that(context.plus_cache['https://127.0.0.1:443/api'], not_(has_length(0)))

    @nginx_plus_test
    @nginx_plus_before_release(r=16)
    def test_plus_status_cache_limit(self):
        time.sleep(1)  # Give N+ some time to start
        manager = NginxManager()
        manager._discover_objects()
        assert_that(manager.objects.objects_by_type[manager.type], has_length(1))

        # get nginx object
        nginx_obj = manager.objects.objects[manager.objects.objects_by_type[manager.type][0]]

        # get metrics collector - the third in the list
        metrics_collector = nginx_obj.collectors[2]

        # run plus status - 4 times
        for x in range(4):
            metrics_collector.plus_status()
            time.sleep(1)

        assert_that(context.plus_cache['https://127.0.0.1:443/plus_status'], has_length(3))
