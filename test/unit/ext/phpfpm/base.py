# -*- coding: utf-8 -*-
from test.base import BaseTestCase

from amplify.agent.common.util import subp


__author__ = "Grant Hulegaard"
__copyright__ = "Copyright (C) Nginx, Inc. All rights reserved."
__license__ = ""
__maintainer__ = "Grant Hulegaard"
__email__ = "grant.hulegaard@nginx.com"


class PHPFPMTestCase(BaseTestCase):
    """
    Tester helper that starts and stops php-fpm on the test container before running tests.
    """
    def __init__(self, *args, **kwargs):
        super(PHPFPMTestCase, self).__init__(*args, **kwargs)
        self.running = False

    def setup_method(self, method):
        super(PHPFPMTestCase, self).setup_method(method)
        if self.running:
            self.stop_fpm()

        self.start_fpm()

    def teardown_method(self, method):
        if self.running:
            # subp.call('pgrep php-fpm | sudo xargs kill -SIGKILL')
            self.stop_fpm()
        super(PHPFPMTestCase, self).teardown_method(method)

    def start_fpm(self):
        if not self.running:
            subp.call('service php7.4-fpm start')
            self.running = True

    def stop_fpm(self):
        if self.running:
            subp.call('service php7.4-fpm stop')
            self.running = False

    def restart_fpm(self):
        if self.running:
            subp.call('service php7.4-fpm restart')


class PHPFPMSupervisordTestCase(PHPFPMTestCase):

    def __init__(self, *args, **kwargs):
        super(PHPFPMSupervisordTestCase, self).__init__(*args, **kwargs)
        self.running = False

    @classmethod
    def setup_class(cls):
        subp.call('supervisorctl -c /etc/supervisord.conf shutdown', check=False)
        subp.call('supervisord -c /etc/supervisord.conf')

    @classmethod
    def teardown_class(cls):
        subp.call('supervisorctl -c /etc/supervisord.conf shutdown')

    def start_fpm(self):
        if not self.running:
            subp.call('supervisorctl -c /etc/supervisord.conf start php-fpm')
        self.running = True

    def stop_fpm(self):
        if self.running:
            subp.call('supervisorctl -c /etc/supervisord.conf stop php-fpm')
        self.running = False

    def restart_fpm(self):
        if self.running:
            subp.call('supervisorctl -c /etc/supervisord.conf restart php-fpm')
