import unittest
from unittest import mock

import cvengine_scanner.scope
from client import config, scope
from client.scope import ScopeError


class ClientScopeTests(unittest.TestCase):
    """The scope floor itself is tested with the library (cvengine_scanner/tests/test_scope.py); this is the part that is the client's own."""

    def setUp(self):
        patcher = mock.patch.object(scope, 'own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_old_name_is_the_library_module(self):
        self.assertIs(scope, cvengine_scanner.scope)

    def test_only_this_machines_own_setting_decides_internal(self):
        with mock.patch.object(config, '_local_internal', return_value=False), mock.patch.dict(config._overrides, {'network': 'internal'}):
            self.assertRaises(ScopeError, scope.check_ip, '10.0.0.1')
        with mock.patch.object(config, '_local_internal', return_value=True):
            self.assertTrue(scope.check_ip('10.0.0.1'))


if __name__ == '__main__':
    unittest.main()
