from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import payment_return_bridge as bridge


class ReturnBridgeTests(unittest.TestCase):
    def test_missing_original_tab_preserves_normal_login(self):
        ui = SimpleNamespace(session_state={}, info=Mock(), stop=Mock())
        with patch.object(bridge, 'listen', return_value=SimpleNamespace(unavailable=True)):
            bridge.show_return(ui, 'cs_test_one')
        ui.stop.assert_not_called()
        self.assertEqual(ui.session_state, {})

    def test_return_ack_does_not_authenticate_or_grant_rights(self):
        ui = SimpleNamespace(session_state={'tokens_pdf': 0}, info=Mock(), stop=Mock())
        with patch.object(bridge, 'listen', return_value=SimpleNamespace(resumed=True)):
            bridge.show_return(ui, 'cs_test_one')
        ui.stop.assert_called_once()
        self.assertEqual(ui.session_state, {'tokens_pdf': 0})
