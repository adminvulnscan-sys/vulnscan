import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from billing import effective_plan

class InternalEnterpriseTests(unittest.TestCase):
    def db(self, grant=None):
        db=Mock()
        db.auth.get_user.return_value=SimpleNamespace(user=SimpleNamespace(email='owner@example.invalid'))
        db.rpc.return_value.execute.return_value.data=grant or {}
        return db

    def test_internal_permission_does_not_change_profile_or_balances(self):
        profile={'email':'owner@example.invalid','plan_activo':'Enterprise','tokens_ent':7}
        before=dict(profile)
        db=self.db({'plan':'Enterprise','source':'internal_test','expires_at':200})
        self.assertEqual(effective_plan(db,profile,now=100),'Enterprise')
        self.assertEqual(profile,before)
        db.rpc.assert_called_once_with('billing_internal_access',{})
        db.table.assert_not_called()

    def test_stored_plan_is_not_internal_authority(self):
        self.assertEqual(effective_plan(self.db(),{'email':'owner@example.invalid','plan_activo':'Enterprise'},100),'Basic')

    def test_permanent_permission_has_no_expiry(self):
        db=self.db({'plan':'Enterprise','source':'internal_test','expires_at':None})
        profile={'email':'owner@example.invalid','tokens_pdf':3,'tokens_ent':5}
        before=dict(profile)
        self.assertEqual(effective_plan(db,profile,10**12),'Enterprise')
        self.assertEqual(profile,before)

    def test_missing_expiry_is_not_a_permanent_grant(self):
        db=self.db({'plan':'Enterprise','source':'internal_test'})
        self.assertEqual(effective_plan(db,{'email':'owner@example.invalid'},100),'Basic')

    def test_revoked_permission_is_not_cached(self):
        db=self.db({'plan':'Enterprise','source':'internal_test','expires_at':None})
        profile={'email':'owner@example.invalid'}
        self.assertEqual(effective_plan(db,profile,100),'Enterprise')
        db.rpc.return_value.execute.return_value.data={}
        self.assertEqual(effective_plan(db,profile,100),'Basic')

    def test_expired_wrong_source_and_wrong_plan_denied(self):
        for grant in [{'plan':'Enterprise','source':'internal_test','expires_at':99},
                      {'plan':'Enterprise','source':'stripe','expires_at':200},
                      {'plan':'Pro','source':'internal_test','expires_at':200}]:
            self.assertEqual(effective_plan(self.db(grant),{'email':'owner@example.invalid'},100),'Basic')

    def test_other_identity_does_not_call_rpc(self):
        db=self.db({'plan':'Enterprise','source':'internal_test','expires_at':200})
        with self.assertLogs('billing',level='WARNING'):
            self.assertEqual(effective_plan(db,{'email':'other@example.invalid'},100),'Basic')
        db.rpc.assert_not_called()

    def test_rpc_failure_keeps_verified_stripe_plan(self):
        db=self.db();db.rpc.side_effect=RuntimeError('SECRET_PAYLOAD')
        profile={'email':'owner@example.invalid','plan_activo':'Pro','billing_status':'active','billing_period_end':200}
        with self.assertLogs('billing',level='WARNING') as logs:
            self.assertEqual(effective_plan(db,profile,100),'Pro')
        self.assertNotIn('SECRET_PAYLOAD',' '.join(logs.output))

if __name__=='__main__':
    unittest.main()
