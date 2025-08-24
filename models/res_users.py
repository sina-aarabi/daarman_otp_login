from odoo import fields, models,SUPERUSER_ID
from odoo.exceptions import AccessDenied

from odoo.modules.registry import Registry



class ResUsers(models.Model):
    _inherit = 'res.users'

    mobile = fields.Char(string='Mobile Number', size=20)
    pod_user_id = fields.Integer(string='POD User ID', help='User ID from the POD system', readonly=True)
    
    
    @classmethod
    def _login(cls, db, credential, user_agent_env):
        try:
            return super()._login(db, credential, user_agent_env=user_agent_env)
        except AccessDenied as e:
            if credential['type'] == 'otp':
                    return {
                        'uid': credential['uid'],
                        'auth_method': 'otp',
                        'mfa': 'default',
                    }
            raise e
    
    def _check_credentials(self, credential, env):
        try:
            return super()._check_credentials(credential, env)
        except AccessDenied:
            if not (credential['type'] == 'password' and credential['password']):
                raise
            if credential['type'] == 'otp':
                return {
                    'uid': self.env.user.id,
                    'auth_method': 'otp',
                    'mfa': 'default',
                }
            raise
                
                        