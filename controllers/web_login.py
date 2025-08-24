import logging
import random
from odoo import http, _
from odoo.http import request
from odoo.addons.web.controllers.home import Home, SIGN_UP_REQUEST_PARAMS
from odoo.exceptions import ValidationError, UserError
from odoo.addons.web.controllers.home import ensure_db
import json

_logger = logging.getLogger(__name__)

# Add OTP-related parameters
CREDENTIAL_PARAMS = ['login', 'password', 'type', 'mobile', 'otp']

class DaarmanLogin(Home):
    @http.route('/web/login', type='http', auth='none', methods=['GET', 'POST'], website=True)
    def web_login(self, redirect=None, **kw):
        if request.httprequest.method == 'GET':
            return super().web_login(redirect=redirect, **kw)

        ensure_db()
        request.params['login_success'] = False
        values = {k: v for k, v in request.params.items() if k in SIGN_UP_REQUEST_PARAMS}
        
        # Get action from form submission
        action = request.params.get('submitted_action')
        login_type = request.params.get('login_type', 'password')
        
        if request.httprequest.method == 'POST':
            if login_type == 'otp':
                values['action'] = action
                return self._handle_otp_login(values, redirect)
            else:
                return super().web_login(redirect=redirect, **kw)

        return super().web_login(redirect=redirect, **kw)

    def _handle_otp_login(self, values, redirect=None):
        """Handle OTP-based login flow"""
        mobile = request.params.get('mobile')
        otp = request.params.get('otp')
        action = values.get('action') or request.params.get('action')

        _logger.info(f"OTP login handler - Action: {action}, Mobile: {mobile}")

        if not mobile:
            values['error'] = _("Mobile number is required")
            return request.render('web.login', values)

        if action == 'send_otp':
            result = self._send_otp(mobile)
            # Make sure to include all necessary values
            values.update({
                'message': result.get('message'),
                'error': result.get('error'),
                'mobile': mobile,
                'otp_sent': True,  # This is crucial
                'login_type': 'otp',
                'action': action
            })
            request.params['otp_sent'] = True  # Add this line to ensure params has otp_sent
            return request.render('web.login', values)
            
        elif action == 'verify_otp':
            if not otp:
                values.update({
                    'error': _("OTP is required"),
                    'mobile': mobile,
                    'otp_sent': True,
                    'login_type': 'otp',
                    'action': action
                })
                return request.render('web.login', values)
            return self._verify_otp(mobile, otp, redirect)
        
        values['error'] = _("Invalid action")
        return request.render('web.login', values)

    def _send_otp(self, mobile):
        """Generate and send OTP"""
        # Generate a 6-digit OTP
        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        

        # TODO: Implement actual OTP sending logic here
        try:
            # Get the create request service
            handsheke = request.env.ref('daarman_api.login_handsheke').sudo()
            
            
            
            request_data = json.loads(handsheke.sample_request)
            response = handsheke.call(data=request_data)
            
            if response and not response.get('hasError'):
                result = response.get('result', {})  
                parsed_result = json.loads(result) if isinstance(result, str) else result 
                keyId = None    
                if isinstance(parsed_result.get('result'), list) and len(parsed_result['result']) > 0 and 'keyId' in parsed_result['result'][0]:
                    keyId = parsed_result['result'][0]['keyId']
                if keyId:
                    authorize = request.env.ref('daarman_api.login_authorize').sudo()
                    authorize_data = json.loads(authorize.sample_request)
                    authorize_data['providerParameters']['body']['keyId'] = keyId
                    authorize_data['providerParameters']['body']['mobile'] = mobile
                    authorize_data['providerParameters']['body']['device_uid'] = "12313213"
                    result = authorize.call(data=authorize_data)
                else:
                    return {'status': 'error', 'message': _("OTP verification failed, please try again")}
            else:
                return {'status': 'error', 'message': _("Failed to get handshake service, please try again")}
        except Exception as e:
            _logger.error(f"Error getting handshake service: {e}")
            return {'status': 'error', 'message': _("Failed to get handshake service, please try again")}
        # Store OTP in session with timestamp
        request.session['otp_data'] = {
            'mobile': mobile,
            'keyId': keyId,
        }
        _logger.info(f"OTP generated for {mobile}: {otp}")

        return {'status': 'success', 'message': _("OTP sent successfully")}

    def _verify_otp(self, mobile, otp, redirect=None):
        """Verify OTP and log in user"""
        otp_data = request.session.get('otp_data', {})
        
        if not otp_data or otp_data.get('mobile') != mobile:
            values = {'error': _("Invalid OTP")}
            return request.render('web.login', values)
        user = None
        try:
            verify = request.env.ref('daarman_api.login_verify').sudo()
            verify_date = json.loads(verify.sample_request)
            verify_date['providerParameters']['body']['keyId'] = otp_data.get('keyId')
            verify_date['providerParameters']['body']['mobile'] = mobile
            verify_date['providerParameters']['body']['code'] = otp
            result = verify.call(data=verify_date)
            if result and not result.get('hasError'):
                parsed_result = json.loads(result.get('result', '{}')) if isinstance(result.get('result'), str) else result.get('result', {})
                if parsed_result.get('hasError'):
                    raise UserError(parsed_result.get('message', _("OTP verification failed, please try again")))
                    
                #Search res_users by mobile number
                user = request.env['res.users'].sudo().search([('mobile', '=', mobile)], limit=1)
                if not user:
                    if isinstance(parsed_result.get('result'), list) and len(parsed_result['result']) > 0 and 'code' in parsed_result['result'][0]:
                        code = parsed_result['result'][0]['code']
                        login_token = request.env.ref('daarman_api.login_get_token').sudo()
                        token_data = json.loads(login_token.sample_request)
                        token_data['providerParameters']['body']['keyId'] = otp_data.get('keyId')
                        token_data['providerParameters']['body']['mobile'] = mobile
                        token_data['providerParameters']['body']['code'] = code
                        token_result = login_token.call(data=token_data)
                        if token_result and not token_result.get('hasError'):
                            token_parsed_result = json.loads(token_result.get('result', '{}')) if isinstance(token_result.get('result'), str) else token_result.get('result', {})
                            if isinstance(token_parsed_result.get('result'), list) and len(token_parsed_result['result']) > 0 and 'access_token' in token_parsed_result['result'][0]:
                                token = token_parsed_result['result'][0]['access_token']
                                profile = request.env.ref('daarman_api.profile_info').sudo()
                                profile_data = json.loads(profile.sample_request)
                                profile_data['providerParameters']['Access-Token'] = token
                                profile_result = profile.call(data=profile_data)
                                if profile_result and not profile_result.get('hasError'):
                                    profile_parsed_result = json.loads(profile_result.get('result', '{}')) if isinstance(profile_result.get('result'), str) else profile_result.get('result', {})
                                    if isinstance(profile_parsed_result.get('result'), dict):
                                        user_data = profile_parsed_result['result']
                                        #create user
                                        request.env['res.users'].sudo().signup({
                                            'name': user_data.get('firstName', '') + ' ' + user_data.get('lastName', ''),
                                            'login': user_data.get('username', ''),
                                            'mobile': mobile,
                                            'email': user_data.get('email', ''),
                                            'active': True,
                                            # generate random password
                                            'password': ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(12)]),
                                            'pod_user_id': int(user_data.get('userId', 0)) if str(user_data.get('userId', '')).isdigit() else False,
                                        })
                                        request.env.cr.commit()
                                        user = request.env['res.users'].sudo().search([('mobile', '=', mobile)], limit=1)

                    else:
                        raise UserError(_("OTP verification failed, please try again"))
                     
            else:
                raise UserError(_("OTP verification failed, please try again"))
        except Exception as e:
            _logger.error(f"Error verifying OTP: {e}")
            values = {'error': _("Failed to verify OTP, please try again")}
            return request.render('web.login', values)
        


        # Clear OTP data from session
        request.session.pop('otp_data', None)

        # Authenticate user
        credential = {'login':user.login,'uid':user.id, 'type':'otp'}
        request.session.authenticate(request.db, credential)
        request.params['login_success'] = True

        return request.redirect(self._login_redirect(user.id, redirect=redirect))

    @http.route('/web/login', type='json', auth='none', methods=['POST'], csrf=True, website=True)
    def web_login_json(self, **kw):
        """Handle JSON requests for OTP operations"""
        try:
            if kw.get('login_type') == 'otp' and kw.get('action') == 'send_otp':
                mobile = kw.get('mobile')
                if not mobile:
                    return {'status': 'error', 'message': _("Mobile number is required")}
                    
                result = self._send_otp(mobile)
                return {
                    'status': 'success',
                    'message': result.get('message', _("OTP sent successfully")),
                    'csrf_token': request.csrf_token()
                }
                
            return {'status': 'error', 'message': _("Invalid request")}
            
        except Exception as e:
            _logger.error("Error in OTP login: %s", str(e))
            return {'status': 'error', 'message': _("System error occurred")}