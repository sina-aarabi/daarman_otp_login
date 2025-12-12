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
        national_code = request.params.get('national_code')
        birthdate = request.params.get('birthdate')
        otp = request.params.get('otp')
        action = values.get('action') or request.params.get('action')

        _logger.info(f"OTP login handler - Action: {action}, Mobile: {mobile}")

        if not mobile:
            values['error'] = _("Mobile number is required")
            return request.render('web.login', values)

        if action == 'send_mobile':
            # Step 1: Check if user exists and show form if new user
            user = request.env['res.users'].sudo().search([('mobile', '=', mobile)], limit=1)
            user_exists = bool(user)
            
            if user_exists:
                # Existing user - automatically call authorize service with data from database
                national_code = user.partner_id.national_code if user.partner_id else ''
                birthdate = str(user.partner_id.birthdate) if user.partner_id and user.partner_id.birthdate else ''
                
                result = self._call_authorize_service(mobile, national_code, birthdate)
                
                if result.get('status') != 'success':
                    values.update({
                        'error': result.get('error'),
                        'mobile': mobile,
                        'login_type': 'otp',
                    })
                    request.params['error'] = result.get('error')
                    return request.render('web.login', values)
                
                # Store data in session for OTP verification
                request.session['otp_data'] = {
                    'mobile': mobile,
                    'keyId': request.session['otp_data'].get('keyId'),
                    'national_code': national_code,
                    'birthdate': birthdate,
                }
                
                values.update({
                    'message': _("OTP sent successfully"),
                    'mobile': mobile,
                    'otp_sent': True,
                    'login_type': 'otp',
                })
                request.params['otp_sent'] = 'True'
                return request.render('web.login', values)
            else:
                # New user - show form for national code and birthdate
                values.update({
                    'mobile': mobile,
                    'show_user_details_form': True,
                    'user_exists': False,
                    'login_type': 'otp',
                })
                request.params['show_user_details_form'] = 'True'
                request.params['user_exists'] = 'False'
                return request.render('web.login', values)
            
        elif action == 'authorize_otp':
            # Step 2: Get user details (from form for new user, or from database for existing user)
            user = request.env['res.users'].sudo().search([('mobile', '=', mobile)], limit=1)
            
            if not user:
                # New user - get from form
                if not national_code or not birthdate:
                    values.update({
                        'error': _("National code and birthdate are required for new users"),
                        'mobile': mobile,
                        'show_user_details_form': True,
                        'login_type': 'otp',
                    })
                    request.params['show_user_details_form'] = 'True'
                    return request.render('web.login', values)
                if not national_code.isdigit() or len(national_code) != 10:
                    values.update({
                        'error': _("National code must be a 10 digit number"),
                        'mobile': mobile,
                        'national_code': national_code,
                        'birthdate': birthdate,
                        'show_user_details_form': True,
                        'login_type': 'otp',
                    })
                    request.params['show_user_details_form'] = 'True'
                    return request.render('web.login', values)
            else:
                # Existing user - get from database
                national_code = user.partner_id.national_code if user.partner_id else ''
                birthdate = str(user.partner_id.birthdate) if user.partner_id and user.partner_id.birthdate else ''
            
            # Call authorize service with mobile, national_code, and birthdate
            result = self._call_authorize_service(mobile, national_code, birthdate)
            
            if result.get('status') != 'success':
                values.update({
                    'error': result.get('error'),
                    'mobile': mobile,
                    'show_user_details_form': not bool(user),
                    'login_type': 'otp',
                })
                if not user:
                    request.params['show_user_details_form'] = 'True'
                return request.render('web.login', values)
            
            # Store data in session for OTP verification
            request.session['otp_data'] = {
                'mobile': mobile,
                'keyId': request.session['otp_data'].get('keyId'),
                'national_code': national_code,
                'birthdate': birthdate,
            }
            
            values.update({
                'message': _("OTP sent successfully"),
                'mobile': mobile,
                'otp_sent': True,
                'login_type': 'otp',
            })
            request.params['otp_sent'] = 'True'
            return request.render('web.login', values)
            
        elif action == 'verify_otp':
            if not otp:
                values.update({
                    'error': _("OTP is required"),
                    'mobile': mobile,
                    'otp_sent': True,
                    'login_type': 'otp',
                })
                request.params['otp_sent'] = 'True'
                return request.render('web.login', values)
            return self._verify_otp(mobile, otp, redirect)
        
        values['error'] = _("Invalid action")
        return request.render('web.login', values)

    def _call_authorize_service(self, mobile, national_code, birthdate):
        """Call authorize service with user details"""
        try:
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
                    authorize_data['providerParameters']['body']['mobile'] = mobile
                    authorize_data['providerParameters']['body']['keyId'] = keyId
                    # authorize_data['providerParameters']['body']['nationalcode'] = national_code
                    # authorize_data['providerParameters']['body']['birthDate'] = birthdate
                    # authorize_data['providerParameters']['body']['captchaHash'] = "hash123456"
                    # authorize_data['providerParameters']['body']['captchaValue'] = "ABCD"
                    authorize_data['providerParameters']['body']['device_uid'] = "12313213"
                    
                    result = authorize.call(data=authorize_data)
                    

                else:
                    values = {'message':'','error': _("Failed to verify OTP, please try again")}
                    return request.render('web.login', values)
            else:
                values = {'message':'','error': _("Failed to get handshake service, please try again")}
                return request.render('web.login', values)
        except Exception as e:
            _logger.error(f"Error getting handshake service: {e}")
            values = {'message':'','error': _("Failed to get handshake service, please try again")}
            return request.render('web.login', values)
        # Store OTP in session with timestamp
        request.session['otp_data'] = {
            'mobile': mobile,
            'keyId': keyId,
        }
        _logger.info(f"OTP generated for {mobile}")

        return {'status': 'success', 'message': _("OTP sent successfully")}
            
          

    def _send_otp(self, mobile):
        """Generate and send OTP (deprecated - kept for compatibility)"""
        try:
            handsheke = request.env.ref('daarman_api.login_handsheke').sudo()
            request_data = json.loads(handsheke.sample_request)
            response = handsheke.call(data=request_data)

            if response and not response.get('hasError'):
                result = response.get('result', {})
                parsed_result = json.loads(result) if isinstance(result, str) else result
                if isinstance(parsed_result.get('result'), list) and len(parsed_result['result']) > 0 and 'keyId' in parsed_result['result'][0]:
                    return {'status': 'success', 'message': _("OTP sent successfully")}
            
            return {'status': 'error', 'error': _("Failed to send OTP")}
        except Exception as e:
            _logger.error(f"Error getting handshake service: {e}")
            return {'status': 'error', 'error': _("Failed to send OTP")}

    def _verify_otp(self, mobile, otp, redirect=None):
        """Verify OTP and log in user"""
        otp_data = request.session.get('otp_data', {})
        
        if not otp_data or otp_data.get('mobile') != mobile:
            values = {'error': _("Invalid OTP session")}
            return request.render('web.login', values)
        
        user = None
        try:
            verify = request.env.ref('daarman_api.login_verify').sudo()
            verify_data = json.loads(verify.sample_request)
            verify_data['providerParameters']['body']['keyId'] = otp_data.get('keyId')
            verify_data['providerParameters']['body']['mobile'] = mobile
            verify_data['providerParameters']['body']['code'] = otp
            result = verify.call(data=verify_data)
            
            if result and not result.get('hasError'):
                parsed_result = json.loads(result.get('result', '{}')) if isinstance(result.get('result'), str) else result.get('result', {})
                if parsed_result.get('hasError'):
                    values = {'error': _("OTP verification failed, please try again")}
                    return request.render('web.login', values)
                    
                # Search res_users by mobile number
                user = request.env['res.users'].sudo().search([('mobile', '=', mobile)], limit=1)
                if not user:
                    # New user - create account
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
                                        # Create partner with national_code and birthdate from session
                                        partner_vals = {
                                            'name': user_data.get('firstName', '') + ' ' + user_data.get('lastName', ''),
                                            'email': user_data.get('email', ''),
                                            'mobile': mobile,
                                            'is_company': False,
                                            'national_code': otp_data.get('national_code'),
                                            'birthdate': otp_data.get('birthdate'),
                                        }
                                        partner = request.env['res.partner'].sudo().create(partner_vals)
                                        
                                        # Create user
                                        request.env['res.users'].sudo().signup({
                                            'name': user_data.get('firstName', '') + ' ' + user_data.get('lastName', ''),
                                            'login': user_data.get('username', ''),
                                            'mobile': mobile,
                                            'email': user_data.get('email', ''),
                                            'active': True,
                                            'password': ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(12)]),
                                            'pod_user_id': int(user_data.get('userId', 0)) if str(user_data.get('userId', '')).isdigit() else False,
                                            'partner_id': partner.id,
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
        credential = {'login': user.login, 'uid': user.id, 'type': 'otp'}
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
                    'status': 'success' if result.get('status') == 'success' else 'error',
                    'message': result.get('message', result.get('error', _("OTP sent successfully"))),
                    'user_exists': bool(result.get('user_exists')),
                    'csrf_token': request.csrf_token()
                }
                
            return {'status': 'error', 'message': _("Invalid request")}
            
        except Exception as e:
            _logger.error("Error in OTP login: %s", str(e))
            return {'status': 'error', 'message': _("System error occurred")}