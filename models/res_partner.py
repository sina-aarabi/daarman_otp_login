from odoo import models, fields


class ResPartner(models.Model):
    _inherit = 'res.partner'

    national_code = fields.Char(string='National Code', size=10)
    birthdate = fields.Date(string='Birthdate')
