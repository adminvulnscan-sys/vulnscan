"""Materialize paid-plan downloads only on explicit request, after server checks."""
import logging

from billing import authenticated_user


def deferred_report(client, owner, report, factory):
    # A separate closure for each report, private to the Streamlit session.
    # No request, generation, entitlement or credit operation at registration.
    report_id = str(report['id'])
    def download():
        try:
            authenticated_user(client, owner)
            result = client.rpc('billing_authorize_pdf', {
                'p_report': report_id, 'p_consume': False}).execute().data
            if not isinstance(result, dict) or result.get('authorized') is not True:
                raise PermissionError('Report not authorized')
            rows = client.table('escaneos').select('*').eq('id', report_id).eq(
                'email_cliente', owner).limit(1).execute().data
            if (not isinstance(rows, list) or len(rows) != 1
                    or str(rows[0].get('id')) != report_id
                    or rows[0].get('email_cliente') != owner):
                raise PermissionError('Report not owned')
            return factory(rows[0])
        except Exception as error:
            logging.getLogger('vulnscan.panel').warning(
                'operation=report_download error_type=%s', type(error).__name__)
            raise RuntimeError('No se pudo preparar o autorizar el informe. Vuelve al panel para comprobar el acceso.') from None
    return download
