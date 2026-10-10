"""Public return routes, independent of cached billing and Stripe clients."""
import os
from urllib.parse import urlencode, urlsplit, urlunsplit


PUBLIC_APP_URL = 'https://vulnscan-kckbqnppvww5b4g8bseevs.streamlit.app/'


def payment_return_url(outcome=None, language='es'):
    """Billing returns to the actual app, independently of the marketing APP_URL."""
    base = os.environ.get('BILLING_RETURN_URL', PUBLIC_APP_URL).strip()
    target = urlsplit(base)
    local_http = target.scheme == 'http' and target.hostname in ('localhost', '127.0.0.1', '::1')
    if (not target.hostname or (target.scheme != 'https' and not local_http)
            or target.username or target.password or target.query or target.fragment
            or '/~/' in target.path or any(c.isspace() for c in base)):
        raise ValueError('Invalid billing return URL')
    # Validate the port as well; malformed values must fail before creating Checkout.
    _ = target.port
    query = {'vista': 'acceso', 'lang': language if language in ('es', 'en') else 'es'}
    if outcome is not None:
        if outcome not in ('exitoso', 'cancelado'):
            raise ValueError('Invalid payment return outcome')
        query['pago'] = outcome
        if outcome == 'exitoso':
            query['session_id'] = '{CHECKOUT_SESSION_ID}'
    return urlunsplit((target.scheme, target.netloc, target.path.rstrip('/') + '/',
                      urlencode(query, safe='{}'), ''))
