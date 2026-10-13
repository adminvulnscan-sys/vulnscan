"""Account-scoped reservations. RPCs are the authority; never debit locally."""
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import logging
import time
from uuid import uuid4


class ScanBusy(ValueError):
    pass


def service_scan_client(client, email):
    """Adapter for a trusted scheduler; the SQL dispatcher verifies service_role."""
    class JobClient:
        def rpc(self, name, params):
            actions = {'billing_scan_claim': 'claim', 'billing_scan_heartbeat': 'heartbeat',
                       'billing_scan_complete': 'complete', 'billing_scan_abort': 'abort',
                       'billing_scan_store': 'store'}
            if name not in actions or params.get('p_credit') is not None:
                raise ValueError('Unsupported scheduler operation')
            return client.rpc('billing_scan_job', {
                'p_email': email, 'p_action': actions[name], 'p_operation': params['p_operation'],
                'p_target': params.get('p_target'), 'p_engine': params.get('p_engine'),
                'p_report': params.get('p_report'), 'p_payload': params.get('p_payload')})
    return JobClient()


def _rpc(client, name, **params):
    result = client.rpc(name, params).execute().data
    if not isinstance(result, dict):
        raise ValueError('No se pudo confirmar la reserva del escaneo')
    return result


def begin_scan(state, client, credit, target, scan_type):
    if state.get('escaneo_en_curso'):
        raise ScanBusy('Ya hay un escaneo en curso. No se ha consumido otro crédito.')
    pending = state.get('_scan_credit_pending')
    if pending and pending.get('payload'):
        store_scan(state, client, pending['payload'])
        raise ScanBusy('Se ha confirmado el escaneo anterior. Sus resultados siguen disponibles.')
    if pending and pending.get('report_id'):
        finish_scan(state, client, completed=True, report_id=pending['report_id'])
        raise ScanBusy('Se ha confirmado el escaneo anterior. Sus resultados siguen disponibles.')
    identity = (state.get('email_usuario'), credit, target, scan_type)
    if pending and tuple(pending['identity']) != identity:
        # Resolve the previous uncertain reservation before admitting a new one.
        result = _rpc(client, 'billing_scan_abort', p_operation=pending['operation'])
        if result.get('status') not in ('failed', 'expired', 'missing', 'completed'):
            raise ValueError('No se pudo resolver el escaneo anterior')
        pending = None
    if pending and not pending.get('server_reservation'):
        # An old, already-debited session must not silently pay again after upgrade.
        raise ValueError('Hay un consumo anterior pendiente de revisión')
    if not pending:
        pending = {'identity': identity, 'operation': str(uuid4()), 'server_reservation': True}
        state['_scan_credit_pending'] = pending
    state['escaneo_en_curso'] = True
    try:
        result = _rpc(client, 'billing_scan_claim', p_operation=pending['operation'],
                      p_credit=credit, p_target=target, p_engine=scan_type)
        if result.get('status') == 'busy':
            state.pop('_scan_credit_pending', None)
            raise ScanBusy('Ya hay un escaneo en curso en esta cuenta. No se ha consumido otro crédito.')
        if result.get('status') == 'completed':
            if result.get('report_id'):
                state['escaneo_actual_id'] = str(result['report_id'])
            state.pop('_scan_credit_pending', None)
            raise ScanBusy('El escaneo anterior ya está confirmado; no se ha iniciado otro.')
        if result.get('status') != 'reserved':
            raise ValueError('No se pudo reservar el escaneo')
        if credit and isinstance(result.get('remaining'), int):
            state[credit] = result['remaining']  # Held, not yet debited.
    except BaseException:
        state['escaneo_en_curso'] = False
        raise


def heartbeat(state, client):
    pending = state['_scan_credit_pending']
    result = _rpc(client, 'billing_scan_heartbeat', p_operation=pending['operation'])
    if result.get('status') != 'reserved':
        raise ValueError('La reserva ha vencido; no se guardarán resultados sin confirmación')


def run_reserved_scan(state, client, scanner, *args, heartbeat_seconds=30, max_scan_seconds=3600, **kwargs):
    """Keep RPCs on the Streamlit thread; only the existing engine runs in a worker."""
    heartbeat(state, client)
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(scanner, *args, **kwargs)
    started = time.monotonic()
    try:
        while True:
            try:
                result = future.result(timeout=heartbeat_seconds)
                heartbeat(state, client)  # Fence stale results before persistence.
                return result
            except FutureTimeout:
                if future.done():  # A TimeoutError from the engine, not this wait.
                    raise
                if time.monotonic()-started >= max_scan_seconds:
                    raise TimeoutError('El escaneo excedió el límite de duración') from None
                heartbeat(state, client)
    finally:
        # A running network request cannot be forcibly killed by Python.
        # Never admit its results after losing the reservation.
        pool.shutdown(wait=False, cancel_futures=True)


def finish_scan(state, client, completed=False, report_id=None):
    state['escaneo_en_curso'] = False
    pending = state.get('_scan_credit_pending')
    if not pending:
        return
    if completed:
        if not report_id:
            raise ValueError('No se ha confirmado el guardado del informe')
        pending['report_id'] = str(report_id)
        result = _rpc(client, 'billing_scan_complete', p_operation=pending['operation'],
                      p_report=str(report_id))
        if result.get('status') != 'completed':
            raise ValueError('El escaneo está guardado; falta confirmar su consumo')
    else:
        if pending.get('report_id') or pending.get('payload'):
            return  # Unknown completion response: retain idempotent recovery, never abort it.
        try:
            result = _rpc(client, 'billing_scan_abort', p_operation=pending['operation'])
        except Exception as error:
            logging.getLogger(__name__).warning('operation=scan_abort error_type=%s', type(error).__name__)
            return  # Retain operation; server expiry frees the hold without any debit.
        if result.get('status') not in ('failed', 'expired', 'missing', 'completed'):
            return
    credit = pending['identity'][1]
    if credit and isinstance(result.get('remaining'), int):
        state[credit] = result['remaining']
    state.pop('_scan_credit_pending', None)


def store_scan(state, client, payload):
    """Persist the result AND consume its held credit in one server transaction."""
    pending = state['_scan_credit_pending']
    pending['payload'] = payload
    result = _rpc(client, 'billing_scan_store', p_operation=pending['operation'], p_payload=payload)
    if result.get('status') == 'expired':
        state.pop('_scan_credit_pending', None)
        state['escaneo_en_curso'] = False
        raise ValueError('La reserva venció sin consumo. Puedes iniciar un nuevo escaneo.')
    if result.get('status') != 'completed' or not result.get('report_id'):
        raise ValueError('No se ha confirmado el informe guardado')
    credit = pending['identity'][1]
    if credit and isinstance(result.get('remaining'), int):
        state[credit] = result['remaining']
    state['escaneo_actual_id'] = str(result['report_id'])
    state['escaneo_en_curso'] = False
    state.pop('_scan_credit_pending', None)
    return str(result['report_id'])
