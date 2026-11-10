"""Additive result vocabulary; legacy ok/error_category/checkpoint fields remain."""
def normalize_result(result):
    category = result.get('error_category', '')
    children = result.get('results', result.get('steps', []))
    for child in children:
        if isinstance(child, dict): normalize_result(child)
    has_data = bool(result.get('characters') or result.get('output') or result.get('output_id') or result.get('preview'))
    if children:
        has_data = has_data or any(c.get('data_state') != 'NONE' for c in children)
    complete = result.get('output_complete', result.get('ok') is True)
    if children and children[-1].get('awaiting_input'):
        result['awaiting_input'] = True
    result['data_state'] = 'FULL' if complete else ('PARTIAL' if has_data else 'NONE')
    if result.get('awaiting_input'):
        status = 'AWAITING_INPUT'
    elif result.get('ok') is True:
        status = 'SUCCESS'
    elif category in {'authentication', 'auth_method'}:
        status = 'AUTH_ERROR'
    elif category == 'storage_error':
        status = 'STORAGE_ERROR'
    elif category == 'parsing_error':
        status = 'PARSE_ERROR'
    elif category == 'cli_error':
        status = 'CLI_ERROR'
    elif category == 'cancelled':
        status = 'CANCELLED'
    elif category in {'deadline', 'read_timeout', 'connect_timeout', 'auth_timeout', 'banner_timeout'}:
        status = 'TIMEOUT'
    elif category in {'connection_lost','connection_refused','dns_error','banner_error','ssh_error',
                      'host_key_changed','host_key_unknown','algorithm_mismatch','handshake_incomplete'}:
        status = 'CONNECT_ERROR'
    elif children:
        good = any(c.get('ok') for c in children)
        statuses = {c.get('status') for c in children if not c.get('ok')}
        status = 'PARTIAL' if good else (next(iter(statuses)) if len(statuses) == 1 else 'UNKNOWN')
    else:
        status = 'PARTIAL' if has_data else 'UNKNOWN'
    result['fault_status'] = status
    uncertain = (result.get('command_sent') is True and result.get('replay_safe') is False
                 and not complete and not result.get('awaiting_input'))
    result['execution_state'] = ('AWAITING_INPUT' if result.get('awaiting_input') else
                                 'UNCERTAIN' if uncertain else 'COMPLETED' if complete else
                                 'NOT_SENT' if result.get('command_sent') is False else 'UNKNOWN')
    if children and any(c.get('execution_state') == 'UNCERTAIN' for c in children):
        uncertain = True
        result['execution_state'] = 'UNCERTAIN'
    result['status'] = 'UNKNOWN' if uncertain else status
    return result
