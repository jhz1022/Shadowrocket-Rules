"""Fail closed on unusually large routing changes; counts are boundary samples,
not website counts. This does not establish the correctness of upstream policy.
"""
import math


def assess(report, limits):
    required = {'schema', 'max_domain_changes', 'max_domain_change_ratio',
                'max_proxy_to_direct', 'max_proxy_to_direct_ratio',
                'max_ip_added_ratio', 'max_ip_removed_ratio'}
    if set(limits) != required or limits['schema'] != 1:
        raise ValueError('Missing or unknown update guard settings')
    for key, value in limits.items():
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError('Invalid update guard limit: ' + key)
        if key.endswith('ratio') and value > 1:
            raise ValueError('Invalid update guard ratio: ' + key)
    if not report.get('previous_config_sha256'):
        raise ValueError('Update guard requires the previous published configuration')
    samples = report['domain_boundary_cases']
    changes = report['boundary_policy_changes']
    if type(samples) is not int or samples <= 0 or any(
            key not in {'PROXY -> DIRECT', 'DIRECT -> PROXY'} or
            type(value) is not int or value < 0 for key, value in changes.items()):
        raise ValueError('Invalid domain transition evidence')
    total = sum(changes.values())
    if total > samples:
        raise ValueError('Domain transition evidence exceeds sample count')
    to_direct = changes.get('PROXY -> DIRECT', 0)
    reasons = []
    for name, value, cap in [
        ('domain_changes', total, limits['max_domain_changes']),
        ('domain_change_ratio', total / samples, limits['max_domain_change_ratio']),
        ('proxy_to_direct', to_direct, limits['max_proxy_to_direct']),
        ('proxy_to_direct_ratio', to_direct / samples, limits['max_proxy_to_direct_ratio'])
    ]:
        if value > cap:
            reasons.append({'metric': name, 'value': value, 'limit': cap})
    for family in ('china4', 'china6'):
        delta = report['ip_policy_changes'][family]
        if any(type(delta[k]) is not int or delta[k] < 0
               for k in ('previous_addresses', 'added_addresses', 'removed_addresses')):
            raise ValueError('Invalid IP transition evidence')
        before = delta['previous_addresses']
        if before <= 0 or delta['removed_addresses'] > before:
            raise ValueError('Invalid previous IP coverage')
        for direction in ('added', 'removed'):
            ratio = delta[direction + '_addresses'] / before
            cap = limits['max_ip_' + direction + '_ratio']
            if ratio > cap:
                reasons.append({'metric': family + '_' + direction + '_ratio',
                                'value': ratio, 'limit': cap})
    return {'passed': not reasons, 'violations': reasons, 'limits': limits,
            'scope': 'Static domain boundary changes and exact China IP membership churn; no live DNS or traffic measurement.'}


def ip_delta(before, after):
    """Count exact interval membership changes without enumerating IP addresses."""
    import ipaddress
    a = [(int(n.network_address), int(n.broadcast_address))
         for n in ipaddress.collapse_addresses(before)]
    b = [(int(n.network_address), int(n.broadcast_address))
         for n in ipaddress.collapse_addresses(after)]
    total_a = sum(end - start + 1 for start, end in a)
    total_b = sum(end - start + 1 for start, end in b)
    overlap = i = j = 0
    while i < len(a) and j < len(b):
        overlap += max(0, min(a[i][1], b[j][1]) - max(a[i][0], b[j][0]) + 1)
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return {'previous_addresses': total_a, 'added_addresses': total_b - overlap,
            'removed_addresses': total_a - overlap}
