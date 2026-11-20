"""Counts of verified observations, never inferred from reachability or port numbers."""
import re
from ipaddress import IPv4Address


def discovery_totals(observations, service_processed):
    from .recommendation_planner import normalized_fact
    ports, services, web = set(), set(), set()
    for item in observations:
        data = item.get('data') or {}
        if item.get('type') == 'web_application':
            from types import SimpleNamespace
            fact = normalized_fact(SimpleNamespace(observation_type='web_application', data=data, is_partial=False))
            if fact:
                web.add((str(item['target_id']), fact['url']))
        if item.get('type') != 'service_discovery':
            continue
        try:
            address = data['address']
            if str(IPv4Address(address)) != address:
                continue
            port, service = data['port'], data['service']
            if (type(port) is not int or not 1 <= port <= 65535 or data.get('state') != 'open'
                    or data.get('transport') != 'tcp' or not isinstance(service, str)
                    or not re.fullmatch(r'[a-z0-9][a-z0-9_.+-]{0,79}', service)):
                continue
            key = (str(item['target_id']), address, 'tcp', port)
            ports.add(key)
            services.add((*key, service))
        except (ValueError, KeyError, TypeError):
            continue
    return {'open_ports': len(ports) if service_processed or ports else None,
            'services': len(services) if service_processed or services else None,
            'web_targets': len(web) if web else None}
