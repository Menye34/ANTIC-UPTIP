"""Deterministic evidence-derived planning. No scanner execution authority."""
from ipaddress import IPv4Address
from urllib.parse import urlsplit
from .baseline_catalog import fingerprint
from .recommendation_capabilities import CAPABILITIES


def normalized_fact(observation):
    """Pure normalized-input contract for trusted producers, never a raw scan parser.

    Existing Nmap normalization emits host_discovery only; no port or service is
    inferred from that record. Future adapters must emit validated typed facts.
    """
    if observation.is_partial or not isinstance(observation.data, dict):
        return None
    data = observation.data
    try:
        address = str(IPv4Address(data['address']))
        if address != data['address']:
            return None
    except (KeyError, ValueError, TypeError):
        return None
    kind = observation.observation_type
    port = data.get('port')
    if type(port) is not int or not 1 <= port <= 65535:
        return None
    if kind == 'service_discovery':
        if data.get('state') != 'open' or data.get('transport') != 'tcp' or data.get('service') not in ('http', 'https'):
            return None
        fact = {'address': address, 'port': port, 'service': data['service'], 'transport': 'tcp'}
    elif kind == 'web_application':
        # An open HTTP port is not evidence of an application or a URL boundary.
        if (data.get('application_verified') is not True or not isinstance(data.get('url'), str)
                or any(ord(c) < 32 for c in data['url']) or '\\' in data['url']):
            return None
        try:
            url = urlsplit(data['url'])
            if (url.scheme not in ('http', 'https') or url.hostname != address
                    or url.username is not None or url.password is not None or url.fragment
                    or (url.port or (443 if url.scheme == 'https' else 80)) != port
                    or len(data['url']) > 2048):
                return None
        except ValueError:
            return None
        fact = {'address': address, 'port': port, 'service': url.scheme, 'url': data['url']}
    else:
        return None
    version = data.get('version')
    if version is not None:
        if not isinstance(version, str) or not version.strip() or len(version) > 120 or any(ord(c) < 32 for c in version):
            return None
        fact['version'] = version
    return fact


def plan_recommendations(observations, *, completed_capabilities=()):
    """One recommendation per evidence condition and distinct objective.

    Deduplication groups equivalent normalized facts; evidence IDs and times are
    provenance, not proof of material change. Changed facts/capability definitions
    produce a new identity; unchanged rejected IDs retain their persisted outcome.
    completed_capabilities is internal trusted context, never request data.
    """
    result, seen = [], set()
    ordered = sorted(observations, key=lambda o: (str(o.target_id), str(o.id)))
    current = {}
    for source in ordered:
        fact = normalized_fact(source)
        if fact is None: continue
        key = (str(source.target_id), source.observation_type, fact['address'], fact['port'], fact['service'], fact.get('url'))
        prior = current.get(key)
        if prior is None or (str(getattr(source, 'collected_at', '')), str(source.id)) > (str(getattr(prior, 'collected_at', '')), str(prior.id)):
            current[key] = source
    for source in current.values():
        fact = normalized_fact(source)
        if fact is None:
            continue
        for capability in CAPABILITIES:
            if capability.source_type != source.observation_type:
                continue
            context = {'planner_version': 2, 'target_id': str(source.target_id),
                       'fact': fact, 'capability': capability.snapshot()}
            digest = fingerprint(context)
            if digest in seen or (str(source.target_id), capability.key, fingerprint(fact)) in completed_capabilities:
                continue
            seen.add(digest)
            discovered = (f"Evidence recorded {fact['service'].upper()} on {fact['address']}:{fact['port']}"
                          + (f" (version {fact['version']})" if fact.get('version') else '') + '.')
            if source.observation_type == 'web_application':
                discovered = f"Evidence identifies a web application at {fact['url']}."
                question = 'Application behavior and security controls have not been established by this observation; an open port alone would not justify this application assessment.'
            else:
                question = 'Service identification does not establish whether the HTTP server configuration or exposed resources present security issues; no vulnerability is asserted.'
            proposed = f"{capability.test} with {capability.tool} would address this objective. Integration is pending; this recommendation cannot queue or execute a test."
            result.append({
                'id': digest, 'kind': 'evidence_followup', 'title': capability.test,
                'planner_version': 2, 'context_digest': digest, 'target_id': source.target_id,
                'target': fact['address'], 'service': fact['service'], 'port': fact['port'],
                'reason': '\n\n'.join((discovered, question, proposed)),
                'explanation': [discovered, question, proposed],
                'source_observation_id': source.id, 'source_evidence_id': source.evidence_id,
                'execution_available': False, 'execution_status': 'pending_integration',
                'execution_unavailability_reason': 'tool_integration_pending',
                'suggested_test': capability.test, 'suggested_tool': capability.tool,
                'proposed_test': {'id': capability.key, 'version': capability.version,
                                  'name': capability.test, 'tool': capability.tool,
                                  'description': capability.description, 'profile_id': capability.profile_id,
                                  'definition_digest': capability.snapshot()['digest']},
                'tool_integration_status': 'pending_integration',
            })
    return sorted(result, key=lambda item: item['id'])


def carry_deferred_legacy(observations, decisions, suggestions):
    """Do not erase an analyst's unresolved Deferred host review on upgrade.

    No new host-review suggestions are generated. Only a matching persisted
    Deferred legacy ID is carried as read-only historical review work.
    """
    from hashlib import sha256
    deferred = {item['recommendation_id'] for item in decisions if item['decision']=='Deferred'}
    result = list(suggestions);seen={item['id'] for item in result}
    for source in sorted(observations,key=lambda o:str(o.id)):
        if source.observation_type!='host_discovery' or source.is_partial or not isinstance(source.data,dict) or source.data.get('status')!='up':
            continue
        address=source.data.get('address')
        if not isinstance(address,str):continue
        try:
            if str(IPv4Address(address))!=address:continue
        except ValueError:continue
        identity=sha256(f'host-review-v1:{source.target_id}:{address}'.encode()).hexdigest()
        if identity not in deferred or identity in seen:continue
        seen.add(identity)
        result.append({'id':identity,'kind':'review_host_discovery','title':'Review responding host',
            'target_id':source.target_id,'target':address,'port':None,'service':None,
            'reason':'This historical host review was explicitly deferred. Review it before completing Testing; host reachability does not justify a follow-up scan.',
            'source_observation_id':source.id,'source_evidence_id':source.evidence_id,
            'execution_available':False,'execution_status':'not_supported','suggested_test':None,'suggested_tool':None})
    return sorted(result,key=lambda item:item['id'])
