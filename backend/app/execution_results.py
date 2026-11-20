"""Bounded original evidence storage and host-discovery-only processing."""
from datetime import datetime, timezone
from hashlib import sha256
import os
import re
from pathlib import Path
from uuid import uuid4
import xml.etree.ElementTree as ET

from sqlalchemy import select

from .baseline_catalog import fingerprint
from .models import ScannerEvidence, ResultProcessingOutcome, SecurityObservation

MAX_OUTPUT = 10 * 1024 * 1024


def parse_discovery(content, target):
    if len(content) > MAX_OUTPUT:
        raise ValueError('evidence_limit_exceeded')
    # Nmap emits this inert declaration itself. No internal/external subsets,
    # entities, alternate encodings or other DTD declarations are accepted.
    if content.count(b'<!DOCTYPE nmaprun>') == 1:
        content = content.replace(b'<!DOCTYPE nmaprun>', b'', 1)
    if (not content or len(content) > MAX_OUTPUT or b'<!DOCTYPE' in content.upper()
            or b'<!ENTITY' in content.upper() or b'\x00' in content):
        raise ValueError('unsafe_or_missing_xml')
    try:
        parser = ET.XMLPullParser(events=('start', 'end'))
        root, count, depth = None, 0, 0
        for offset in range(0, len(content), 8192):
            parser.feed(content[offset:offset+8192])
            for action, node in parser.read_events():
                if action == 'start':
                    count += 1
                    depth += 1
                    if root is None:
                        root = node
                    if count > 5000 or depth > 32:
                        raise ValueError('xml_complexity_exceeded')
                    if node.tag in ('ports', 'port', 'script', 'os', 'trace'):
                        raise ValueError('unsupported_result_type')
                else:
                    depth -= 1
        parser.close()
    except ET.ParseError as exc:
        raise ValueError('malformed_xml') from exc
    if root is None or root.tag != 'nmaprun' or root.get('scanner') != 'nmap':
        raise ValueError('unexpected_scanner_output')
    finished = root.find('runstats/finished')
    totals = root.find('runstats/hosts')
    if (finished is None or finished.get('exit') != 'success' or totals is None
            or totals.get('total') != '1'
            or (totals.get('up'), totals.get('down')) not in (('1', '0'), ('0', '1'))):
        raise ValueError('incomplete_discovery_result')
    hosts = root.findall('host')
    if len(hosts) > 1:
        raise ValueError('unexpected_discovered_target')
    if hosts:
        host = hosts[0]
        addresses = host.findall('address')
        ipv4 = [address.get('addr') for address in addresses if address.get('addrtype') == 'ipv4']
        if ipv4 != [target] or host.findall('hostnames/hostname'):
            raise ValueError('unexpected_discovered_target')
        status = host.find('status')
        if status is None or status.get('state') not in ('up', 'down'):
            raise ValueError('invalid_host_status')
        state = status.get('state')
        if (state == 'up') != (totals.get('up') == '1'):
            raise ValueError('inconsistent_discovery_result')
    else:
        if totals.get('down') != '1':
            raise ValueError('missing_host_result')
        state = 'down'
    return {'address': target, 'status': state}


def parse_services(content, target, ports):
    """Only complete, explicitly probed TCP service identifications are facts.

    Version NSE output is retained in original XML, never promoted to an
    observation. Port numbers/table guesses do not establish an HTTP service.
    """
    from .nmap_service_profile import plan
    plan(target, ports)
    if len(content) > MAX_OUTPUT:
        raise ValueError('evidence_limit_exceeded')
    if content.count(b'<!DOCTYPE nmaprun>') == 1:
        content = content.replace(b'<!DOCTYPE nmaprun>', b'', 1)
    if not content or b'<!DOCTYPE' in content.upper() or b'<!ENTITY' in content.upper() or b'\x00' in content:
        raise ValueError('unsafe_or_missing_xml')
    try:
        parser = ET.XMLPullParser(events=('start', 'end'))
        root, count, depth = None, 0, 0
        for offset in range(0, len(content), 8192):
            parser.feed(content[offset:offset + 8192])
            for action, node in parser.read_events():
                if action == 'start':
                    count += 1
                    depth += 1
                    if root is None:
                        root = node
                    if count > 5000 or depth > 32:
                        raise ValueError('xml_complexity_exceeded')
                else:
                    depth -= 1
        parser.close()
    except ET.ParseError as exc:
        raise ValueError('malformed_xml') from exc
    if root is None or root.tag != 'nmaprun' or root.get('scanner') != 'nmap':
        raise ValueError('unexpected_scanner_output')
    finished, totals = root.find('runstats/finished'), root.find('runstats/hosts')
    if (finished is None or finished.get('exit') != 'success' or totals is None
            or totals.get('total') != '1'
            or (totals.get('up'), totals.get('down')) not in (('1', '0'), ('0', '1'))):
        raise ValueError('incomplete_service_result')
    hosts = root.findall('host')
    if len(hosts) != 1:
        raise ValueError('unexpected_discovered_target')
    host = hosts[0]
    if ([a.get('addr') for a in host.findall('address') if a.get('addrtype') == 'ipv4'] != [target]
            or host.findall('hostnames/hostname') or len(host.findall('ports')) > 1):
        raise ValueError('unexpected_discovered_target')
    status = host.find('status')
    if (status is None or status.get('state') not in ('up', 'down')
            or (status.get('state') == 'up') != (totals.get('up') == '1')):
        raise ValueError('inconsistent_service_result')
    found, seen = [], set()
    for node in host.findall('ports/port'):
        try:
            port = int(node.get('portid', ''))
        except ValueError as exc:
            raise ValueError('invalid_service_port') from exc
        if node.get('protocol') != 'tcp' or port not in ports or port in seen:
            raise ValueError('unauthorized_service_port')
        seen.add(port)
        states, services = node.findall('state'), node.findall('service')
        if len(states) != 1 or len(services) > 1:
            raise ValueError('ambiguous_service_result')
        if states[0].get('state') != 'open' or not services:
            continue
        if status.get('state') != 'up':
            raise ValueError('inconsistent_service_result')
        service = services[0]
        if service.get('method') != 'probed' or service.get('conf') not in ('7', '8', '9', '10'):
            continue
        name, tunnel = service.get('name'), service.get('tunnel')
        if (not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.+-]{0,79}', name)
                or name == 'unknown' or tunnel not in (None, 'ssl')):
            continue
        fact = {'address': target, 'port': port, 'state': 'open', 'transport': 'tcp',
                'service': 'https' if name == 'http' and tunnel == 'ssl' else name}
        version = service.get('version')
        if version:
            if len(version) > 120 or any(ord(c) < 32 or ord(c) == 127 for c in version):
                raise ValueError('invalid_service_version')
            fact['version'] = version
        found.append(fact)
    return sorted(found, key=lambda fact: fact['port'])


class EvidenceStore:
    def __init__(self, root):
        self.root = Path(root)
        if (not self.root.is_absolute() or self.root.resolve(strict=True) != self.root
                or not self.root.is_dir()):
            raise ValueError('invalid_evidence_directory')
        info = self.root.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('private_worker_owned_evidence_directory_required')

    def write(self, content):
        # Database stores only opaque keys; no caller-controlled path fragments.
        name = uuid4().hex
        fd = os.open(self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(self.root, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return f'evidence/{name}'


def evidence(db, attempt, content, format, partial, store):
    if len(content) > MAX_OUTPUT:
        raise ValueError('evidence_limit_exceeded')
    digest = sha256(content).hexdigest()
    existing = db.scalar(select(ScannerEvidence).where(
        ScannerEvidence.attempt_id == attempt.id, ScannerEvidence.format == format,
        ScannerEvidence.content_hash == digest, ScannerEvidence.is_partial == partial))
    if existing is not None:
        return existing
    inline = len(content) <= 1048576
    row = ScannerEvidence(attempt_id=attempt.id, request_id=attempt.request_id,
        assessment_id=attempt.assessment_id, target_id=attempt.target_id, tool='Nmap',
        format=format, content=content if inline else None,
        storage_key=None if inline else store.write(content), content_hash=digest,
        size_bytes=len(content), is_partial=partial, collected_at=datetime.now(timezone.utc))
    db.add(row)
    db.flush()
    return row


def process(db, attempt, source, content):
    """Caller locks request and attempt; observations and result commit together."""
    if (source.attempt_id != attempt.id or source.request_id != attempt.request_id
            or source.assessment_id != attempt.assessment_id or source.target_id != attempt.target_id
            or source.tool != 'Nmap' or source.format != 'nmap-xml'):
        raise ValueError('evidence_provenance_mismatch')
    service = attempt.profile_id == 'service-discovery'
    processor = 'nmap-service-discovery' if service else 'nmap-host-discovery'
    version = '1' if service else '2'
    prior = db.scalar(select(ResultProcessingOutcome).where(
        ResultProcessingOutcome.evidence_id == source.id,
        ResultProcessingOutcome.processor == processor,
        ResultProcessingOutcome.processor_version == version).order_by(ResultProcessingOutcome.run_number.desc()))
    if prior is not None and prior.status == 'Succeeded':
        return prior
    row = ResultProcessingOutcome(evidence_id=source.id, attempt_id=attempt.id,
        request_id=attempt.request_id, assessment_id=attempt.assessment_id, target_id=attempt.target_id,
        processor=processor, processor_version=version, run_number=1 if prior is None else prior.run_number+1,
        operation_id=uuid4(), status='Pending', is_partial=source.is_partial, observation_count=0)
    db.add(row)
    db.flush()
    row.status = 'Processing'
    row.started_at = datetime.now(timezone.utc)
    db.flush()
    try:
        if sha256(content).hexdigest() != source.content_hash or source.is_partial:
            raise ValueError('partial_or_invalid_evidence')
        if service:
            from .nmap_service_profile import validate_plan
            if not validate_plan(attempt.parameters):
                raise ValueError('invalid_service_plan')
            results = parse_services(content, attempt.parameters['target'], attempt.parameters['ports'])
        else:
            results = [parse_discovery(content, attempt.parameters['target'])]
    except ValueError as exc:
        row.status = 'Failed'
        row.error_code = str(exc)
        row.safe_diagnostic = 'Discovery result could not be verified.'
    else:
        for result in results:
            key = fingerprint(result)
            existing = db.scalar(select(SecurityObservation).where(
                SecurityObservation.evidence_id == source.id, SecurityObservation.deduplication_key == key))
            if existing is None:
                db.add(SecurityObservation(processing_id=row.id, evidence_id=source.id,
                    attempt_id=attempt.id, request_id=attempt.request_id, assessment_id=attempt.assessment_id,
                    target_id=attempt.target_id, observation_type='service_discovery' if service else 'host_discovery', data=result,
                    deduplication_key=key, collected_at=source.collected_at,
                    processed_at=datetime.now(timezone.utc), is_partial=False))
                db.flush()
                row.observation_count += 1
        row.status = 'Succeeded'
    row.finished_at = datetime.now(timezone.utc)
    db.flush()
    return row
