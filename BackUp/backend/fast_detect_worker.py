from common.pipeline import Outcome, process_event
from common.scoring import build_result, compute_score
from detectors.email_msg import analyze_email
from detectors.link import analyze_link


def analyze(body, deadline, store):
    scan_type, payload = body.get('type'), body.get('payload')
    if not isinstance(payload, str) or not payload.strip():
        raise ValueError('Payload rỗng')
    if scan_type == 'link':
        analysis = analyze_link(payload, deadline)
    elif scan_type == 'email':
        analysis = analyze_email(payload, deadline)
    else:
        raise ValueError(f'Loại đầu vào không hỗ trợ: {scan_type}')

    score = compute_score(analysis.findings, reputation_ok=analysis.reputation_ok,
                          reputation_needed=analysis.reputation_needed)
    return Outcome(build_result(score, analysis.details), cache_key=body.get('target_hash'))


def lambda_handler(event, context):
    return process_event(event, context, analyze)
