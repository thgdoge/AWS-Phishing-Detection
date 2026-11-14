import argparse
import functools
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
if hasattr(sys.stdout, 'reconfigure'):          # Windows: in được tiếng Việt
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

from common.net import Deadline                      # noqa: E402
from common.scoring import build_result, compute_score  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description='Quét thử link/email/file cục bộ')
    ap.add_argument('kind', choices=['link', 'email', 'file'])
    ap.add_argument('target', help='URL, đường dẫn tới file chứa email, hoặc đường dẫn tới tệp')
    ap.add_argument('--offline', action='store_true', help='chỉ phân tích tĩnh, không gọi mạng')
    ap.add_argument('--json', action='store_true', help='in toàn bộ kết quả dạng JSON')
    args = ap.parse_args()
    deadline = Deadline(60)

    if args.kind == 'link':
        from detectors.link import analyze_link
        analysis = analyze_link(args.target, deadline, mode='static' if args.offline else 'full')
    elif args.kind == 'email':
        import detectors.email_msg as em
        if args.offline:
            em.analyze_link = functools.partial(em.analyze_link, mode='static')
        with open(args.target, encoding='utf-8', errors='replace') as fh:
            analysis = em.analyze_email(fh.read(), deadline)
    else:
        from detectors.file import analyze_file
        if not os.path.isfile(args.target):
            sys.exit(f'Không tìm thấy tệp: {args.target}')
        if args.offline:      # bỏ qua VirusTotal/MalwareBazaar bằng cách không đọc key
            for k in ('VT_API_KEY', 'VT_BACKUP_API_KEYS', 'ABUSECH_AUTH_KEY'):
                os.environ.pop(k, None)
        analysis = analyze_file(args.target, os.path.basename(args.target), deadline, allow_upload=False)

    score = compute_score(analysis.findings, reputation_ok=analysis.reputation_ok,
                          reputation_needed=analysis.reputation_needed)
    if args.json:
        print(json.dumps(build_result(score, analysis.details), ensure_ascii=False, indent=2, default=str))
        return
    print(f'\nĐiểm tin cậy : {score.score}/100  ->  {score.risk_level}')
    print(f'Độ tin cậy   : {score.confidence}')
    print('\nLý do:' if score.reasons else '\nKhông phát hiện dấu hiệu bất thường.')
    for r in score.reasons:
        print(f'  - {r}')
    print('\nChi tiết điểm trừ:')
    for s in score.signals:
        print(f'  -{s.penalty:>3}  [{s.category}] {s.code}')
    if not score.signals:
        print('  (không có)')


if __name__ == '__main__':
    main()
