import os
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
INCLUDE_FILES = ['fast_detect_worker.py', 'file_detect_worker.py']
INCLUDE_DIRS = ['common', 'detectors']


def main():
    os.makedirs(os.path.join(ROOT, 'dist'), exist_ok=True)
    out = os.path.join(ROOT, 'dist', 'detect-workers.zip')
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zf:
        for name in INCLUDE_FILES:
            zf.write(os.path.join(ROOT, name), name)
        for d in INCLUDE_DIRS:
            for base, _, files in os.walk(os.path.join(ROOT, d)):
                if '__pycache__' in base:
                    continue
                for f in files:
                    if f.endswith('.py'):
                        full = os.path.join(base, f)
                        zf.write(full, os.path.relpath(full, ROOT))
    print(f'Đã tạo {out} ({os.path.getsize(out) / 1024:.1f} KB)')


if __name__ == '__main__':
    main()
