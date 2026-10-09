"""Check local Markdown targets without network access."""
import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
bad, checked = [], 0
for p in ROOT.rglob('*.md'):
    if any(x in p.parts for x in ('.git','.venv','outputs','14_조사')):
        continue
    for href in re.findall(r'\]\(([^\s)]+)(?:\s+"[^"]*")?\)',p.read_text(encoding='utf-8-sig')):
        if href.startswith(('http:','https:','mailto:','#')):
            continue
        target = href.split('#')[0]
        checked += 1
        if not (p.parent / unquote(target)).exists():
            bad.append((str(p.relative_to(ROOT)),href))
if bad:
    raise SystemExit(f'Broken local links: {bad}')
print(f'PASS: {checked} local Markdown links.')
