"""Extract the official auth-key worked-example values.

One-shot provenance tool: parses the saved sample page and prints the
g_a / b / g_b / dh_prime / auth_key hex strings as a key=value stream
suitable for kat_values.txt. Progress notes go to stderr.

    cd td && python3 extract_kat.py > kat_values.txt
"""

import re
import sys

html = open('tests/data/auth_key_sample.html').read()

def block(name):
    m = re.search(r'<!-- start %s -->\s*<pre><code>(.*?)</code></pre>' % name, html, re.S)
    return m.group(1).strip() if m else None

def hexrun(v):
    if v is None:
        return None
    m = re.search(r'([0-9A-F]{400,})', v)
    return m.group(1) if m else None

def table_row(label):
    # <td>LABEL</td> ... <td><code>HEX</code> <code>HEX</code>...</td> ... </tr>
    m = re.search(r'<td>%s</td>(.*?)</tr>' % label, html, re.S)
    if not m:
        return None
    row = m.group(1)
    chunks = re.findall(r'<code>([0-9A-F]+)</code>', row)
    return ''.join(chunks)

b = hexrun(block('b'))
g_b = hexrun(block('g_b'))
auth_key = hexrun(block('auth_key'))
g_a = table_row('g_a')
dh_prime = table_row('dh_prime')

for k, v in [('g_a', g_a), ('b', b), ('g_b', g_b), ('dh_prime', dh_prime), ('auth_key', auth_key)]:
    if v and v.startswith('FE000100'):
        v = v[len('FE000100'):]
    print('%s %s %s' % (k, len(v) if v else None, (v[:20] + '...') if v else ''), file=sys.stderr)
    if v:
        print('%s=%s' % (k, v))
