import re

with open('frontend/app.js', 'r', encoding='utf-8') as f:
    c = f.read()

import sys
lines = c.split('\n')
for i, line in enumerate(lines):
    if 'id="devFilter"' in line:
        lines[i] = '            <button class="mini-btn" style="background:#10b981;border-color:#059669;color:white;margin-right:8px;" onclick="window.open(\'/api/export/devices\', \'_blank\')">📊 Excel\'e Aktar</button>\n' + line
        break

with open('frontend/app.js', 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))
print("Button added.")
