import re
with open('frontend/app.js', 'r', encoding='utf-8') as f:
    content = f.read()
idx1 = content.find('async function refreshSecurity()')
idx2 = content.find('function runSecurityScan()')
print(idx1, idx2)
