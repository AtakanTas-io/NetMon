import re
c = open('frontend/app.js', 'r', encoding='utf-8').read()
old_str = 'let tableHead = <tr><th>Durum</th><th>Hostname</th><th>IP</th><th>MAC</th><th>Üretici</th><th>Tip</th><th>Son Görülme</th><th>İşlemler</th></tr>;'
new_str = 'let tableHead = <tr><th>Durum</th><th>IP</th><th>Hostname</th><th>Tip</th><th>MAC</th><th>Gecikme</th><th>Son Görülme</th><th>İşlemler</th></tr>;'
c = c.replace(old_str, new_str)
open('frontend/app.js', 'w', encoding='utf-8').write(c)
