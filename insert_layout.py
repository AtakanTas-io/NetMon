import re

with open('frontend/app.js', 'r', encoding='utf-8') as f:
    c = f.read()

# Fix layout of panel head for devices page
c = c.replace('<div class="panel-head">', '<div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">')
c = c.replace('<div class="right">', '<div class="right" style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end;">')

with open('frontend/app.js', 'w', encoding='utf-8') as f:
    f.write(c)

print("Layout fixed.")
