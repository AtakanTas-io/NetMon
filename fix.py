import sys
c = open('frontend/app.js', 'r', encoding='utf-8').read()
c = c.replace('|| "question"', '|| "cpu"')
open('frontend/app.js', 'w', encoding='utf-8').write(c)
