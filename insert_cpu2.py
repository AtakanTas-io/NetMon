import re

with open('frontend/app.js', 'r', encoding='utf-8') as f:
    c = f.read()

# Fix 1: unknown property
c = c.replace('unknown: "question",', 'unknown: "cpu",')

# Fix 2: the ICON definition
cpu_icon = "  cpu: '<rect x=\"4\" y=\"4\" width=\"16\" height=\"16\" rx=\"2\" ry=\"2\"></rect><rect x=\"9\" y=\"9\" width=\"6\" height=\"6\"></rect><line x1=\"9\" y1=\"1\" x2=\"9\" y2=\"4\"></line><line x1=\"15\" y1=\"1\" x2=\"15\" y2=\"4\"></line><line x1=\"9\" y1=\"20\" x2=\"9\" y2=\"23\"></line><line x1=\"15\" y1=\"20\" x2=\"15\" y2=\"23\"></line><line x1=\"20\" y1=\"9\" x2=\"23\" y2=\"9\"></line><line x1=\"20\" y1=\"14\" x2=\"23\" y2=\"14\"></line><line x1=\"1\" y1=\"9\" x2=\"4\" y2=\"9\"></line><line x1=\"1\" y1=\"14\" x2=\"4\" y2=\"14\"></line>',\n  check:"
c = c.replace('  check:', cpu_icon)

# Fix 3: replace fallback string
c = c.replace('|| "question"', '|| "cpu"')

with open('frontend/app.js', 'w', encoding='utf-8') as f:
    f.write(c)

print("Icons replaced.")
