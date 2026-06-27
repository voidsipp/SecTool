import re, io
p = 'src/analytics/alertFeed.ts'
s = io.open(p, encoding='utf-8').read()
# Use ASCII-only \u escapes in the JS regex (valid in JS, safe in source).
new_class = '/[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\uFFFE\\uFFFF]/g'
s2 = re.sub(r'return s\.replace\(/\[.*?\]/g, ""\);',
            'return s.replace(' + new_class + ', "");',
            s, count=1)
s2 = s2.replace('  // Disallowed: most C0 controls except tab/newline/carriage-return.',
                '  // Strip C0 controls disallowed by XML 1.0 (everything except tab/LF/CR)\n  // plus the FFFE/FFFF noncharacters; they are invalid even when escaped.')
assert s2 != s, "no change made"
io.open(p, 'w', encoding='utf-8', newline='\n').write(s2)
print("ok")
