import sys, xml.etree.ElementTree as ET, glob, os
path = sys.argv[1] if len(sys.argv) > 1 else None
if not path:
    matches = glob.glob('coverage/results/**/coverage.cobertura.xml', recursive=True)
    path = matches[0] if matches else None
if not path:
    print('no coverage.cobertura.xml found')
    sys.exit(1)
print(f"reading: {path}")
tree = ET.parse(path)
root = tree.getroot()
line_rate   = float(root.attrib.get('line-rate', 0))   * 100
branch_rate = float(root.attrib.get('branch-rate', 0)) * 100
print(f"=== Coverage summary ===")
print(f"  line   coverage: {line_rate:6.2f}%")
print(f"  branch coverage: {branch_rate:6.2f}%")
print()
agg = {}
for cls in root.iter('class'):
    name = cls.attrib.get('filename', cls.attrib.get('name', '?'))
    lines = cls.find('lines')
    if lines is None: continue
    line_list = lines.findall('line')
    total = len(line_list)
    covered = sum(1 for l in line_list if int(l.attrib.get('hits', 0)) > 0)
    if name not in agg:
        agg[name] = [0, 0]
    agg[name][0] += covered
    agg[name][1] += total

def short(p):
    for marker in ('IPBanCore\\', 'IPBanCore/', '/IPBanCore/'):
        i = p.rfind(marker)
        if i >= 0: return p[i + (1 if marker.startswith('/') else 0):]
    return p

ranked = sorted(
    ((cov / total * 100 if total else 0, total, short(name)) for name, (cov, total) in agg.items() if total >= 10),
    key=lambda x: (x[0], -x[1]))
print("=== 40 files with the lowest line coverage (>=10 lines) ===")
print(f"  {'cov%':>6}  {'lines':>5}  file")
for rate, total, name in ranked[:40]:
    print(f"  {rate:6.2f}  {total:5d}  {name}")
ranked_by_uncovered = sorted(
    (((total - cov), cov / total * 100 if total else 0, total, short(name)) for name, (cov, total) in agg.items() if total >= 30),
    key=lambda x: -x[0])
print()
print("=== 30 files with the most uncovered lines (>=30 total) ===")
print(f"  {'uncov':>5}  {'cov%':>6}  {'lines':>5}  file")
for uncov, rate, total, name in ranked_by_uncovered[:30]:
    print(f"  {uncov:5d}  {rate:6.2f}  {total:5d}  {name}")
