#!/usr/bin/env bash
# Run the IPBan test suite under coverlet and produce raw + HTML coverage reports.
# Usage:
#   coverage/run.sh                                  # all tests
#   coverage/run.sh "Category!=LinuxIntegrationSlow" # pass-through filter
#
# Outputs (all under the coverage/ folder so the repo root stays clean):
#   coverage/results/<guid>/coverage.cobertura.xml   raw report
#   coverage/report/index.html                       HTML report (if reportgenerator is installed)

set -euo pipefail

# Resolve repo root regardless of where the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

FILTER="${1:-}"

# install reportgenerator if missing
if ! command -v reportgenerator >/dev/null 2>&1; then
  if command -v dotnet >/dev/null 2>&1; then
    echo ">> installing dotnet-reportgenerator-globaltool"
    dotnet tool install -g dotnet-reportgenerator-globaltool || true
    export PATH="$PATH:$HOME/.dotnet/tools"
  fi
fi

# clear old results so we don't aggregate across runs
rm -rf coverage/results coverage/report
mkdir -p coverage/results

echo ">> running tests with coverage collection"
TEST_ARGS=(
  "IPBanTests/IPBanTests.csproj"
  "--collect:XPlat Code Coverage"
  "--settings" "$SCRIPT_DIR/coverlet.runsettings"
  "--results-directory" "$REPO_ROOT/coverage/results"
  "-c" "Release"
  "--logger" "console;verbosity=minimal"
)
if [ -n "$FILTER" ]; then
  TEST_ARGS+=("--filter" "$FILTER")
fi
dotnet test "${TEST_ARGS[@]}"

# locate the cobertura xml the collector wrote
COBERTURA="$(find coverage/results -name 'coverage.cobertura.xml' | head -n1)"
if [ -z "$COBERTURA" ]; then
  echo ">> ERROR: no coverage.cobertura.xml produced — check that coverlet.collector is referenced in IPBanTests.csproj"
  exit 1
fi
echo ">> raw report: $COBERTURA"

# print a quick text summary using the cobertura XML
python3 - "$COBERTURA" <<'PY'
import sys, xml.etree.ElementTree as ET
path = sys.argv[1]
tree = ET.parse(path)
root = tree.getroot()
line_rate   = float(root.attrib.get('line-rate', 0))   * 100
branch_rate = float(root.attrib.get('branch-rate', 0)) * 100
print()
print(f"=== Coverage summary ===")
print(f"  line   coverage: {line_rate:6.2f}%")
print(f"  branch coverage: {branch_rate:6.2f}%")
print()
# print bottom 15 files by line coverage so gaps are obvious
# Aggregate by file (cobertura emits one <class> per type, so a file with multiple types
# shows up multiple times — we collapse by filename).
agg = {}  # filename -> [covered_lines, total_lines]
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

# Strip the long github.com prefix if SourceLink is enabled
def short(p):
    for marker in ('IPBanCore/', '/IPBanCore/'):
        i = p.rfind(marker)
        if i >= 0: return p[i + (1 if marker.startswith('/') else 0):]
    return p

# 20 files with the lowest line coverage (>= 10 lines, to skip trivial cases)
ranked = sorted(
    ((cov / total * 100 if total else 0, total, short(name)) for name, (cov, total) in agg.items() if total >= 10),
    key=lambda x: (x[0], -x[1]))
print("=== 20 files with the lowest line coverage (>=10 lines) ===")
print(f"  {'cov%':>6}  {'lines':>5}  file")
for rate, total, name in ranked[:20]:
    print(f"  {rate:6.2f}  {total:5d}  {name}")
# Also show files with low coverage AND many lines — these are the highest-leverage targets
ranked_by_uncovered = sorted(
    (((total - cov), cov / total * 100 if total else 0, total, short(name)) for name, (cov, total) in agg.items() if total >= 30),
    key=lambda x: -x[0])
print()
print("=== 15 files with the most uncovered lines (>=30 total) ===")
print(f"  {'uncov':>5}  {'cov%':>6}  {'lines':>5}  file")
for uncov, rate, total, name in ranked_by_uncovered[:15]:
    print(f"  {uncov:5d}  {rate:6.2f}  {total:5d}  {name}")
PY

# render HTML if reportgenerator is available
if command -v reportgenerator >/dev/null 2>&1; then
  echo ">> generating HTML report at coverage/report/index.html"
  reportgenerator \
    -reports:"$COBERTURA" \
    -targetdir:coverage/report \
    -reporttypes:"Html;Badges;TextSummary" \
    >/dev/null
  echo ">> open coverage/report/index.html in a browser"
else
  echo ">> reportgenerator not on PATH — skipped HTML render"
fi
