import os
from datetime import datetime
from html import escape

from ..scanners.base import ScanResult, Severity


def export_html_report(results: dict[str, list[ScanResult]]) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"system_threat_report_{timestamp}.html"
    path = os.path.join(os.path.expanduser("~"), "Desktop", filename)

    all_items: list[tuple[str, ScanResult]] = []
    for source, items in results.items():
        for item in items:
            all_items.append((source, item))

    total = len(all_items)
    danger = sum(1 for _, i in all_items if i.severity == Severity.DANGER)
    warn = sum(1 for _, i in all_items if i.severity == Severity.WARNING)
    safe = total - danger - warn

    color_map = {Severity.SAFE: "#9ece6a", Severity.WARNING: "#e0af68", Severity.DANGER: "#f7768e"}
    label_map = {Severity.SAFE: "安全", Severity.WARNING: "可疑", Severity.DANGER: "危险"}

    rows_html = ""
    for source, item in all_items:
        color = color_map.get(item.severity, "#c0caf5")
        label = label_map.get(item.severity, "?")
        rows_html += f"""<tr>
<td><span style="color:{color};font-weight:bold">{escape(label)}</span></td>
<td>{escape(source)}</td>
<td>{escape(item.name)}</td>
<td style="color:#565f89">{escape(item.detail)}</td>
</tr>
"""

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>系统危险排查报告 - {datetime.now().strftime("%Y-%m-%d %H:%M")}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: #1a1b26; color: #c0caf5; font-family: "Microsoft YaHei", "Segoe UI", sans-serif; padding: 32px; }}
h1 {{ color: #7aa2f7; margin-bottom: 8px; }}
.subtitle {{ color: #565f89; margin-bottom: 24px; }}
.stats {{ display: flex; gap: 16px; margin-bottom: 24px; }}
.stat-card {{ background: #24283b; border-radius: 10px; padding: 16px 24px; text-align: center; flex: 1; }}
.stat-card .num {{ font-size: 28px; font-weight: bold; }}
.stat-card .label {{ font-size: 12px; color: #565f89; margin-top: 4px; }}
table {{ width: 100%; border-collapse: collapse; background: #24283b; border-radius: 8px; overflow: hidden; }}
th {{ background: #16161e; text-align: left; padding: 10px 12px; font-size: 13px; color: #565f89; }}
td {{ padding: 10px 12px; border-top: 1px solid #2f3549; font-size: 13px; }}
tr:hover {{ background: #2a2e42; }}
</style>
</head>
<body>
<h1>系统危险排查报告</h1>
<p class="subtitle">生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<div class="stats">
<div class="stat-card"><div class="num" style="color:#c0caf5">{total}</div><div class="label">总计</div></div>
<div class="stat-card"><div class="num" style="color:#9ece6a">{safe}</div><div class="label">安全</div></div>
<div class="stat-card"><div class="num" style="color:#e0af68">{warn}</div><div class="label">可疑</div></div>
<div class="stat-card"><div class="num" style="color:#f7768e">{danger}</div><div class="label">危险</div></div>
</div>
<table>
<thead><tr><th>等级</th><th>来源</th><th>名称</th><th>详情</th></tr></thead>
<tbody>
{rows_html}
</tbody>
</table>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
