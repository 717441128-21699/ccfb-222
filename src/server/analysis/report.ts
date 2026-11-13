// 独立 HTML 报告:内联 CSS,无外部资源,可直接发给同事或归档
import type { FirmwareMeta, Finding, Severity } from '../../shared/types.js';
import { humanSize, hex } from '../../shared/magic.js';

function esc(s: string | number | undefined | null): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const SEV_LABEL: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '提示',
};

function sevClass(s: Severity): string {
  return `sev sev-${s}`;
}

function findingRows(list: Finding[]): string {
  if (list.length === 0) return '<tr><td colspan="6" class="empty">无</td></tr>';
  return list
    .map(
      (f) => `<tr>
      <td><span class="${sevClass(f.severity)}">${SEV_LABEL[f.severity]}</span></td>
      <td>${esc(f.category)}</td>
      <td>${esc(f.title)}</td>
      <td class="mono">${esc(f.path)}${f.line ? ':' + f.line : ''}</td>
      <td class="mono small">${esc(f.evidence)}</td>
      <td class="small">${esc(f.advice)}</td>
    </tr>`
    )
    .join('');
}

export function buildHtmlReport(meta: FirmwareMeta): string {
  const a = meta.analysis;
  const findings = a?.findings ?? [];
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => counts[f.severity]++);
  const sorted = [...findings].sort((x, y) => severityRank(x.severity) - severityRank(y.severity));

  const segRows = (a?.segments ?? [])
    .map(
      (s) => `<tr>
      <td class="mono">${hex(s.offset)}</td>
      <td class="mono">${humanSize(s.size)}${s.sizeIsEstimate ? ' *' : ''}</td>
      <td>${esc(s.type)}</td>
      <td>${esc(s.label)}</td>
      <td class="small">${esc((s.warnings ?? []).concat(s.error ? [s.error] : []).join('; '))}</td>
    </tr>`
    )
    .join('');

  const compRows = (a?.components ?? [])
    .map(
      (c) => `<tr>
      <td>${esc(c.name)}</td><td class="mono">${esc(c.version)}</td>
      <td class="mono small">${esc(c.path)}</td>
      <td>${c.vulns.length ? c.vulns.map((v) => `<span class="${sevClass(v.severity)}">${esc(v.cve)}</span>`).join(' ') : '<span class="ok">未命中</span>'}</td>
    </tr>`
    )
    .join('') || '<tr><td colspan="4" class="empty">未识别到已知组件</td></tr>';

  const svcRows = (a?.services ?? [])
    .map(
      (s) => `<tr class="${s.risky ? 'row-risk' : ''}">
      <td>${esc(s.name)}</td><td>${s.port ?? '-'}/${esc(s.proto)}</td>
      <td class="mono small">${esc(s.source)}</td>
      <td>${s.risky ? '<span class="sev sev-medium">风险</span> ' + esc(s.reason ?? '') : '<span class="ok">正常</span>'}</td>
    </tr>`
    )
    .join('') || '<tr><td colspan="4" class="empty">未从启动脚本提取到服务</td></tr>';

  const warnItems = (a?.warnings ?? []).map((w) => `<li>${esc(w)}</li>`).join('') || '<li class="empty">无</li>';

  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>固件分析报告 - ${esc(meta.originalName)}</title>
<style>
:root{--bg:#0f1420;--card:#171e2e;--line:#26314a;--fg:#e6ebf5;--mut:#8a97ad;--accent:#4f8cff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 "Segoe UI","Microsoft YaHei",sans-serif;padding:32px}
.wrap{max-width:1180px;margin:0 auto}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.meta{color:var(--mut);font-size:13px;margin-bottom:24px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 18px;min-width:120px}
.card .n{font-size:26px;font-weight:700}.card .l{color:var(--mut);font-size:12px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#1d2740;font-weight:600;font-size:12px;color:var(--mut)}
tr:last-child td{border-bottom:none}.mono{font-family:Consolas,Menlo,monospace}.small{font-size:12px;color:var(--mut)}
.empty{color:var(--mut);text-align:center}.row-risk{background:rgba(255,120,80,.07)}
.sev{display:inline-block;padding:2px 8px;border-radius:20px;font-size:12px;font-weight:600;white-space:nowrap}
.sev-critical{background:#4a1525;color:#ff8aa0}.sev-high{background:#4a2a15;color:#ffb38a}
.sev-medium{background:#4a4115;color:#ffe08a}.sev-low{background:#1f3a4a;color:#8fd0ff}.sev-info{background:#26314a;color:#aebcd4}
.ok{color:#7fd6a0}.foot{margin-top:40px;color:var(--mut);font-size:12px;border-top:1px solid var(--line);padding-top:16px}
ul{padding-left:20px}
</style></head><body><div class="wrap">
<h1>固件安全分析报告</h1>
<div class="meta">文件:${esc(meta.originalName)} ｜ 大小:${humanSize(meta.size)} ｜ SHA-256:<span class="mono">${esc(meta.sha256)}</span><br>
上传时间:${esc(meta.uploadedAt)}${meta.note ? ' ｜ 备注:' + esc(meta.note) : ''}</div>

<div class="cards">
  ${(['critical', 'high', 'medium', 'low', 'info'] as Severity[])
    .map((s) => `<div class="card"><div class="n">${counts[s]}</div><div class="l">${SEV_LABEL[s]}</div></div>`)
    .join('')}
  <div class="card"><div class="n">${a?.stats.fileCount ?? 0}</div><div class="l">文件数</div></div>
  <div class="card"><div class="n">${a?.components.length ?? 0}</div><div class="l">识别组件</div></div>
</div>

<h2>1. 分区结构</h2>
<table><thead><tr><th>偏移</th><th>大小</th><th>类型</th><th>说明</th><th>告警</th></tr></thead>
<tbody>${segRows || '<tr><td colspan="5" class="empty">无</td></tr>'}</tbody></table>
<p class="small">* 估算大小:段未声明长度或镜像被截断,按镜像边界估算</p>

<h2>2. 组件与漏洞比对(离线库)</h2>
<table><thead><tr><th>组件</th><th>版本</th><th>路径</th><th>命中 CVE</th></tr></thead><tbody>${compRows}</tbody></table>

<h2>3. 服务与端口</h2>
<table><thead><tr><th>服务</th><th>端口</th><th>来源脚本</th><th>评估</th></tr></thead><tbody>${svcRows}</tbody></table>

<h2>4. 风险发现(${findings.length} 项)</h2>
<table><thead><tr><th>等级</th><th>分类</th><th>问题</th><th>位置</th><th>证据</th><th>建议</th></tr></thead>
<tbody>${findingRows(sorted)}</tbody></table>

<h2>5. 解析告警</h2><ul>${warnItems}</ul>

<div class="foot">由本地固件分析台生成,所有分析均在本机完成,镜像未外传。生成时间:${esc(new Date().toISOString())}</div>
</div></body></html>`;
}

function severityRank(s: Severity): number {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s];
}
