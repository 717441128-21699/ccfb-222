import type { Severity } from '../../shared/types';

const LABEL: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '提示',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge ${severity}`}>{LABEL[severity]}</span>;
}

export function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : 2)} ${units[i]}`;
}

export function modeText(mode: number): string {
  return '0' + (mode & 0o7777).toString(8);
}

export function EmptyHint({ text }: { text: string }) {
  return <p className="mut small" style={{ padding: '18px 4px' }}>{text}</p>;
}

export function PageHeader({ title, sub }: { title: string; sub?: string }) {
  return (
    <>
      <h2 className="page-title">{title}</h2>
      {sub && <p className="page-sub">{sub}</p>}
    </>
  );
}
