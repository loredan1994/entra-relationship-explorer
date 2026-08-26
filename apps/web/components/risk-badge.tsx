import type { RiskLevel } from "@entra-explorer/domain";

export function RiskBadge({ level, reason }: { level: RiskLevel; reason: string }) {
  const label = level === "low" ? "Low" : level === "review" ? "Review" : "High";
  return (
    <span className={`risk-badge risk-${level}`} title={reason}>
      <span aria-hidden="true" />
      {label}
    </span>
  );
}
