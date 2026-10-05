import type { SVGProps } from "react";

import type { FormatFamily } from "../engine/types";

type IconProps = SVGProps<SVGSVGElement>;

const base = {
  width: 20,
  height: 20,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

export function AirlockMark(props: IconProps) {
  return (
    <svg viewBox="0 0 32 32" width={28} height={28} aria-hidden {...props}>
      <rect x="1" y="1" width="30" height="30" rx="8" fill="var(--mark-bg)" />
      <circle cx="16" cy="16" r="8.4" fill="none" stroke="var(--accent)" strokeWidth="2" />
      <rect x="9.4" y="15" width="13.2" height="2" rx="1" fill="var(--mark-fg)" />
      <circle cx="16" cy="16" r="0.75" fill="var(--mark-bg)" />
    </svg>
  );
}

export function UploadIcon(props: IconProps) {
  return (
    <svg {...base} width={28} height={28} {...props}>
      <path d="M12 15V4" />
      <path d="m7.5 8.5 4.5-4.5 4.5 4.5" />
      <path d="M4 14v3.5A2.5 2.5 0 0 0 6.5 20h11a2.5 2.5 0 0 0 2.5-2.5V14" />
    </svg>
  );
}

export function CheckIcon(props: IconProps) {
  return (
    <svg {...base} width={16} height={16} strokeWidth={2} {...props}>
      <path d="m5 12.5 4.5 4.5L19 7.5" />
    </svg>
  );
}

export function AlertIcon(props: IconProps) {
  return (
    <svg {...base} {...props}>
      <path d="M12 3.5 2.8 19.5h18.4L12 3.5Z" />
      <path d="M12 10v4.2" />
      <path d="M12 17.2h.01" />
    </svg>
  );
}

export function CloseIcon(props: IconProps) {
  return (
    <svg {...base} width={16} height={16} {...props}>
      <path d="M6 6l12 12M18 6 6 18" />
    </svg>
  );
}

export function ChevronIcon(props: IconProps) {
  return (
    <svg {...base} width={16} height={16} {...props}>
      <path d="m6 9 6 6 6-6" />
    </svg>
  );
}

export function FamilyIcon({ family, ...props }: IconProps & { family: FormatFamily }) {
  switch (family) {
    case "spreadsheet":
      return (
        <svg {...base} {...props}>
          <rect x="4" y="4" width="16" height="16" rx="2.5" />
          <path d="M4 9.5h16M4 14.5h16M10 9.5V20" />
        </svg>
      );
    case "presentation":
      return (
        <svg {...base} {...props}>
          <rect x="3.5" y="4.5" width="17" height="11" rx="2" />
          <path d="M12 15.5V20M8.5 20h7" />
        </svg>
      );
    case "image":
      return (
        <svg {...base} {...props}>
          <rect x="3.5" y="4.5" width="17" height="15" rx="2.5" />
          <circle cx="9" cy="10" r="1.6" />
          <path d="m20.5 16-4.8-4.8L6 19.5" />
        </svg>
      );
    case "code":
    case "config":
      return (
        <svg {...base} {...props}>
          <path d="m9 8-4 4 4 4M15 8l4 4-4 4" />
        </svg>
      );
    default:
      return (
        <svg {...base} {...props}>
          <path d="M14 3.5H7.5a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2V8L14 3.5Z" />
          <path d="M14 3.5V8h4.5M9 12.5h6M9 16h4" />
        </svg>
      );
  }
}
