import type { KeyboardEvent } from "react";

import type { InspectResult } from "../engine/types";
import { fileNameFromPath, formatBytes } from "../lib/format";
import { CheckIcon, CloseIcon, FamilyIcon, UploadIcon } from "./icons";

export type Selection =
  | { status: "empty" }
  | { status: "inspecting"; path: string }
  | { status: "verified"; path: string; result: InspectResult }
  | { status: "rejected"; path: string };

const FORMAT_CHIPS = ["PDF", "DOCX", "XLSX", "PPTX", "TXT", "CSV", "Images"];

interface Props {
  selection: Selection;
  hovering: boolean;
  disabled: boolean;
  onBrowse: () => void;
  onClear: () => void;
}

export function DropZone({ selection, hovering, disabled, onBrowse, onClear }: Props) {
  if (selection.status !== "empty") {
    return <FileCard selection={selection} hovering={hovering} onReplace={onBrowse} onClear={onClear} />;
  }

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onBrowse();
    }
  };

  return (
    <div
      className="dropzone"
      data-hovering={hovering || undefined}
      data-disabled={disabled || undefined}
      role="button"
      tabIndex={0}
      aria-label="Drop files here, or press Enter to choose a file"
      onClick={onBrowse}
      onKeyDown={onKeyDown}
    >
      <div className="dropzone__icon">
        <UploadIcon />
      </div>
      <p className="dropzone__title">{hovering ? "Release to load file" : "Drop files here"}</p>
      <p className="dropzone__hint">
        or <span className="link">browse your computer</span>
      </p>
      <ul className="chips" aria-label="Supported formats">
        {FORMAT_CHIPS.map((chip) => (
          <li key={chip} className="chip">
            {chip}
          </li>
        ))}
      </ul>
    </div>
  );
}

function FileCard({
  selection,
  hovering,
  onReplace,
  onClear,
}: {
  selection: Exclude<Selection, { status: "empty" }>;
  hovering: boolean;
  onReplace: () => void;
  onClear: () => void;
}) {
  const name = selection.status === "verified" ? selection.result.file_name : fileNameFromPath(selection.path);
  const family = selection.status === "verified" ? selection.result.family : "document";

  return (
    <div className="filecard" data-hovering={hovering || undefined} data-status={selection.status}>
      <div className="filecard__tile">
        <FamilyIcon family={family} width={24} height={24} />
      </div>
      <div className="filecard__body">
        <p className="filecard__name" title={name}>
          {name}
        </p>
        <p className="filecard__meta">
          {selection.status === "inspecting" && (
            <span className="status status--working">
              <span className="spinner" aria-hidden /> Verifying on this device…
            </span>
          )}
          {selection.status === "verified" && (
            <>
              <span>{selection.result.format_label}</span>
              <span className="dot-sep" aria-hidden>
                ·
              </span>
              <span>{formatBytes(selection.result.size_bytes)}</span>
              <span className="status status--ok">
                <CheckIcon /> Verified
              </span>
            </>
          )}
          {selection.status === "rejected" && <span className="status status--bad">Not loaded</span>}
        </p>
      </div>
      <div className="filecard__actions">
        <button type="button" className="ghost" onClick={onReplace}>
          Replace
        </button>
        <button type="button" className="icon-button" onClick={onClear} aria-label="Remove file">
          <CloseIcon />
        </button>
      </div>
    </div>
  );
}
