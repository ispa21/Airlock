import type { ExtractSummary, SegmentKind } from "../engine/types";
import { AlertIcon } from "./icons";

const KINDS: Record<SegmentKind, { label: string; easyToMiss: boolean; words?: boolean }> = {
  body: { label: "Main text", easyToMiss: false, words: true },
  ocr: { label: "Text in images (OCR)", easyToMiss: false, words: true },
  header_footer: { label: "Headers & footers", easyToMiss: false },
  note: { label: "Notes", easyToMiss: true, words: true },
  comment: { label: "Comments", easyToMiss: true },
  tracked_change: { label: "Deleted text kept by tracked changes", easyToMiss: true },
  hidden: { label: "Hidden content", easyToMiss: true },
  metadata: { label: "Properties & authors", easyToMiss: true },
  link: { label: "Links & connections", easyToMiss: true },
  field: { label: "Formulas & field codes", easyToMiss: true },
  alt_text: { label: "Alt text & object names", easyToMiss: true },
  name: { label: "Names & bookmarks", easyToMiss: false },
  template: { label: "Templates & masters", easyToMiss: true },
  chart: { label: "Chart data", easyToMiss: true },
};

const number = new Intl.NumberFormat("en-US");

function plural(n: number, one: string, many = `${one}s`): string {
  return `${number.format(n)} ${n === 1 ? one : many}`;
}

export function structureLine(summary: ExtractSummary): string {
  const c = summary.counts;
  const parts: string[] = [];
  if (c.pages) parts.push(plural(c.pages, "page"));
  if (c.slides) parts.push(plural(c.slides, "slide"));
  if (c.sheets) parts.push(plural(c.sheets, "sheet"));
  if (c.rows) parts.push(plural(c.rows, "row"));
  if (c.lines) parts.push(plural(c.lines, "line"));
  parts.push(plural(summary.word_count, "word"));
  if (c.images_ocr) parts.push(`${plural(c.images_ocr, "image")} read with OCR`);
  if (c.embedded) parts.push(plural(c.embedded, "embedded file"));
  return parts.join(" · ");
}

export function ExtractionReport({ summary }: { summary: ExtractSummary }) {
  const hiddenItems = summary.parts.filter((p) => KINDS[p.kind]?.easyToMiss).reduce((n, p) => n + p.segments, 0);
  return (
    <section className="report" aria-labelledby="report-title">
      <header className="report__head">
        <h2 id="report-title">What Airlock read</h2>
        <span className="report__meta">
          {summary.format_label} · {(summary.duration_ms / 1000).toFixed(1)} s
        </span>
      </header>
      <p className="report__structure">{structureLine(summary)}</p>
      {hiddenItems > 0 && (
        <p className="report__callout">
          Includes {plural(hiddenItems, "item")} that are easy to miss when you open the file.
        </p>
      )}

      <ul className="report__parts">
        {summary.parts.map((part) => {
          const meta = KINDS[part.kind] ?? { label: part.kind, easyToMiss: false };
          return (
            <li key={part.kind} className="report__part">
              <span className="report__label">
                {meta.label}
                {meta.easyToMiss && <span className="tag">Easy to miss</span>}
              </span>
              <span className="report__count">
                {meta.words ? plural(part.words, "word") : plural(part.segments, "item")}
              </span>
            </li>
          );
        })}
      </ul>

      {summary.unextracted_total > 0 && (
        <div className="notice notice--warn">
          <AlertIcon className="notice__icon" />
          <div>
            <p className="notice__title">{plural(summary.unextracted_total, "item")} could not be read</p>
            <ul className="report__unread">
              {summary.unextracted.map((item) => (
                <li key={`${item.kind}:${item.label}`}>
                  {item.label}
                  {item.count > 1 ? ` (${item.count})` : ""}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <p className="report__foot">
        Read on this device. Your original file was not changed.
      </p>
    </section>
  );
}
