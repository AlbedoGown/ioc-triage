import csv
import json
import sys

from ioc_triage.sources import PUBLIC_FIELDS, Verdict


def render(verdicts: list[Verdict], fmt: str) -> None:
    if fmt == "json":
        json.dump([v.to_dict() for v in verdicts], sys.stdout, ensure_ascii=False, indent=2)
        return

    if fmt == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=list(PUBLIC_FIELDS))
        writer.writeheader()
        for v in verdicts:
            writer.writerow(v.to_dict())
        return

    _render_table(verdicts)


def _render_table(verdicts: list[Verdict]) -> None:
    headers = ["Индикатор", "Тип", "Источник", "Детекты", "Впервые замечен", "Вывод"]
    rows = [
        [v.indicator, v.indicator_type, v.source, v.detections or "—", v.first_seen or "—", v.verdict]
        for v in verdicts
    ]
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]

    def fmt_row(row: list[str]) -> str:
        return "  ".join(cell.ljust(w) for cell, w in zip(row, widths))

    print(fmt_row(headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt_row(row))
