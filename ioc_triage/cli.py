import argparse
import sys

from ioc_triage.detect import detect_type, is_private_ip
from ioc_triage.output import render
from ioc_triage.sources import Verdict
from ioc_triage.sources import abusech, virustotal, abuseipdb

SOURCES_BY_TYPE = {
    "ip": [abuseipdb.check, virustotal.check, abusech.check],
    "domain": [virustotal.check, abusech.check],
    "url": [virustotal.check, abusech.check],
    "md5": [virustotal.check, abusech.check],
    "sha1": [virustotal.check, abusech.check],
    "sha256": [virustotal.check, abusech.check],
}


def read_indicators(args: argparse.Namespace) -> list[str]:
    if args.input:
        with open(args.input, newline="") as f:
            if args.column:
                import csv

                reader = csv.DictReader(f)
                return [row[args.column].strip() for row in reader if row.get(args.column)]
            return [line.strip() for line in f if line.strip()]
    return [line.strip() for line in sys.stdin if line.strip()]


def check_indicator(indicator: str) -> list[Verdict]:
    indicator_type = detect_type(indicator)

    if indicator_type == "ip" and is_private_ip(indicator):
        return [Verdict(indicator, "ip", "local", verdict="внутренний адрес, проверка не имеет смысла")]

    if indicator_type == "unknown":
        return [Verdict(indicator, "unknown", "-", verdict="не удалось определить тип")]

    return [check_fn(indicator, indicator_type) for check_fn in SOURCES_BY_TYPE.get(indicator_type, [])]


def main() -> None:
    parser = argparse.ArgumentParser(description="Пакетная проверка индикаторов компрометации")
    parser.add_argument("--input", help="файл со списком индикаторов или CSV")
    parser.add_argument("--column", help="имя столбца в CSV с индикатором")
    parser.add_argument("--output", choices=["table", "csv", "json"], default="table")
    args = parser.parse_args()

    indicators = read_indicators(args)
    verdicts = [v for indicator in indicators for v in check_indicator(indicator)]

    if not verdicts:
        print("Нет результатов.", file=sys.stderr)
        return

    render(verdicts, args.output)


if __name__ == "__main__":
    main()
