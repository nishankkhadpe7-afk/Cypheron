"""Terminal scanner: python -m scanner.cli https://example.com [--active]"""
import argparse
import asyncio
import json

from . import analyst_summary, run_scan

COLORS = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
          "low": "\033[94m", "info": "\033[90m", "pass": "\033[92m"}
RESET = "\033[0m"


async def main():
    ap = argparse.ArgumentParser(description="Cypheron web security scanner")
    ap.add_argument("url")
    ap.add_argument("--active", action="store_true",
                    help="also probe for exposed files (only on sites you own or may test)")
    ap.add_argument("--json", action="store_true", help="print the raw JSON report")
    args = ap.parse_args()

    async def progress(evt):
        if evt["type"] == "check_start" and not args.json:
            print(f"  … {evt['check']}")

    report = await run_scan(args.url, active=args.active, emit=progress)
    report["analyst"] = await analyst_summary(report)
    if args.json:
        print(json.dumps(report, indent=2))
        return

    print(f"\nCYPHERON · {report['final_url']}")
    print(f"Score {report['score']}/100  Grade {report['grade']}  Risk {report['risk']}  ({report['duration_ms']} ms)\n")
    for w in report["warnings"]:
        print(f"  ⚠ {w}")
    for f in report["findings"]:
        c = COLORS[f["severity"]]
        print(f"  {c}{f['severity'].upper():9}{RESET} {f['title']}")
    print("\nCategories:")
    for c in report["categories"]:
        print(f"  {c['label']:24} {c['percent']:3}%  ({c['passed']}/{c['total']})")
    print(f"\nAnalyst ({report['analyst']['source']}): {report['analyst']['text']}\n")


if __name__ == "__main__":
    asyncio.run(main())
