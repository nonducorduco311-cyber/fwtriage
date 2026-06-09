"""fwtriage CLI.

Usage:
  python3 -m fwtriage entropy   <image>
  python3 -m fwtriage extract   <image> [--out DIR]
  python3 -m fwtriage classify  <extracted-dir>
  python3 -m fwtriage services  <extracted-dir>
  python3 -m fwtriage secrets   <extracted-dir>
  python3 -m fwtriage all       <image-or-dir> [--out DIR] [--json]

'all' runs the full pipeline: on an image it does entropy + extraction, then
classifies/scans the extracted filesystem; on a directory it skips extraction.
"""
import argparse
import os
import sys

from . import entropy, extract, classify, services, secrets, report


def _emit(data, as_json):
    print(report.render(data, as_json=as_json))


def cmd_all(args):
    target = args.target
    data = {"target": target}

    if os.path.isfile(target):
        data["entropy"] = entropy.analyze(target)
        ext = extract.extract(target, args.out)
        data["extraction"] = ext
        scan_root = ext.get("extracted_to")
        if not scan_root:
            print(report.render(data, as_json=args.json))
            print("\n[!] Nothing extracted - stopping. See entropy verdict above.",
                  file=sys.stderr)
            return
    elif os.path.isdir(target):
        scan_root = target
    else:
        print(f"[!] not found: {target}", file=sys.stderr)
        sys.exit(2)

    data["classification"] = classify.classify_dir(scan_root)
    data["services"] = services.identify(scan_root)
    data["secrets"] = secrets.scan_dir(scan_root)
    _emit(data, args.json)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fwtriage", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("entropy"); p.add_argument("target")
    p = sub.add_parser("extract"); p.add_argument("target"); p.add_argument("--out", default="./fwtriage_out")
    p = sub.add_parser("classify"); p.add_argument("target")
    p = sub.add_parser("services"); p.add_argument("target")
    p = sub.add_parser("secrets"); p.add_argument("target")
    p = sub.add_parser("all"); p.add_argument("target"); p.add_argument("--out", default="./fwtriage_out"); p.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)

    if args.cmd == "entropy":
        _emit({"target": args.target, "entropy": entropy.analyze(args.target)}, False)
    elif args.cmd == "extract":
        _emit({"target": args.target, "extraction": extract.extract(args.target, args.out)}, False)
    elif args.cmd == "classify":
        _emit({"target": args.target, "classification": classify.classify_dir(args.target)}, False)
    elif args.cmd == "services":
        _emit({"target": args.target, "services": services.identify(args.target)}, False)
    elif args.cmd == "secrets":
        _emit({"target": args.target, "secrets": secrets.scan_dir(args.target)}, False)
    elif args.cmd == "all":
        cmd_all(args)


if __name__ == "__main__":
    main()
