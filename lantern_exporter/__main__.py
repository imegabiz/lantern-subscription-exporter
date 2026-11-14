import argparse
import logging
import os
import sys

from . import constants as C
from .client import LanternClient
from .errors import ExporterError
from .pipeline import run


def _parser():
    parser = argparse.ArgumentParser(prog="lantern_exporter")
    parser.add_argument("--output-dir", default=os.environ.get("LANTERN_OUTPUT_DIR", "subscription"))
    parser.add_argument("--state-file", default=os.environ.get("LANTERN_STATE_FILE", ".state/state.json"))
    parser.add_argument("--country", default=os.environ.get("LANTERN_COUNTRY", C.DEFAULT_COUNTRY))
    parser.add_argument("--min-configs", type=int, default=int(os.environ.get("LANTERN_MIN_CONFIGS", C.MIN_CONFIGS)))
    parser.add_argument("--app-version", default=os.environ.get("LANTERN_APP_VERSION", C.DEFAULT_APP_VERSION))
    parser.add_argument(
        "--singbox-version", default=os.environ.get("LANTERN_SINGBOX_VERSION", C.DEFAULT_SINGBOX_VERSION)
    )
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stdout)
    if args.min_configs < 1:
        print("--min-configs must be at least 1", file=sys.stderr)
        return 2
    client = LanternClient(
        country=args.country.strip().upper(),
        app_version=args.app_version,
        singbox_version=args.singbox_version,
    )
    try:
        result = run(client, args.state_file, args.output_dir, args.min_configs)
    except ExporterError as exc:
        logging.getLogger("lantern_exporter").error("update failed, previous output kept: %s", exc)
        return 1
    log = logging.getLogger("lantern_exporter")
    log.info("usable configs: %d", result.count)
    log.info("files changed: %s", result.changed or "none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
