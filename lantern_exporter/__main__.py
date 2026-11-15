import argparse
import logging
import os
import sys

from . import constants as C
from .client import LanternClient
from .errors import ExporterError
from .pipeline import run
from .state import generate_key_text, parse_key


def _parser():
    parser = argparse.ArgumentParser(prog="lantern_exporter")
    parser.add_argument("--output-dir", default=os.environ.get("LANTERN_OUTPUT_DIR", "subscription"))
    parser.add_argument("--state-file", default=os.environ.get("LANTERN_STATE_FILE", C.DEFAULT_STATE_FILE))
    parser.add_argument(
        "--legacy-state-file", default=os.environ.get("LANTERN_LEGACY_STATE_FILE", C.DEFAULT_LEGACY_STATE_FILE)
    )
    parser.add_argument(
        "--bootstrap",
        choices=C.BOOTSTRAP_MODES,
        default=os.environ.get("LANTERN_BOOTSTRAP", "none") or "none",
    )
    parser.add_argument(
        "--hysteria2-links",
        choices=C.HYSTERIA2_LINK_MODES,
        default=os.environ.get("LANTERN_HYSTERIA2_LINKS", C.DEFAULT_HYSTERIA2_LINKS) or C.DEFAULT_HYSTERIA2_LINKS,
    )
    parser.add_argument("--country", default=os.environ.get("LANTERN_COUNTRY", C.DEFAULT_COUNTRY))
    parser.add_argument("--min-configs", type=int, default=int(os.environ.get("LANTERN_MIN_CONFIGS", C.MIN_CONFIGS)))
    parser.add_argument("--app-version", default=os.environ.get("LANTERN_APP_VERSION", C.DEFAULT_APP_VERSION))
    parser.add_argument(
        "--singbox-version", default=os.environ.get("LANTERN_SINGBOX_VERSION", C.DEFAULT_SINGBOX_VERSION)
    )
    parser.add_argument("--generate-key", action="store_true")
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    if args.generate_key:
        print(generate_key_text())
        return 0
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stdout, force=True)
    log = logging.getLogger("lantern_exporter")
    if args.min_configs < 1:
        print("--min-configs must be at least 1", file=sys.stderr)
        return 2
    try:
        key = parse_key(os.environ.get(C.STATE_KEY_ENV, ""))
    except ExporterError as exc:
        log.error("update failed, previous output kept: %s", exc)
        return 1
    client = LanternClient(
        country=args.country.strip().upper(),
        app_version=args.app_version,
        singbox_version=args.singbox_version,
    )
    try:
        result = run(
            client,
            args.state_file,
            args.output_dir,
            key,
            bootstrap=args.bootstrap,
            legacy_state_path=args.legacy_state_file,
            min_configs=args.min_configs,
            hysteria2_links=args.hysteria2_links,
        )
    except ExporterError as exc:
        log.error("update failed, previous output kept: %s", exc)
        return 1
    log.info("usable configs: %d (share links: %d)", result.count, result.link_count)
    if result.links_omitted:
        log.info("%d Hysteria2 config(s) were left out of sub.txt for security, see README", result.links_omitted)
    if result.junk_not_expressible:
        log.info(
            "%d Hysteria2 config(s) request pre_initial_junk, which only xray.json can express",
            result.junk_not_expressible,
        )
    if result.state_written:
        log.info("the encrypted state file was written and must be committed")
    log.info("files changed: %s", result.changed or "none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
