import argparse
import sys

from orahealthcheck.config_loader import ConfigLoader, ConfigSyntaxError, ConfigValidationError, ConfigValidator
from orahealthcheck.engine import CheckRunner


def _load_validated(config_dir: str):
    config = ConfigLoader(config_dir).load_all()
    ConfigValidator().validate(config)
    return config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="orahealthcheck")
    parser.add_argument("--config-dir", default="config")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate-config")
    sub.add_parser("list-targets")
    sub.add_parser("list-profiles")
    sub.add_parser("list-groups")
    sub.add_parser("list-checks")
    run = sub.add_parser("run")
    run.add_argument("--target", required=True)
    run.add_argument("--profile", help="Perfil opcional para esta ejecución; no modifica el target configurado")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = _load_validated(args.config_dir)
        if args.command == "validate-config":
            print("Configuration is valid")
        elif args.command == "list-targets":
            for item in config["targets"].values():
                print(f"{item.target_id}\t{item.name}\t{item.profile}")
        elif args.command == "list-profiles":
            for item in config["profiles"].values():
                print(f"{item.profile_id}\t{','.join(item.enabled_groups)}")
        elif args.command == "list-groups":
            for item in config["groups"].values():
                print(f"{item.group_id}\t{item.name}\t{len(item.checks)} checks")
        elif args.command == "list-checks":
            for item in config["checks"].values():
                print(f"{item.check_id}\t{item.group_id}\t{item.title}")
        elif args.command == "run":
            if args.target not in config["targets"]:
                print(f"Target desconocido: {args.target}", file=sys.stderr)
                return 2
            if args.profile and args.profile not in config["profiles"]:
                print(f"Perfil desconocido: {args.profile}", file=sys.stderr)
                return 2
            output_dir = CheckRunner(config).run_target(args.target, profile_id=args.profile)
            print(f"Salida generada: {output_dir}")
        return 0
    except ConfigSyntaxError as exc:
        print(f"Configuration syntax error:\n{exc}", file=sys.stderr)
        return 1
    except ConfigValidationError as exc:
        print(f"Configuration validation failed:\n{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
