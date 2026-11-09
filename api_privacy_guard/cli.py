"""CLI for human-only administration, never expose these commands as MCP tools."""
from __future__ import annotations
import argparse
import getpass
import json
import re
import sys
import time
from .config import GuardError, config_path, initialize, load


def main() -> None:
    parser = argparse.ArgumentParser(prog="api-privacy-guard", description="API Privacy Guard - administração local")
    sp = parser.add_subparsers(dest="command", required=True)
    sp.add_parser("init", help="Criar configuração desabilitada por padrão")
    sp.add_parser("status", help="Listar perfis e status (sem credenciais)")
    p = sp.add_parser("secret-set", help="Guardar token no cofre do sistema")
    p.add_argument("name", help="Alias da credencial, nunca o valor")
    p = sp.add_parser("secret-delete", help="Excluir token do cofre do sistema")
    p.add_argument("name")
    p = sp.add_parser(
        "network-snapshot",
        help="Observar conexões de um PID e subprocessos (não bloqueia tráfego)",
    )
    p.add_argument("--pid", type=int, required=True, help="PID do processo raiz da IDE")
    p.add_argument("--no-children", action="store_true", help="Não incluir subprocessos")
    p.add_argument("--show-ip", action="store_true", help="Exibir IPs remotos (somente na saída local)")
    p.add_argument("--samples", type=int, default=1, help="Amostras entre 1 e 30 (padrão: 1)")
    p.add_argument("--interval", type=float, default=1.0, help="Segundos entre amostras (0.25 a 60)")
    args = parser.parse_args()
    try:
        if args.command == "init":
            print(f"Configuração criada: {initialize()}")
        elif args.command == "status":
            cfg = load()
            print(json.dumps({"config_path": str(config_path()),
                              "ssh_targets": {k: {"enabled": v.get("enabled", False), "tasks": list(v.get("tasks", {}))}
                                              for k, v in cfg["ssh_targets"].items()},
                              "api_services": {k: {"enabled": v.get("enabled", False), "methods": v.get("methods", [])}
                                               for k, v in cfg["api_services"].items()}}, indent=2))
        elif args.command == "network-snapshot":
            from .network_guard import take_snapshot
            if not 1 <= args.samples <= 30 or not 0.25 <= args.interval <= 60:
                raise GuardError("Intervalo ou número de amostras inválido.")
            for sample_no in range(args.samples):
                if sample_no:
                    time.sleep(args.interval)
                result = take_snapshot(
                    args.pid,
                    include_children=not args.no_children,
                    reveal_addresses=args.show_ip,
                )
                result["sample"] = sample_no + 1
                print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        elif args.command in ("secret-set", "secret-delete"):
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", args.name):
                raise GuardError("Alias inválido.")
            import keyring
            if args.command == "secret-set":
                secret = getpass.getpass("Digite o token (não será exibido): ")
                if not secret:
                    raise GuardError("Não foi fornecido token.")
                keyring.set_password("APIPrivacyGuard", args.name, secret)
                print("Credencial armazenada no cofre local do usuário.")
            else:
                keyring.delete_password("APIPrivacyGuard", args.name)
                print("Credencial excluída do cofre local do usuário.")
    except (GuardError, ImportError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        sys.exit(2)
    except Exception:
        # Don't print sensitive keyring backend errors.
        print("ERRO: falha na operação de credenciais.", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
