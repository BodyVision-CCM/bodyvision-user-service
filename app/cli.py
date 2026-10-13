"""Outils en ligne de commande.

    python -m app.cli generate-key --out jwt_private.pem     # clé RSA 2048 bits pour la production
"""

import argparse
from pathlib import Path

from app.security import write_new_private_key


def main() -> None:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate-key", help="Génère une clé privée RSA (PEM) sans écraser un fichier existant.")
    gen.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "generate-key":
        if args.out.exists():
            raise SystemExit(f"{args.out} existe déjà : refus de l'écraser.")
        write_new_private_key(args.out)
        print(f"Clé écrite dans {args.out} (permissions 600). Ne la commitez jamais.")


if __name__ == "__main__":
    main()
