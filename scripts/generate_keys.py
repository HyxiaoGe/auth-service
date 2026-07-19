#!/usr/bin/env python3
"""Generate RSA key pair for JWT signing."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.security.jwt_handler import generate_rsa_keys

if __name__ == "__main__":
    try:
        generate_rsa_keys()
    except FileExistsError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        print("   为避免令牌和 JWKS 突变，请先备份并显式移走旧密钥。", file=sys.stderr)
        raise SystemExit(1) from exc
    print("✅ RSA key pair generated successfully!")
    print("   Private key: keys/private.pem")
    print("   Public key:  keys/public.pem")
    print()
    print("⚠️  Keep private.pem SECRET. Never commit it to git.")
    print("   Add 'keys/' to your .gitignore.")
