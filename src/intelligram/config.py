from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import secrets


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime configuration for one IntelliGram deployment.

    Development defaults are deliberately local-only. Production must provide
    a durable signing secret and explicitly set ``development_mode`` to false.
    """

    database_path: Path
    host: str
    port: int
    public_base_url: str
    token_secret: bytes
    development_mode: bool
    development_login_code: str | None
    mtproto_dc_id: int
    mtproto_port: int
    mtproto_rsa_private_key_path: Path
    mtproto_rsa_public_key_path: Path

    @classmethod
    def from_environment(cls) -> "Settings":
        development_mode = os.getenv("INTELLIGRAM_DEVELOPMENT_MODE", "true").lower() == "true"
        token_secret_text = os.getenv("INTELLIGRAM_TOKEN_SECRET")
        if token_secret_text:
            token_secret = token_secret_text.encode("utf-8")
        elif development_mode:
            # Ephemeral development-only secret: sessions become invalid at restart.
            token_secret = secrets.token_bytes(48)
        else:
            raise RuntimeError("INTELLIGRAM_TOKEN_SECRET is required outside development mode")

        development_login_code = os.getenv("INTELLIGRAM_DEVELOPMENT_LOGIN_CODE")
        if not development_mode and development_login_code:
            raise RuntimeError("INTELLIGRAM_DEVELOPMENT_LOGIN_CODE is prohibited outside development mode")

        data_dir = Path(os.getenv("INTELLIGRAM_DATA_DIR", "./data")).resolve()
        return cls(
            database_path=Path(os.getenv("INTELLIGRAM_DATABASE_PATH", str(data_dir / "intelligram.sqlite3"))).resolve(),
            host=os.getenv("INTELLIGRAM_HOST", "127.0.0.1"),
            port=int(os.getenv("INTELLIGRAM_PORT", "8080")),
            public_base_url=os.getenv("INTELLIGRAM_PUBLIC_BASE_URL", "http://127.0.0.1:8080").rstrip("/"),
            token_secret=token_secret,
            development_mode=development_mode,
            development_login_code=development_login_code,
            mtproto_dc_id=int(os.getenv("INTELLIGRAM_MTPROTO_DC_ID", "1")),
            mtproto_port=int(os.getenv("INTELLIGRAM_MTPROTO_PORT", "10443")),
            mtproto_rsa_private_key_path=Path(
                os.getenv("INTELLIGRAM_MTPROTO_RSA_PRIVATE_KEY", str(data_dir / "mtproto_server_private.pem"))
            ).resolve(),
            mtproto_rsa_public_key_path=Path(
                os.getenv("INTELLIGRAM_MTPROTO_RSA_PUBLIC_KEY", str(data_dir / "mtproto_server_public.pem"))
            ).resolve(),
        )

    def ensure_directories(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.mtproto_rsa_private_key_path.parent.mkdir(parents=True, exist_ok=True)
