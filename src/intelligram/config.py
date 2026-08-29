from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import secrets
from urllib.parse import urlsplit


DEFAULT_PUBLIC_LINK_BASE_URL = "https://intelligram.local"


def _load_local_dotenv() -> None:
    """Load simple local `.env` assignments without overriding real environment.

    IntelliGram intentionally avoids a dotenv runtime dependency. This tiny
    parser accepts the deployment convention needed for self-hosted local use
    while shell/service-manager variables always take precedence.
    """

    path = Path.cwd() / ".env"
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value[:1] == value[-1:] and value[:1] in {"'", '"'}:
            value = value[1:-1]
        if key and key.replace("_", "").isalnum() and key not in os.environ:
            os.environ[key] = value


def _normalize_admin_phone(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    digits = "".join(character for character in value if character.isdigit())
    if not 3 <= len(digits) <= 15:
        raise ValueError("INTELLIGRAM_ADMIN_PHONE must contain 3 to 15 digits")
    return f"+{digits}"


def _normalize_public_link_base_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlsplit(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError(
            "INTELLIGRAM_PUBLIC_LINK_BASE_URL must be an absolute HTTP(S) URL without a query or fragment"
        )
    return normalized


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
    # External, user-visible base for public usernames and server-generated invite links.
    # This is intentionally separate from `public_base_url`, which identifies the HTTP API.
    public_link_base_url: str = DEFAULT_PUBLIC_LINK_BASE_URL
    # Optional, server-side-only phone identity permitted to use the owner portal.
    admin_owner_phone: str | None = None

    @classmethod
    def from_environment(cls) -> "Settings":
        _load_local_dotenv()
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
            host=os.getenv("INTELLIGRAM_HOST", "0.0.0.0"),
            port=int(os.getenv("INTELLIGRAM_PORT", "8080")),
            public_base_url=os.getenv("INTELLIGRAM_PUBLIC_BASE_URL", "http://0.0.0.0:8080").rstrip("/"),
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
            public_link_base_url=_normalize_public_link_base_url(
                os.getenv("INTELLIGRAM_PUBLIC_LINK_BASE_URL", DEFAULT_PUBLIC_LINK_BASE_URL)
            ),
            admin_owner_phone=_normalize_admin_phone(os.getenv("INTELLIGRAM_ADMIN_PHONE")),
        )

    def ensure_directories(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.mtproto_rsa_private_key_path.parent.mkdir(parents=True, exist_ok=True)
