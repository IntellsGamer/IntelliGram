from __future__ import annotations

import uvicorn

from intelligram.api.app import create_app
from intelligram.config import Settings


def main() -> None:
    settings = Settings.from_environment()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
