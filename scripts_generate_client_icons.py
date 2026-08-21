from __future__ import annotations

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "assets" / "intelligram-app-icon.png"
WEB_K_IMAGES = ROOT / "client" / "public" / "assets" / "img"

TARGETS = {
    "android-chrome-36x36.png": 36,
    "android-chrome-48x48.png": 48,
    "android-chrome-72x72.png": 72,
    "android-chrome-96x96.png": 96,
    "android-chrome-144x144.png": 144,
    "android-chrome-192x192.png": 192,
    "android-chrome-256x256.png": 256,
    "android-chrome-384x384.png": 384,
    "android-chrome-512x512.png": 512,
    "apple-touch-icon-precomposed.png": 180,
    "apple-touch-icon.png": 180,
    "favicon-16x16.png": 16,
    "favicon-32x32.png": 32,
    "favicon-194x194.png": 194,
    "icon_square_192.png": 192,
    "icon_square_384.png": 384,
    "icon_square_512.png": 512,
    "logo_512.png": 512,
    "logo_filled_rounded.png": 512,
}


def main() -> None:
    source = Image.open(SOURCE).convert("RGBA")
    WEB_K_IMAGES.mkdir(parents=True, exist_ok=True)

    for filename, size in TARGETS.items():
        image = source.resize((size, size), Image.Resampling.LANCZOS)
        image.save(WEB_K_IMAGES / filename, format="PNG", optimize=True)

    favicon = source.resize((256, 256), Image.Resampling.LANCZOS)
    favicon.save(
        WEB_K_IMAGES / "favicon.ico",
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    favicon.save(
        WEB_K_IMAGES / "favicon_unread.ico",
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )


if __name__ == "__main__":
    main()
