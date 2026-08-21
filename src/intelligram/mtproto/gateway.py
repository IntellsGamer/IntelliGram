"""Async TCP MTProto gateway for IntelliGram's abridged transport."""

from __future__ import annotations

import asyncio
import logging
import struct

from intelligram.config import Settings
from intelligram.mtproto.keys import ServerKeyPair, load_or_create_server_keypair
from intelligram.mtproto.adapter import MTProtoSessionAdapter
from intelligram.mtproto.authorization_handshake import AuthorizationHandshake
from intelligram.mtproto.crypto import MTProtoSecurityError
from intelligram.mtproto.plain_handshake import PlainHandshakeError
from intelligram.mtproto.transport import ABRIDGED_TAG, TransportError, encode_abridged_packet, read_abridged_packet


LOGGER = logging.getLogger(__name__)


class MTProtoGateway:
    """Serves the pre-authorization MTProto plaintext handshake over TCP.

    Per-connection state is deliberately isolated: handshake nonces must never
    be reused between independently connected peers.
    """

    def __init__(self, server_key_pair: ServerKeyPair):
        self.server_key_pair = server_key_pair
        self._server: asyncio.base_events.Server | None = None

    async def start(self, host: str, port: int) -> None:
        self._server = await asyncio.start_server(self._handle_client, host, port, limit=4 * 1024 * 1024)

    async def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError("Gateway is not started")
        async with self._server:
            await self._server.serve_forever()

    async def close(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    @property
    def sockets(self) -> tuple[tuple[str, int], ...]:
        if self._server is None or not self._server.sockets:
            return ()
        return tuple(socket.getsockname()[:2] for socket in self._server.sockets)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        adapter = AuthorizationHandshake(self.server_key_pair)
        peer = writer.get_extra_info("peername")
        try:
            tag = await reader.readexactly(1)
            if tag != ABRIDGED_TAG:
                raise TransportError("Expected abridged transport tag 0xef")
            encrypted_sessions: dict[int, MTProtoSessionAdapter] = {}
            while True:
                packet = await read_abridged_packet(reader)
                auth_key_id = struct.unpack_from("<Q", packet, 0)[0] if len(packet) >= 8 else None
                if auth_key_id == 0:
                    response = adapter.handle_packet(packet)
                    for key_id, completed in adapter.completed_keys.items():
                        encrypted_sessions.setdefault(
                            key_id,
                            MTProtoSessionAdapter(auth_key=completed.auth_key, server_salt=completed.server_salt),
                        )
                else:
                    if auth_key_id is None or auth_key_id not in encrypted_sessions:
                        raise MTProtoSecurityError("AUTH_KEY_UNREGISTERED")
                    response = encrypted_sessions[auth_key_id].handle_encrypted(packet)
                if response is not None:
                    writer.write(encode_abridged_packet(response))
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except (TransportError, PlainHandshakeError, MTProtoSecurityError) as exc:
            LOGGER.info("Closing invalid MTProto peer %s: %s", peer, exc)
        except Exception:
            LOGGER.exception("Unhandled MTProto gateway failure for peer %s", peer)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass


async def run_gateway(settings: Settings) -> None:
    settings.ensure_directories()
    key_pair = load_or_create_server_keypair(
        settings.mtproto_rsa_private_key_path,
        settings.mtproto_rsa_public_key_path,
    )
    gateway = MTProtoGateway(key_pair)
    await gateway.start(settings.host, settings.mtproto_port)
    LOGGER.info(
        "IntelliGram MTProto gateway listening on %s:%d with public-key fingerprint %d",
        settings.host,
        settings.mtproto_port,
        key_pair.fingerprint,
    )
    await gateway.serve_forever()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(run_gateway(Settings.from_environment()))
