/*
 * Derived from Telegram Web K's TCP transport wrapper.
 * IntelliGram uses ordinary binary WebSocket frames carrying MTProto abridged
 * packets; no Telegram obfuscation preamble or production proxy is used.
 */

import {logger, LogTypes} from '@lib/logger';
import Modes from '@config/modes';
import {MTConnection, MTConnectionConstructable} from '@lib/mtproto/transports/transport';
import type MTTransport from '@lib/mtproto/transports/transport';
import abridgedPacketCodec from '@lib/mtproto/transports/abridged';
import {ConnectionStatus} from '@lib/mtproto/connectionStatus';
import transportController from '@lib/mtproto/transports/controller';
import type MTPNetworker from '@lib/mtproto/networker';
import ctx from '@environment/ctx';

type PendingPacket = Partial<{
  resolve: (data: Uint8Array) => void,
  reject: (reason?: unknown) => void,
  body: Uint8Array,
  encoded: Uint8Array,
  bodySent: boolean
}>;

export default class TcpAbridged implements MTTransport {
  private readonly codec = abridgedPacketCodec;
  private pending: PendingPacket[] = [];
  private log: ReturnType<typeof logger>;
  private autoReconnect = true;
  private reconnectTimeout: number;
  private lastCloseTime: number;
  private releasingPending = false;

  public networker: MTPNetworker;
  public connected = false;
  public connection: MTConnection;

  constructor(
    private Connection: MTConnectionConstructable,
    private dcId: number,
    private url: string,
    private logSuffix: string,
    private retryTimeout: number
  ) {
    this.log = logger(`ABRIDGED-${dcId}` + logSuffix, LogTypes.Error | LogTypes.Log);
    this.connect();
  }

  private onOpen = () => {
    this.connected = true;
    if(import.meta.env.VITE_MTPROTO_AUTO && Modes.multipleTransports) {
      transportController.setTransportOpened('websocket');
    }
    // The local gateway requires the native abridged tag as its first WS frame.
    this.connection.send(new Uint8Array([this.codec.tag]));
    this.networker?.onTransportOpen();
    void this.releasePending();
  };

  private onMessage = (buffer: ArrayBuffer) => {
    const packet = this.codec.readPacket(new Uint8Array(buffer));
    if(this.networker) {
      this.networker.onTransportData(packet, Date.now());
      return;
    }
    const pending = this.pending.shift();
    pending?.resolve?.(packet);
  };

  private onClose = () => {
    this.clear();
    if(this.networker) {
      const retryAt = this.autoReconnect ? Date.now() + this.retryTimeout : undefined;
      this.networker.setConnectionStatus(ConnectionStatus.Closed, retryAt);
    }
    if(this.autoReconnect) {
      const elapsed = Date.now() - this.lastCloseTime;
      const delay = Number.isFinite(elapsed) && elapsed < this.retryTimeout ? this.retryTimeout - elapsed : 0;
      this.reconnectTimeout = ctx.setTimeout(this.reconnect, delay);
    }
  };

  public clear() {
    if(import.meta.env.VITE_MTPROTO_AUTO && Modes.multipleTransports && this.connected) {
      transportController.setTransportClosed('websocket');
    }
    this.connected = false;
    this.connection?.removeEventListener('open', this.onOpen);
    this.connection?.removeEventListener('close', this.onClose);
    this.connection?.removeEventListener('message', this.onMessage);
    this.connection = undefined;
  }

  public reconnect = () => {
    if(this.reconnectTimeout !== undefined) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = undefined;
    }
    if(this.connection) return;
    this.lastCloseTime = Date.now();
    this.networker?.setConnectionStatus(ConnectionStatus.Connecting);
    this.connect();
  };

  public forceReconnect() {
    this.close();
    this.reconnect();
  }

  public close() {
    const connection = this.connection;
    if(!connection) return;
    this.clear();
    connection.close();
  }

  public destroy() {
    this.setAutoReconnect(false);
    this.close();
    this.pending.forEach((pending) => pending.reject?.(new Error('Transport destroyed')));
    this.pending = [];
  }

  public setAutoReconnect(enable: boolean) {
    this.autoReconnect = enable;
    if(!enable && this.reconnectTimeout !== undefined) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = undefined;
    }
    if(enable && !this.connection && this.reconnectTimeout === undefined) {
      this.reconnect();
    }
  }

  public changeUrl(url: string) {
    if(this.url === url) return;
    this.url = url;
    this.forceReconnect();
  }

  private connect() {
    this.connection = new this.Connection(this.dcId, this.url, this.logSuffix);
    this.connection.addEventListener('open', this.onOpen);
    this.connection.addEventListener('close', this.onClose);
    this.connection.addEventListener('message', this.onMessage);
  }

  public send(body: Uint8Array) {
    const encoded = this.codec.encodePacket(body);
    if(this.networker) {
      this.pending.push({body, encoded});
      void this.releasePending();
      return;
    }
    const promise = new Promise<Uint8Array>((resolve, reject) => {
      this.pending.push({resolve, reject, body, encoded});
    });
    void this.releasePending();
    return promise;
  }

  private async releasePending() {
    if(!this.connected || this.releasingPending) return;
    this.releasingPending = true;
    for(let index = 0; index < this.pending.length; index++) {
      const pending = this.pending[index];
      if(!pending?.encoded || pending.bodySent || !this.connected) continue;
      this.connection.send(pending.encoded);
      if(pending.resolve) {
        pending.bodySent = true;
      } else {
        this.pending.splice(index--, 1);
      }
    }
    this.releasingPending = false;
  }
}
