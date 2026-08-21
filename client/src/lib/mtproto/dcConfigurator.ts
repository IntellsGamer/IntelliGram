/*
 * Derived from Telegram Web K's data-center configurator.
 * IntelliGram is intentionally a single-DC self-hosted deployment.
 */

import MTTransport, {MTConnectionConstructable} from '@lib/mtproto/transports/transport';
import Modes from '@config/modes';
import indexOfAndSplice from '@helpers/array/indexOfAndSplice';
import Socket from '@lib/mtproto/transports/websocket';
import TcpAbridged from '@lib/mtproto/transports/tcpAbridged';
import {DcId} from '@types';

export type TransportType = 'websocket' | 'https' | 'http';
export type ConnectionType = 'client' | 'download' | 'upload';

type Servers = {
  [transportType in TransportType]: {
    [connectionType in ConnectionType]: {
      [dcId: DcId]: MTTransport[]
    }
  }
};

const SELF_HOSTED_DC_ID = 1 as DcId;
const RETRY_TIMEOUT_CLIENT = 3000;
const RETRY_TIMEOUT_DOWNLOAD = 3000;

function serverBaseUrl() {
  const configured = import.meta.env.VITE_INTELLIGRAM_SERVER_URL;
  if(configured) return configured.replace(/\/$/, '');
  return `${location.protocol}//${location.hostname}:8080`;
}

export function assertValidDcId(dcId: DcId): DcId {
  if(+dcId !== SELF_HOSTED_DC_ID) {
    throw new Error('[IntelliGram MT] this deployment exposes only self-hosted DC 1');
  }
  return SELF_HOSTED_DC_ID;
}

export function constructIntelliGramWebSocketUrl(_dcId: DcId, _connectionType: ConnectionType) {
  assertValidDcId(_dcId);
  const base = serverBaseUrl();
  const websocketBase = base.startsWith('https://') ? `wss://${base.slice('https://'.length)}` :
    base.startsWith('http://') ? `ws://${base.slice('http://'.length)}` : base;
  return `${websocketBase}/apiws`;
}

export class DcConfigurator {
  public chosenServers: Servers = {} as Servers;

  private transportSocket = (dcId: DcId, connectionType: ConnectionType) => {
    const chosenServer = constructIntelliGramWebSocketUrl(dcId, connectionType);
    const logSuffix = connectionType === 'upload' ? '-U' : connectionType === 'download' ? '-D' : '';
    const retryTimeout = connectionType === 'client' ? RETRY_TIMEOUT_CLIENT : RETRY_TIMEOUT_DOWNLOAD;
    return new TcpAbridged(Socket as MTConnectionConstructable, SELF_HOSTED_DC_ID, chosenServer, logSuffix, retryTimeout);
  };

  public chooseServer(
    dcId: DcId,
    connectionType: ConnectionType = 'client',
    transportType: TransportType = Modes.transport,
    reuse = true,
    _premium?: boolean
  ) {
    dcId = assertValidDcId(dcId);
    if(!this.chosenServers[transportType]) {
      this.chosenServers[transportType] = {client: {}, download: {}, upload: {}};
    }
    const servers = this.chosenServers[transportType][connectionType];
    const transports = servers[dcId] ??= [];
    if(!transports.length || !reuse) {
      const transport = this.transportSocket(dcId, connectionType);
      if(reuse) transports.push(transport);
      return transport;
    }
    return transports[0];
  }

  public static removeTransport<T>(obj: any, transport: T) {
    for(const transportType in obj) {
      for(const connectionType in obj[transportType]) {
        for(const dcId in obj[transportType][connectionType]) {
          const transports: T[] = obj[transportType][connectionType][dcId];
          indexOfAndSplice(transports, transport);
        }
      }
    }
  }
}
