import {readFileSync} from 'node:fs';

const source = readFileSync('client/src/lib/mtproto/schema.ts', 'utf8');
const marker = 'export default ';
const start = source.indexOf(marker);
if (start < 0) {
  throw new Error('Generated schema export was not found');
}
const exportValue = source.slice(start + marker.length).trim();
const assertion = exportValue.lastIndexOf('} as ');
if (assertion < 0) {
  throw new Error('Generated schema type assertion was not found');
}
const schema = JSON.parse(exportValue.slice(0, assertion + 1));
const wanted = new Set([
  'user',
  'userEmpty',
  'users.userFull',
  'contacts.contacts',
  'messages.dialogs',
  'messages.dialogsSlice',
  'messages.peerDialogs',
  'messages.messages',
  'messages.messagesSlice',
  'message',
  'dialog',
  'peerUser',
  'peerChat',
  'inputPeerSelf',
  'inputPeerUser',
  'inputPeerChat',
  'inputUserSelf',
  'inputUser',
  'inputDialogPeer',
  'userStatusEmpty',
  'peerSettings',
  'peerNotifySettings',
  'privacyValueAllowAll',
  'account.privacyRules',
  'peerNotifySettings',
  'updateNewMessage',
  'updateMessageID',
  'updates',
  'updatesCombined',
  'updatesTooLong',
]);
const wantedMethods = new Set([
  'users.getUsers',
  'users.getFullUser',
  'contacts.getContacts',
  'messages.getDialogs',
  'messages.getPeerDialogs',
  'messages.getHistory',
  'messages.sendMessage',
  'account.updateStatus',
  'account.getPrivacy',
]);
for (const entry of schema.API.constructors.filter((item) => wanted.has(item.predicate))) {
  console.log(JSON.stringify({kind: 'constructor', ...entry}, null, 2));
}
for (const entry of schema.API.methods.filter((item) => wantedMethods.has(item.method))) {
  console.log(JSON.stringify({kind: 'method', ...entry}, null, 2));
}
