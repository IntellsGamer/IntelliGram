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
if(process.env.PRINT_SCHEMA_TABLES === '1') {
  console.log(JSON.stringify(Object.fromEntries(Object.entries(schema).map(([key, value]) => [key, value && typeof value === 'object' ? Object.keys(value) : typeof value]))));
  process.exit(0);
}
const lookupConstructorIds = new Set(
  (process.env.LOOKUP_CONSTRUCTOR_IDS || '')
    .split(',')
    .map((id) => id.trim().toLowerCase().replace(/^0x/, ''))
    .filter(Boolean)
);
const onlyLookupConstructorIds = process.env.ONLY_LOOKUP_CONSTRUCTOR_IDS === '1';
const wanted = new Set([
  'user',
  'userEmpty',
  'users.userFull',
  'userFull',
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
  'messages.invitedUsers',
  'chat',
  'chatEmpty',
  'updateNewChat',
  'updateChatParticipants',
  'chatParticipants',
  'chatPhotoEmpty',
  'inputFile',
  'inputFileBig',
  'photo',
  'photoEmpty',
  'photoSize',
  'photos.photo',
  'inputPhotoFileLocation',
  'upload.file',
  'storage.fileUnknown',
  'updates.difference',
  'updates.differenceEmpty',
  'chatFull',
  'messages.chatFull',
  'chatParticipants',
  'chatParticipant',
  'messages.affectedMessages',
  'messages.peerSettings',
  'auth.loggedOut',
  'updateShort',
  'updateUserTyping',
  'updateChatUserTyping',
  'langPackDifference',
  'help.countriesList',
  'help.countriesListNotModified',
  'contacts.resolvedPeer',
  'updateReadHistoryInbox',
  'updateChatParticipants',
  'updateEditMessage',
  'updateDeleteMessages',
  'contacts.importedContacts',
  'contacts.found',
  'importedContact',
  'inputPhoneContact',
  'account.authorization',
  'authorization',
  'dialog',
  'peerUser',
  'peerChat',
  'account.authorizations',
  'account.contentSettings',
  'help.appConfig',
  'jsonObject',
  'pong',
]);
const lookupMethodIds = new Set(
  (process.env.LOOKUP_METHOD_IDS || '')
    .split(',')
    .map((id) => id.trim().toLowerCase().replace(/^0x/, ''))
    .filter(Boolean)
);
const onlyLookupMethodIds = process.env.ONLY_LOOKUP_METHOD_IDS === '1';
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
  'messages.createChat',
  'account.updateProfile',
  'upload.saveFilePart',
  'upload.saveBigFilePart',
  'photos.uploadProfilePhoto',
  'upload.getFile',
  'updates.getDifference',
  'messages.getFullChat',
  'messages.readHistory',
  'messages.setTyping',
  'messages.getPeerSettings',
  'auth.logOut',
  'langpack.getLangPack',
  'help.getCountriesList',
  'contacts.resolveUsername',
  'messages.addChatUser',
  'messages.deleteChatUser',
  'messages.editChatTitle',
  'messages.editChatAbout',
  'messages.editMessage',
  'messages.deleteMessages',
  'messages.forwardMessages',
  'contacts.importContacts',
  'contacts.search',
  'account.getAuthorizations',
  'account.resetAuthorization',
]);
const allConstructors = [...schema.API.constructors, ...schema.MTProto.constructors];
const allMethods = [...schema.API.methods, ...schema.MTProto.methods];
for (const entry of allConstructors.filter((item) => {
  const unsignedId = (item.id >>> 0).toString(16).padStart(8, '0');
  return (!onlyLookupConstructorIds && wanted.has(item.predicate)) || lookupConstructorIds.has(unsignedId);
})) {
  console.log(JSON.stringify({kind: 'constructor', ...entry}, null, 2));
}
for (const entry of allMethods.filter((item) => {
  const unsignedId = (item.id >>> 0).toString(16).padStart(8, '0');
  return (!onlyLookupMethodIds && wantedMethods.has(item.method)) || lookupMethodIds.has(unsignedId);
})) {
  console.log(JSON.stringify({kind: 'method', ...entry}, null, 2));
}
