# Actual Telegram Web A RPC Coverage

This report reads every JavaScript/TypeScript source file in Telegram Web A’s `src/` tree. It filters `GramJs.Namespace.Class` references through the project’s own `api.tl` `---functions---` section, excluding API result/data classes from the request inventory. A ‘missing’ row means no Teamgram handler filename matched by name; it remains subject to manual source confirmation.

**Unique schema-defined RPCs referenced by Web A:** 438  
**Direct Teamgram handler-name matches:** 146  
**No direct Teamgram handler-name match:** 292

## Namespace coverage

| Namespace | Client RPCs | Direct Teamgram handlers | Filename-unmatched |
|---|---:|---:|---:|
| `account` | 49 | 33 | 16 |
| `aicompose` | 7 | 0 | 7 |
| `auth` | 2 | 2 | 0 |
| `bots` | 9 | 0 | 9 |
| `channels` | 42 | 8 | 34 |
| `chatlists` | 8 | 0 | 8 |
| `communities` | 2 | 0 | 2 |
| `contacts` | 15 | 15 | 0 |
| `ephemeral` | 4 | 0 | 4 |
| `folders` | 1 | 0 | 1 |
| `fragment` | 1 | 0 | 1 |
| `help` | 11 | 6 | 5 |
| `langpack` | 5 | 0 | 5 |
| `messages` | 173 | 68 | 105 |
| `payments` | 43 | 0 | 43 |
| `phone` | 20 | 0 | 20 |
| `photos` | 5 | 5 | 0 |
| `premium` | 4 | 0 | 4 |
| `stats` | 7 | 0 | 7 |
| `stories` | 21 | 0 | 21 |
| `updates` | 3 | 3 | 0 |
| `users` | 6 | 6 | 0 |

## Lazy-loading and synchronization obligations

| RPC | Used by Web A | Teamgram handler match |
|---|---|---|
| `channels.getParticipants` | Yes (2 source file(s)) | No static filename match |
| `messages.getDialogs` | Yes (1 source file(s)) | Yes |
| `messages.getHistory` | Yes (1 source file(s)) | Yes |
| `messages.getMessages` | Yes (2 source file(s)) | Yes |
| `messages.getPeerDialogs` | Yes (2 source file(s)) | Yes |
| `messages.search` | Yes (1 source file(s)) | Yes |
| `messages.searchGlobal` | Yes (1 source file(s)) | Yes |
| `updates.getChannelDifference` | Yes (1 source file(s)) | Yes |
| `updates.getDifference` | Yes (1 source file(s)) | Yes |

## Authentication and session-security obligations

| RPC | Used by Web A | Teamgram handler match |
|---|---|---|
| `account.getAuthorizations` | Yes (1 source file(s)) | Yes |
| `account.getPassword` | Yes (1 source file(s)) | No static filename match |
| `account.resetAuthorization` | Yes (1 source file(s)) | Yes |
| `account.updatePasswordSettings` | No static reference | — |
| `auth.checkPassword` | No static reference | — |
| `auth.logOut` | Yes (1 source file(s)) | Yes |
| `auth.sendCode` | No static reference | — |
| `auth.signIn` | No static reference | — |
| `auth.signUp` | No static reference | — |

## Group and channel obligations

| RPC | Used by Web A | Teamgram handler match |
|---|---|---|
| `channels.createChannel` | Yes (1 source file(s)) | No static filename match |
| `channels.editAbout` | No static reference | — |
| `channels.editTitle` | Yes (1 source file(s)) | No static filename match |
| `channels.getFullChannel` | Yes (2 source file(s)) | No static filename match |
| `channels.getParticipants` | Yes (2 source file(s)) | No static filename match |
| `channels.inviteToChannel` | Yes (1 source file(s)) | No static filename match |
| `messages.addChatUser` | Yes (1 source file(s)) | Yes |
| `messages.createChat` | Yes (1 source file(s)) | Yes |
| `messages.deleteChatUser` | Yes (1 source file(s)) | Yes |

## Direct Teamgram handler matches

| RPC | Web A source files | Teamgram handler files |
|---|---:|---|
| `account.changeAuthorizationSettings` | 1 | `app/bff/authorization/internal/core/account.changeAuthorizationSettings_handler.go` |
| `account.checkUsername` | 1 | `app/bff/usernames/internal/core/account.checkUsername_handler.go` |
| `account.deletePasskey` | 1 | `app/bff/passkey/internal/core/account.deletePasskey_handler.go` |
| `account.getAccountTTL` | 1 | `app/bff/account/internal/core/account.getAccountTTL_handler.go` |
| `account.getAuthorizations` | 1 | `app/bff/passport/internal/core/account.getAuthorizations_handler.go` |
| `account.getContactSignUpNotification` | 1 | `app/bff/contacts/internal/core/account.getContactSignUpNotification_handler.go` |
| `account.getContentSettings` | 1 | `app/bff/nsfw/internal/core/account.getContentSettings_handler.go` |
| `account.getGlobalPrivacySettings` | 1 | `app/bff/privacysettings/internal/core/account.getGlobalPrivacySettings_handler.go` |
| `account.getNotifyExceptions` | 1 | `app/bff/notification/internal/core/account.getNotifyExceptions_handler.go` |
| `account.getNotifySettings` | 1 | `app/bff/notification/internal/core/account.getNotifySettings_handler.go` |
| `account.getPasskeys` | 1 | `app/bff/passkey/internal/core/account.getPasskeys_handler.go` |
| `account.getPrivacy` | 1 | `app/bff/privacysettings/internal/core/account.getPrivacy_handler.go` |
| `account.getSavedMusicIds` | 1 | `app/bff/userchannelprofiles/internal/core/account.getSavedMusicIds_handler.go` |
| `account.initPasskeyRegistration` | 1 | `app/bff/passkey/internal/core/account.initPasskeyRegistration_handler.go` |
| `account.registerDevice` | 1 | `app/bff/notification/internal/core/account.registerDevice_handler.go` |
| `account.registerPasskey` | 1 | `app/bff/passkey/internal/core/account.registerPasskey_handler.go` |
| `account.resetAuthorization` | 1 | `app/bff/account/internal/core/account.resetAuthorization_handler.go` |
| `account.saveMusic` | 1 | `app/bff/userchannelprofiles/internal/core/account.saveMusic_handler.go` |
| `account.setAccountTTL` | 1 | `app/bff/account/internal/core/account.setAccountTTL_handler.go` |
| `account.setAuthorizationTTL` | 1 | `app/bff/authorization/internal/core/account.setAuthorizationTTL_handler.go` |
| `account.setContactSignUpNotification` | 1 | `app/bff/contacts/internal/core/account.setContactSignUpNotification_handler.go` |
| `account.setContentSettings` | 1 | `app/bff/nsfw/internal/core/account.setContentSettings_handler.go` |
| `account.setGlobalPrivacySettings` | 1 | `app/bff/privacysettings/internal/core/account.setGlobalPrivacySettings_handler.go` |
| `account.setMainProfileTab` | 1 | `app/bff/userchannelprofiles/internal/core/account.setMainProfileTab_handler.go` |
| `account.setPrivacy` | 1 | `app/bff/privacysettings/internal/core/account.setPrivacy_handler.go` |
| `account.toggleSponsoredMessages` | 1 | `app/bff/sponsoredmessages/internal/core/account.toggleSponsoredMessages_handler.go` |
| `account.unregisterDevice` | 1 | `app/bff/notification/internal/core/account.unregisterDevice_handler.go` |
| `account.updateBirthday` | 1 | `app/bff/userchannelprofiles/internal/core/account.updateBirthday_handler.go` |
| `account.updateNotifySettings` | 2 | `app/bff/notification/internal/core/account.updateNotifySettings_handler.go` |
| `account.updatePersonalChannel` | 1 | `app/bff/userchannelprofiles/internal/core/account.updatePersonalChannel_handler.go` |
| `account.updateProfile` | 1 | `app/bff/userchannelprofiles/internal/core/account.updateProfile_handler.go` |
| `account.updateStatus` | 1 | `app/bff/userchannelprofiles/internal/core/account.updateStatus_handler.go` |
| `account.updateUsername` | 1 | `app/bff/usernames/internal/core/account.updateUsername_handler.go` |
| `auth.logOut` | 1 | `app/bff/authorization/internal/core/auth.logOut_handler.go` |
| `auth.resetAuthorizations` | 1 | `app/bff/authorization/internal/core/auth.resetAuthorizations_handler.go` |
| `channels.checkSearchPostsFlood` | 1 | `app/bff/messages/internal/core/channels.checkSearchPostsFlood_handler.go` |
| `channels.checkUsername` | 1 | `app/bff/usernames/internal/core/channels.checkUsername_handler.go` |
| `channels.getSendAs` | 1 | `app/bff/messages/internal/core/channels.getSendAs_handler.go` |
| `channels.searchPosts` | 1 | `app/bff/messages/internal/core/channels.searchPosts_handler.go` |
| `channels.setMainProfileTab` | 1 | `app/bff/userchannelprofiles/internal/core/channels.setMainProfileTab_handler.go` |
| `channels.toggleJoinRequest` | 1 | `app/bff/chatinvites/internal/core/channels.toggleJoinRequest_handler.go` |
| `channels.toggleJoinToSend` | 1 | `app/bff/chatinvites/internal/core/channels.toggleJoinToSend_handler.go` |
| `channels.updateUsername` | 1 | `app/bff/usernames/internal/core/channels.updateUsername_handler.go` |
| `contacts.addContact` | 1 | `app/bff/contacts/internal/core/contacts.addContact_handler.go` |
| `contacts.block` | 1 | `app/bff/contacts/internal/core/contacts.block_handler.go` |
| `contacts.deleteContacts` | 1 | `app/bff/contacts/internal/core/contacts.deleteContacts_handler.go` |
| `contacts.editCloseFriends` | 1 | `app/bff/contacts/internal/core/contacts.editCloseFriends_handler.go` |
| `contacts.getBlocked` | 1 | `app/bff/contacts/internal/core/contacts.getBlocked_handler.go` |
| `contacts.getContacts` | 1 | `app/bff/contacts/internal/core/contacts.getContacts_handler.go` |
| `contacts.getSponsoredPeers` | 1 | `app/bff/sponsoredmessages/internal/core/contacts.getSponsoredPeers_handler.go` |
| `contacts.getTopPeers` | 1 | `app/bff/contacts/internal/core/contacts.getTopPeers_handler.go` |
| `contacts.importContacts` | 1 | `app/bff/contacts/internal/core/contacts.importContacts_handler.go` |
| `contacts.resetTopPeerRating` | 1 | `app/bff/contacts/internal/core/contacts.resetTopPeerRating_handler.go` |
| `contacts.resolvePhone` | 1 | `app/bff/users/internal/core/contacts.resolvePhone_handler.go` |
| `contacts.resolveUsername` | 2 | `app/bff/usernames/internal/core/contacts.resolveUsername_handler.go` |
| `contacts.search` | 1 | `app/bff/contacts/internal/core/contacts.search_handler.go` |
| `contacts.unblock` | 1 | `app/bff/contacts/internal/core/contacts.unblock_handler.go` |
| `contacts.updateContactNote` | 1 | `app/bff/contacts/internal/core/contacts.updateContactNote_handler.go` |
| `help.dismissSuggestion` | 1 | `app/bff/configuration/internal/core/help.dismissSuggestion_handler.go` |
| `help.getConfig` | 1 | `app/bff/configuration/internal/core/help.getConfig_handler.go` |
| `help.getCountriesList` | 1 | `app/bff/configuration/internal/core/help.getCountriesList_handler.go` |
| `help.getNearestDc` | 1 | `app/bff/configuration/internal/core/help.getNearestDc_handler.go` |
| `help.getPremiumPromo` | 1 | `app/bff/premium/internal/core/help.getPremiumPromo_handler.go` |
| `help.getSupport` | 1 | `app/bff/configuration/internal/core/help.getSupport_handler.go` |
| `messages.addChatUser` | 1 | `app/bff/chats/internal/core/messages.addChatUser_handler.go` |
| `messages.checkChatInvite` | 1 | `app/bff/chatinvites/internal/core/messages.checkChatInvite_handler.go` |
| `messages.clickSponsoredMessage` | 1 | `app/bff/sponsoredmessages/internal/core/messages.clickSponsoredMessage_handler.go` |
| `messages.createChat` | 1 | `app/bff/chats/internal/core/messages.createChat_handler.go` |
| `messages.deleteChat` | 1 | `app/bff/chats/internal/core/messages.deleteChat_handler.go` |
| `messages.deleteChatUser` | 1 | `app/bff/chats/internal/core/messages.deleteChatUser_handler.go` |
| `messages.deleteExportedChatInvite` | 1 | `app/bff/chatinvites/internal/core/messages.deleteExportedChatInvite_handler.go` |
| `messages.deleteHistory` | 1 | `app/bff/messages/internal/core/messages.deleteHistory_handler.go` |
| `messages.deleteMessages` | 1 | `app/bff/messages/internal/core/messages.deleteMessages_handler.go` |
| `messages.deleteRevokedExportedChatInvites` | 1 | `app/bff/chatinvites/internal/core/messages.deleteRevokedExportedChatInvites_handler.go` |
| `messages.deleteSavedHistory` | 1 | `app/bff/savedmessagedialogs/internal/core/messages.deleteSavedHistory_handler.go` |
| `messages.editChatAbout` | 1 | `app/bff/chats/internal/core/messages.editChatAbout_handler.go` |
| `messages.editChatCreator` | 1 | `app/bff/chats/internal/core/messages.editChatCreator_handler.go` |
| `messages.editChatDefaultBannedRights` | 1 | `app/bff/chats/internal/core/messages.editChatDefaultBannedRights_handler.go` |
| `messages.editChatParticipantRank` | 1 | `app/bff/chats/internal/core/messages.editChatParticipantRank_handler.go` |
| `messages.editChatPhoto` | 1 | `app/bff/chats/internal/core/messages.editChatPhoto_handler.go` |
| `messages.editChatTitle` | 1 | `app/bff/chats/internal/core/messages.editChatTitle_handler.go` |
| `messages.editExportedChatInvite` | 1 | `app/bff/chatinvites/internal/core/messages.editExportedChatInvite_handler.go` |
| `messages.editMessage` | 1 | `app/bff/messages/internal/core/messages.editMessage_handler.go` |
| `messages.exportChatInvite` | 1 | `app/bff/chatinvites/internal/core/messages.exportChatInvite_handler.go` |
| `messages.forwardMessages` | 1 | `app/bff/messages/internal/core/messages.forwardMessages_handler.go` |
| `messages.getChatInviteImporters` | 1 | `app/bff/chatinvites/internal/core/messages.getChatInviteImporters_handler.go` |
| `messages.getCommonChats` | 1 | `app/bff/chats/internal/core/messages.getCommonChats_handler.go` |
| `messages.getDefaultHistoryTTL` | 1 | `app/bff/privacysettings/internal/core/messages.getDefaultHistoryTTL_handler.go` |
| `messages.getDialogs` | 1 | `app/bff/dialogs/internal/core/messages.getDialogs_handler.go` |
| `messages.getExportedChatInvites` | 1 | `app/bff/chatinvites/internal/core/messages.getExportedChatInvites_handler.go` |
| `messages.getExtendedMedia` | 1 | `app/bff/messages/internal/core/messages.getExtendedMedia_handler.go` |
| `messages.getFullChat` | 1 | `app/bff/chats/internal/core/messages.getFullChat_handler.go` |
| `messages.getFutureChatCreatorAfterLeave` | 1 | `app/bff/chats/internal/core/messages.getFutureChatCreatorAfterLeave_handler.go` |
| `messages.getHistory` | 1 | `app/bff/messages/internal/core/messages.getHistory_handler.go` |
| `messages.getMessages` | 2 | `app/bff/messages/internal/core/messages.getMessages_handler.go` |
| `messages.getMessagesViews` | 1 | `app/bff/messages/internal/core/messages.getMessagesViews_handler.go` |
| `messages.getOutboxReadDate` | 1 | `app/bff/messages/internal/core/messages.getOutboxReadDate_handler.go` |
| `messages.getPeerDialogs` | 2 | `app/bff/dialogs/internal/core/messages.getPeerDialogs_handler.go` |
| `messages.getPeerSettings` | 1 | `app/bff/dialogs/internal/core/messages.getPeerSettings_handler.go` |
| `messages.getPinnedDialogs` | 2 | `app/bff/dialogs/internal/core/messages.getPinnedDialogs_handler.go` |
| `messages.getPinnedSavedDialogs` | 1 | `app/bff/savedmessagedialogs/internal/core/messages.getPinnedSavedDialogs_handler.go` |
| `messages.getRichMessage` | 1 | `app/bff/messages/internal/core/messages.getRichMessage_handler.go` |
| `messages.getSavedDialogs` | 1 | `app/bff/dialogs/internal/core/messages.getSavedDialogs_handler.go`<br>`app/bff/savedmessagedialogs/internal/core/messages.getSavedDialogs_handler.go` |
| `messages.getSavedHistory` | 1 | `app/bff/dialogs/internal/core/messages.getSavedHistory_handler.go`<br>`app/bff/savedmessagedialogs/internal/core/messages.getSavedHistory_handler.go` |
| `messages.getSponsoredMessages` | 1 | `app/bff/sponsoredmessages/internal/core/messages.getSponsoredMessages_handler.go` |
| `messages.getUnreadMentions` | 1 | `app/bff/messages/internal/core/messages.getUnreadMentions_handler.go` |
| `messages.hideAllChatJoinRequests` | 1 | `app/bff/chatinvites/internal/core/messages.hideAllChatJoinRequests_handler.go` |
| `messages.hideChatJoinRequest` | 1 | `app/bff/chatinvites/internal/core/messages.hideChatJoinRequest_handler.go` |
| `messages.hidePeerSettingsBar` | 1 | `app/bff/dialogs/internal/core/messages.hidePeerSettingsBar_handler.go` |
| `messages.markDialogUnread` | 1 | `app/bff/dialogs/internal/core/messages.markDialogUnread_handler.go` |
| `messages.migrateChat` | 1 | `app/bff/chats/internal/core/messages.migrateChat_handler.go` |
| `messages.readHistory` | 1 | `app/bff/messages/internal/core/messages.readHistory_handler.go` |
| `messages.readMentions` | 1 | `app/bff/messages/internal/core/messages.readMentions_handler.go` |
| `messages.readMessageContents` | 1 | `app/bff/messages/internal/core/messages.readMessageContents_handler.go` |
| `messages.reportSponsoredMessage` | 1 | `app/bff/sponsoredmessages/internal/core/messages.reportSponsoredMessage_handler.go` |
| `messages.saveDefaultSendAs` | 1 | `app/bff/messages/internal/core/messages.saveDefaultSendAs_handler.go` |
| `messages.saveDraft` | 1 | `app/bff/drafts/internal/core/messages.saveDraft_handler.go` |
| `messages.search` | 1 | `app/bff/messages/internal/core/messages.search_handler.go` |
| `messages.searchGlobal` | 1 | `app/bff/messages/internal/core/messages.searchGlobal_handler.go` |
| `messages.sendMedia` | 2 | `app/bff/messages/internal/core/messages.sendMedia_handler.go` |
| `messages.sendMessage` | 2 | `app/bff/messages/internal/core/messages.sendMessage_handler.go` |
| `messages.sendMultiMedia` | 2 | `app/bff/messages/internal/core/messages.sendMultiMedia_handler.go` |
| `messages.setDefaultHistoryTTL` | 1 | `app/bff/privacysettings/internal/core/messages.setDefaultHistoryTTL_handler.go` |
| `messages.setTyping` | 2 | `app/bff/dialogs/internal/core/messages.setTyping_handler.go` |
| `messages.summarizeText` | 1 | `app/bff/messages/internal/core/messages.summarizeText_handler.go` |
| `messages.toggleDialogPin` | 1 | `app/bff/dialogs/internal/core/messages.toggleDialogPin_handler.go` |
| `messages.toggleNoForwards` | 2 | `app/bff/messages/internal/core/messages.toggleNoForwards_handler.go` |
| `messages.toggleSavedDialogPin` | 1 | `app/bff/savedmessagedialogs/internal/core/messages.toggleSavedDialogPin_handler.go` |
| `messages.unpinAllMessages` | 1 | `app/bff/messages/internal/core/messages.unpinAllMessages_handler.go` |
| `messages.updatePinnedMessage` | 1 | `app/bff/messages/internal/core/messages.updatePinnedMessage_handler.go` |
| `messages.uploadMedia` | 1 | `app/bff/files/internal/core/messages.uploadMedia_handler.go` |
| `messages.viewSponsoredMessage` | 1 | `app/bff/sponsoredmessages/internal/core/messages.viewSponsoredMessage_handler.go` |
| `photos.deletePhotos` | 1 | `app/bff/userchannelprofiles/internal/core/photos.deletePhotos_handler.go` |
| `photos.getUserPhotos` | 1 | `app/bff/userchannelprofiles/internal/core/photos.getUserPhotos_handler.go` |
| `photos.updateProfilePhoto` | 1 | `app/bff/userchannelprofiles/internal/core/photos.updateProfilePhoto_handler.go` |
| `photos.uploadContactProfilePhoto` | 1 | `app/bff/userchannelprofiles/internal/core/photos.uploadContactProfilePhoto_handler.go` |
| `photos.uploadProfilePhoto` | 1 | `app/bff/userchannelprofiles/internal/core/photos.uploadProfilePhoto_handler.go` |
| `updates.getChannelDifference` | 1 | `app/bff/updates/internal/core/updates.getChannelDifference_handler.go` |
| `updates.getDifference` | 1 | `app/bff/updates/internal/core/updates.getDifference_handler.go` |
| `updates.getState` | 1 | `app/bff/updates/internal/core/updates.getState_handler.go` |
| `users.getFullUser` | 2 | `app/bff/users/internal/core/users.getFullUser_handler.go` |
| `users.getRequirementsToContact` | 1 | `app/bff/privacysettings/internal/core/users.getRequirementsToContact_handler.go` |
| `users.getSavedMusic` | 1 | `app/bff/userchannelprofiles/internal/core/users.getSavedMusic_handler.go` |
| `users.getSavedMusicByID` | 1 | `app/bff/userchannelprofiles/internal/core/users.getSavedMusicByID_handler.go` |
| `users.getUsers` | 2 | `app/bff/users/internal/core/users.getUsers_handler.go` |
| `users.suggestBirthday` | 1 | `app/bff/userchannelprofiles/internal/core/users.suggestBirthday_handler.go` |

## Filename-unmatched client RPCs

| RPC | Web A source files | Representative Web A paths |
|---|---:|---|
| `account.getCollectibleEmojiStatuses` | 1 | `api/gramjs/methods/symbols.ts` |
| `account.getPaidMessagesRevenue` | 1 | `api/gramjs/methods/users.ts` |
| `account.getPassword` | 1 | `api/gramjs/methods/twoFaSettings.ts` |
| `account.getRecentEmojiStatuses` | 1 | `api/gramjs/methods/symbols.ts` |
| `account.getWallPapers` | 1 | `api/gramjs/methods/settings.ts` |
| `account.getWebAuthorizations` | 1 | `api/gramjs/methods/settings.ts` |
| `account.reorderUsernames` | 1 | `api/gramjs/methods/settings.ts` |
| `account.reportPeer` | 1 | `api/gramjs/methods/account.ts` |
| `account.reportProfilePhoto` | 1 | `api/gramjs/methods/account.ts` |
| `account.resetWebAuthorization` | 1 | `api/gramjs/methods/settings.ts` |
| `account.resetWebAuthorizations` | 1 | `api/gramjs/methods/settings.ts` |
| `account.resolveBusinessChatLink` | 1 | `api/gramjs/methods/account.ts` |
| `account.toggleNoPaidMessagesException` | 1 | `api/gramjs/methods/users.ts` |
| `account.toggleUsername` | 1 | `api/gramjs/methods/settings.ts` |
| `account.updateEmojiStatus` | 1 | `api/gramjs/methods/users.ts` |
| `account.uploadWallPaper` | 1 | `api/gramjs/methods/settings.ts` |
| `aicompose.createTone` | 1 | `api/gramjs/methods/messages.ts` |
| `aicompose.deleteTone` | 1 | `api/gramjs/methods/messages.ts` |
| `aicompose.getTone` | 1 | `api/gramjs/methods/messages.ts` |
| `aicompose.getToneExample` | 1 | `api/gramjs/methods/messages.ts` |
| `aicompose.getTones` | 1 | `api/gramjs/methods/messages.ts` |
| `aicompose.saveTone` | 1 | `api/gramjs/methods/messages.ts` |
| `aicompose.updateTone` | 1 | `api/gramjs/methods/messages.ts` |
| `bots.allowSendMessage` | 1 | `api/gramjs/methods/bots.ts` |
| `bots.canSendMessage` | 1 | `api/gramjs/methods/bots.ts` |
| `bots.checkDownloadFileParams` | 1 | `api/gramjs/methods/bots.ts` |
| `bots.getBotRecommendations` | 1 | `api/gramjs/methods/bots.ts` |
| `bots.getPopularAppBots` | 1 | `api/gramjs/methods/bots.ts` |
| `bots.getPreviewMedias` | 1 | `api/gramjs/methods/bots.ts` |
| `bots.invokeWebViewCustomMethod` | 1 | `api/gramjs/methods/bots.ts` |
| `bots.setBotInfo` | 1 | `api/gramjs/methods/bots.ts` |
| `bots.toggleUserEmojiStatusPermission` | 1 | `api/gramjs/methods/bots.ts` |
| `channels.createChannel` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.deactivateAllUsernames` | 1 | `api/gramjs/methods/management.ts` |
| `channels.deleteChannel` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.deleteHistory` | 1 | `api/gramjs/methods/messages.ts` |
| `channels.deleteMessages` | 1 | `api/gramjs/methods/messages.ts` |
| `channels.deleteParticipantHistory` | 1 | `api/gramjs/methods/messages.ts` |
| `channels.editAdmin` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.editBanned` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.editPhoto` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.editTitle` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.exportMessageLink` | 1 | `api/gramjs/methods/messages.ts` |
| `channels.getAdminedPublicChannels` | 1 | `api/gramjs/methods/settings.ts` |
| `channels.getChannelRecommendations` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.getFullChannel` | 2 | `api/gramjs/methods/chats.ts`<br>`api/gramjs/methods/communities.ts` |
| `channels.getGroupsForDiscussion` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.getMessages` | 2 | `api/gramjs/methods/client.ts`<br>`api/gramjs/methods/messages.ts` |
| `channels.getParticipant` | 2 | `api/gramjs/methods/chats.ts`<br>`api/gramjs/methods/client.ts` |
| `channels.getParticipants` | 2 | `api/gramjs/methods/chats.ts`<br>`api/gramjs/methods/client.ts` |
| `channels.inviteToChannel` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.joinChannel` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.leaveChannel` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.readHistory` | 1 | `api/gramjs/methods/messages.ts` |
| `channels.readMessageContents` | 1 | `api/gramjs/methods/messages.ts` |
| `channels.reorderUsernames` | 1 | `api/gramjs/methods/settings.ts` |
| `channels.reportSpam` | 1 | `api/gramjs/methods/messages.ts` |
| `channels.setDiscussionGroup` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.toggleAutotranslation` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.toggleForum` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.toggleParticipantsHidden` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.togglePreHistoryHidden` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.toggleSignatures` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.toggleUsername` | 1 | `api/gramjs/methods/settings.ts` |
| `channels.toggleViewForumAsMessages` | 1 | `api/gramjs/methods/chats.ts` |
| `channels.updatePaidMessagesPrice` | 1 | `api/gramjs/methods/chats.ts` |
| `chatlists.checkChatlistInvite` | 1 | `api/gramjs/methods/chats.ts` |
| `chatlists.deleteExportedInvite` | 1 | `api/gramjs/methods/chats.ts` |
| `chatlists.editExportedInvite` | 1 | `api/gramjs/methods/chats.ts` |
| `chatlists.exportChatlistInvite` | 1 | `api/gramjs/methods/chats.ts` |
| `chatlists.getExportedInvites` | 1 | `api/gramjs/methods/chats.ts` |
| `chatlists.getLeaveChatlistSuggestions` | 1 | `api/gramjs/methods/chats.ts` |
| `chatlists.joinChatlistInvite` | 1 | `api/gramjs/methods/chats.ts` |
| `chatlists.leaveChatlist` | 1 | `api/gramjs/methods/chats.ts` |
| `communities.getJoinedCommunities` | 1 | `api/gramjs/methods/communities.ts` |
| `communities.toggleCommunityCollapsedInDialogs` | 1 | `api/gramjs/methods/communities.ts` |
| `ephemeral.deleteMessage` | 1 | `api/gramjs/methods/messages.ts` |
| `ephemeral.getCallbackAnswer` | 1 | `api/gramjs/methods/bots.ts` |
| `ephemeral.reportMessage` | 1 | `api/gramjs/methods/messages.ts` |
| `ephemeral.sendMessage` | 1 | `api/gramjs/methods/messages.ts` |
| `folders.editPeerFolders` | 1 | `api/gramjs/methods/chats.ts` |
| `fragment.getCollectibleInfo` | 1 | `api/gramjs/methods/fragment.ts` |
| `help.getAppConfig` | 1 | `api/gramjs/methods/misc.ts` |
| `help.getPeerColors` | 1 | `api/gramjs/methods/settings.ts` |
| `help.getPeerProfileColors` | 1 | `api/gramjs/methods/settings.ts` |
| `help.getPromoData` | 1 | `api/gramjs/methods/misc.ts` |
| `help.getTimezonesList` | 1 | `api/gramjs/methods/settings.ts` |
| `langpack.getDifference` | 1 | `api/gramjs/methods/settings.ts` |
| `langpack.getLangPack` | 1 | `api/gramjs/methods/settings.ts` |
| `langpack.getLanguage` | 1 | `api/gramjs/methods/settings.ts` |
| `langpack.getLanguages` | 1 | `api/gramjs/methods/settings.ts` |
| `langpack.getStrings` | 1 | `api/gramjs/methods/settings.ts` |
| `messages.acceptUrlAuth` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.addPollAnswer` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.appendTodoList` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.checkUrlAuthMatchCode` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.clearRecentReactions` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.clearRecentStickers` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.composeMessageWithAI` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.createForumTopic` | 1 | `api/gramjs/methods/forum.ts` |
| `messages.declineUrlAuth` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.deleteParticipantReaction` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.deleteParticipantReactions` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.deleteScheduledMessages` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.deleteTopicHistory` | 1 | `api/gramjs/methods/forum.ts` |
| `messages.editForumTopic` | 1 | `api/gramjs/methods/forum.ts` |
| `messages.faveSticker` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getAllStickers` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getAttachMenuBot` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.getAttachMenuBots` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.getAvailableEffects` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.getAvailableReactions` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.getBotApp` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.getBotCallbackAnswer` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.getCustomEmojiDocuments` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getDefaultTagReactions` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.getDhConfig` | 1 | `api/gramjs/methods/calls.ts` |
| `messages.getDialogFilters` | 1 | `api/gramjs/methods/chats.ts` |
| `messages.getDiscussionMessage` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.getEmojiGroups` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getEmojiKeywordsDifference` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getEmojiStickerGroups` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getEmojiStickers` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getFactCheck` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.getFavedStickers` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getFeaturedEmojiStickers` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getFeaturedStickers` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getForumTopics` | 2 | `api/gramjs/methods/client.ts`<br>`api/gramjs/methods/forum.ts` |
| `messages.getForumTopicsByID` | 1 | `api/gramjs/methods/forum.ts` |
| `messages.getInlineBotResults` | 2 | `api/gramjs/methods/bots.ts`<br>`api/gramjs/methods/symbols.ts` |
| `messages.getMessageReactionsList` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.getMessageReadParticipants` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.getMessagesReactions` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.getPaidReactionPrivacy` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.getPollVotes` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.getPreparedInlineMessage` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.getQuickReplies` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.getQuickReplyMessages` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.getRecentReactions` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.getRecentStickers` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getReplies` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.getSavedGifs` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getSavedReactionTags` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.getScheduledHistory` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.getStickerSet` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getStickers` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.getSuggestedDialogFilters` | 1 | `api/gramjs/methods/chats.ts` |
| `messages.getTopReactions` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.getUnreadPollVotes` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.getUnreadReactions` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.getWebPage` | 2 | `api/gramjs/methods/client.ts`<br>`api/gramjs/methods/messages.ts` |
| `messages.getWebPagePreview` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.importChatInvite` | 1 | `api/gramjs/methods/chats.ts` |
| `messages.installStickerSet` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.prolongWebView` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.readDiscussion` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.readPollVotes` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.readReactions` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.report` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.reportMessagesDelivery` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.reportReaction` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.reportReadMetrics` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.reportSpam` | 1 | `api/gramjs/methods/users.ts` |
| `messages.requestAppWebView` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.requestChatJoinWebView` | 1 | `api/gramjs/methods/chats.ts` |
| `messages.requestMainWebView` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.requestSimpleWebView` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.requestUrlAuth` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.requestWebView` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.saveGif` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.saveRecentSticker` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.searchCustomEmoji` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.searchEmojiStickerSets` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.searchStickerSets` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.searchStickers` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.sendInlineBotResult` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.sendPaidReaction` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.sendQuickReplyMessages` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.sendReaction` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.sendScheduledMessages` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.sendVote` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.sendWebViewData` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.setChatAvailableReactions` | 1 | `api/gramjs/methods/chats.ts` |
| `messages.setDefaultReaction` | 1 | `api/gramjs/methods/reactions.ts` |
| `messages.startBot` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.toggleBotInAttachMenu` | 1 | `api/gramjs/methods/bots.ts` |
| `messages.toggleDialogFilterTags` | 1 | `api/gramjs/methods/chats.ts` |
| `messages.togglePeerTranslations` | 1 | `api/gramjs/methods/chats.ts` |
| `messages.toggleSuggestedPostApproval` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.toggleTodoCompleted` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.transcribeAudio` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.translateText` | 1 | `api/gramjs/methods/messages.ts` |
| `messages.uninstallStickerSet` | 1 | `api/gramjs/methods/symbols.ts` |
| `messages.updateDialogFilter` | 1 | `api/gramjs/methods/chats.ts` |
| `messages.updateDialogFiltersOrder` | 1 | `api/gramjs/methods/chats.ts` |
| `messages.updatePinnedForumTopic` | 1 | `api/gramjs/methods/forum.ts` |
| `messages.updateSavedReactionTag` | 1 | `api/gramjs/methods/reactions.ts` |
| `payments.applyGiftCode` | 1 | `api/gramjs/methods/payments.ts` |
| `payments.changeStarsSubscription` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.checkCanSendGift` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.checkGiftCode` | 1 | `api/gramjs/methods/payments.ts` |
| `payments.convertStarGift` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.craftStarGift` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.fulfillStarsSubscription` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getCraftStarGifts` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getGiveawayInfo` | 1 | `api/gramjs/methods/payments.ts` |
| `payments.getPaymentForm` | 1 | `api/gramjs/methods/payments.ts` |
| `payments.getPaymentReceipt` | 1 | `api/gramjs/methods/payments.ts` |
| `payments.getPremiumGiftCodeOptions` | 1 | `api/gramjs/methods/payments.ts` |
| `payments.getResaleStarGifts` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getSavedStarGifts` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarGiftActiveAuctions` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarGiftAuctionAcquiredGifts` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarGiftAuctionState` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarGiftCollections` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarGiftUpgradeAttributes` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarGiftUpgradePreview` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarGiftWithdrawalUrl` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarGifts` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarsGiftOptions` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarsGiveawayOptions` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarsRevenueStats` | 1 | `api/gramjs/methods/statistics.ts` |
| `payments.getStarsRevenueWithdrawalUrl` | 1 | `api/gramjs/methods/statistics.ts` |
| `payments.getStarsStatus` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarsSubscriptions` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarsTopupOptions` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarsTransactions` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getStarsTransactionsByID` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getUniqueStarGift` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.getUniqueStarGiftValueInfo` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.launchPrepaidGiveaway` | 1 | `api/gramjs/methods/payments.ts` |
| `payments.resolveStarGiftOffer` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.saveStarGift` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.sendPaymentForm` | 1 | `api/gramjs/methods/payments.ts` |
| `payments.sendStarsForm` | 1 | `api/gramjs/methods/payments.ts` |
| `payments.toggleStarGiftsPinnedToTop` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.transferStarGift` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.updateStarGiftPrice` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.upgradeStarGift` | 1 | `api/gramjs/methods/stars.ts` |
| `payments.validateRequestedInfo` | 1 | `api/gramjs/methods/payments.ts` |
| `phone.acceptCall` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.confirmCall` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.createGroupCall` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.discardCall` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.discardGroupCall` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.editGroupCallParticipant` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.editGroupCallTitle` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.exportGroupCallInvite` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.getCallConfig` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.getGroupCall` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.getGroupParticipants` | 2 | `api/gramjs/methods/calls.ts`<br>`api/gramjs/methods/client.ts` |
| `phone.joinGroupCall` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.joinGroupCallPresentation` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.leaveGroupCall` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.leaveGroupCallPresentation` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.receivedCall` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.requestCall` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.sendSignalingData` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.setCallRating` | 1 | `api/gramjs/methods/calls.ts` |
| `phone.toggleGroupCallStartSubscription` | 1 | `api/gramjs/methods/calls.ts` |
| `premium.applyBoost` | 1 | `api/gramjs/methods/payments.ts` |
| `premium.getBoostsList` | 1 | `api/gramjs/methods/payments.ts` |
| `premium.getBoostsStatus` | 1 | `api/gramjs/methods/payments.ts` |
| `premium.getMyBoosts` | 1 | `api/gramjs/methods/payments.ts` |
| `stats.getBroadcastStats` | 1 | `api/gramjs/methods/statistics.ts` |
| `stats.getMegagroupStats` | 1 | `api/gramjs/methods/statistics.ts` |
| `stats.getMessagePublicForwards` | 1 | `api/gramjs/methods/statistics.ts` |
| `stats.getMessageStats` | 1 | `api/gramjs/methods/statistics.ts` |
| `stats.getStoryPublicForwards` | 1 | `api/gramjs/methods/statistics.ts` |
| `stats.getStoryStats` | 1 | `api/gramjs/methods/statistics.ts` |
| `stats.loadAsyncGraph` | 1 | `api/gramjs/methods/statistics.ts` |
| `stories.activateStealthMode` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.deleteStories` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.editStory` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.exportStoryLink` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.getAlbumStories` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.getAlbums` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.getAllStories` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.getPeerMaxIDs` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.getPeerStories` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.getPinnedStories` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.getStoriesArchive` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.getStoriesByID` | 2 | `api/gramjs/methods/client.ts`<br>`api/gramjs/methods/stories.ts` |
| `stories.getStoriesViews` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.getStoryViewsList` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.incrementStoryViews` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.readStories` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.report` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.sendReaction` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.togglePeerStoriesHidden` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.togglePinned` | 1 | `api/gramjs/methods/stories.ts` |
| `stories.togglePinnedToTop` | 1 | `api/gramjs/methods/stories.ts` |
