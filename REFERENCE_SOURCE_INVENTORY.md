# Reference Source Inventory

This is a static source-tree inventory generated from local, read-only copies of Telegram Web A and Teamgram Server. It is a map for systematic protocol and feature-contract analysis; it does not execute third-party code.

## Telegram Web A

**Root:** `/home/ubuntu/reference-sources/telegram-web-a`  
**Files audited:** 3,045 total; 2,363 textual/code/configuration files.

### Top-level layout

| Directory | File count |
|---|---:|
| `src` | 2,916 |
| `public` | 54 |
| `tauri` | 33 |
| `dev` | 12 |
| `deploy` | 3 |
| `.husky` | 1 |
| `docs` | 1 |
| `plugins` | 1 |
| `.github` | 1 |

### Dominant file types

| Extension | Files |
|---|---:|
| `.tsx` | 925 |
| `.ts` | 856 |
| `.scss` | 515 |
| `.svg` | 499 |
| `.tgs` | 58 |
| `.png` | 46 |
| `.json` | 26 |
| `.woff2` | 20 |
| `.js` | 15 |
| `.mp3` | 11 |
| `.html` | 9 |
| `[no extension]` | 8 |
| `.rs` | 8 |
| `.md` | 6 |
| `.webmanifest` | 4 |
| `.css` | 4 |
| `.webp` | 4 |
| `.ico` | 3 |
| `.template` | 3 |
| `.woff` | 3 |

### Largest textual files reviewed as high-complexity candidates

| Path | KiB |
|---|---:|
| `public/build-stats.json` | 95500.6 |
| `public/statoscope-report.html` | 2683.8 |
| `src/lib/gramjs/tl/api.d.ts` | 953.2 |
| `package-lock.json` | 522.7 |
| `src/lib/gramjs/tl/static/api.tl` | 272.4 |
| `src/lib/gramjs/tl/apiTl.ts` | 239.6 |
| `src/types/language.d.ts` | 124.0 |
| `src/global/actions/api/messages.ts` | 112.3 |
| `src/global/actions/api/chats.ts` | 112.1 |
| `src/components/common/Composer.tsx` | 111.0 |
| `src/lib/fasttextweb/fasttext-wasm.js` | 97.0 |
| `src/api/gramjs/methods/messages.ts` | 85.0 |
| `src/components/middle/message/Message.tsx` | 82.0 |
| `src/global/types/actions.ts` | 78.3 |
| `src/styles/icons/preview.html` | 75.3 |
| `src/lib/vibecalls/phone/phoneCall.ts` | 68.3 |
| `src/components/ui/textInput/richText.ts` | 63.5 |
| `src/api/gramjs/methods/chats.ts` | 59.4 |
| `src/components/middle/MessageList.tsx` | 56.8 |
| `src/components/modals/gift/craft/GiftCraftModal.tsx` | 53.2 |
| `src/global/actions/apiUpdaters/messages.ts` | 53.0 |
| `src/lib/gramjs/network/MTProtoSender.ts` | 52.6 |
| `src/components/right/Profile.tsx` | 52.4 |
| `src/global/selectors/messages.ts` | 51.4 |
| `src/components/middle/message/ActionMessageText.tsx` | 44.3 |

### Functional keyword coverage

| Concern | Matching source files | Representative paths |
|---|---:|---|
| auth | 162 | `CHANGELOG.md`<br>`package-lock.json`<br>`package.json`<br>`vite.config.ts`<br>`dev/createBundleStatsComment.ts`<br>`dev/telegraphChangelog.js`<br>`docs/TAURI.md`<br>`public/build-stats.json` |
| updates | 507 | `AGENTS.md`<br>`CHANGELOG.md`<br>`CLAUDE.md`<br>`eslint.config.js`<br>`package-lock.json`<br>`package.json`<br>`deploy/prepareTauriConfig.js`<br>`dev/buildIcons.ts` |
| history | 307 | `AGENTS.md`<br>`CHANGELOG.md`<br>`CLAUDE.md`<br>`package-lock.json`<br>`dev/generateLangTypes.ts`<br>`dev/tlHash.js`<br>`public/build-stats.json`<br>`public/statoscope-report.html` |
| secret chats | 24 | `package-lock.json`<br>`docs/TAURI.md`<br>`public/build-stats.json`<br>`public/statoscope-report.html`<br>`.github/workflows/package-and-publish.yml`<br>`src/lib/twemojiRegex.js`<br>`src/styles/themes.json`<br>`src/types/language.d.ts` |
| groups channels | 482 | `.stylelintrc.json`<br>`AGENTS.md`<br>`CHANGELOG.md`<br>`CLAUDE.md`<br>`eslint.config.js`<br>`package-lock.json`<br>`package.json`<br>`dev/telegraphChangelog.js` |
| media | 814 | `AGENTS.md`<br>`CHANGELOG.md`<br>`CLAUDE.md`<br>`README.md`<br>`package-lock.json`<br>`vite.config.ts`<br>`dev/createBundleStatsComment.ts`<br>`dev/log.html` |
| transport | 38 | `README.md`<br>`public/build-stats.json`<br>`public/compatTest.js`<br>`src/config.ts`<br>`src/global/cache.ts`<br>`src/global/initialState.ts`<br>`src/api/types/misc.ts`<br>`src/api/gramjs/methods/client.ts` |

## Teamgram Server

**Root:** `/home/ubuntu/reference-sources/teamgram-server`  
**Files audited:** 1,935 total; 1,845 textual/code/configuration files.

### Top-level layout

| Directory | File count |
|---|---:|
| `app` | 1,738 |
| `teamgramd` | 90 |
| `pkg` | 49 |
| `specs` | 17 |
| `docs` | 16 |
| `clients` | 3 |
| `data` | 1 |

### Dominant file types

| Extension | Files |
|---|---:|
| `.go` | 1,566 |
| `.yaml` | 76 |
| `.md` | 66 |
| `.sh` | 66 |
| `.xml` | 48 |
| `.sql` | 46 |
| `.proto` | 20 |
| `.jpeg` | 14 |
| `[no extension]` | 8 |
| `.png` | 6 |
| `.jpg` | 3 |
| `.yml` | 3 |
| `.gif` | 2 |
| `.webp` | 2 |
| `.example` | 1 |
| `.teamgram` | 1 |
| `.mod` | 1 |
| `.sum` | 1 |
| `.mp4` | 1 |
| `.toml` | 1 |

### Largest textual files reviewed as high-complexity candidates

| Path | KiB |
|---|---:|
| `app/service/biz/user/user/user.tl.pb.go` | 459.3 |
| `app/service/biz/dialog/dialog/dialog.tl.pb.go` | 238.0 |
| `app/service/biz/chat/chat/chat.tl.pb.go` | 205.5 |
| `app/service/biz/user/user/user.tl_grpc.pb.go` | 165.6 |
| `app/service/biz/user/user/codec_schema.tl.pb.go` | 131.5 |
| `app/service/biz/message/message/message.tl.pb.go` | 129.9 |
| `app/service/authsession/authsession/authsession.tl.pb.go` | 123.6 |
| `app/messenger/msg/inbox/inbox/inbox.tl.pb.go` | 117.3 |
| `app/service/biz/message/internal/dal/dao/mysql_dao/messages_dao.go` | 100.6 |
| `app/service/media/media/media.tl.pb.go` | 90.7 |
| `app/messenger/msg/msg/msg/msg.tl.pb.go` | 85.2 |
| `app/service/biz/dialog/dialog/dialog.tl_grpc.pb.go` | 73.1 |
| `app/service/biz/dialog/internal/dal/dao/mysql_dao/dialogs_dao.go` | 67.5 |
| `app/service/biz/dialog/dialog/codec_schema.tl.pb.go` | 66.7 |
| `app/service/status/status/status.tl.pb.go` | 65.6 |
| `app/interface/session/session/session.tl.pb.go` | 65.3 |
| `app/service/biz/chat/chat/chat.tl_grpc.pb.go` | 63.0 |
| `app/service/dfs/dfs/dfs.tl.pb.go` | 60.8 |
| `app/service/biz/chat/chat/codec_schema.tl.pb.go` | 60.1 |
| `app/service/idgen/idgen/idgen.tl.pb.go` | 58.9 |
| `app/service/biz/user/client/user_client.go` | 52.5 |
| `app/service/biz/user/internal/dal/dao/mysql_dao/users_dao.go` | 50.9 |
| `app/service/biz/user/internal/server/grpc/service/user_service_impl.go` | 48.5 |
| `app/service/biz/message/internal/dal/dao/mysql_dao/chat_participants_dao.go` | 47.1 |
| `app/service/biz/updates/updates/updates.tl.pb.go` | 42.8 |

### Functional keyword coverage

| Concern | Matching source files | Representative paths |
|---|---:|---|
| auth | 1,594 | `README-env-en.md`<br>`README.md`<br>`SECURITY.md`<br>`build.sh`<br>`dalgenall.sh`<br>`docker-compose-env.yaml`<br>`docs/install-manual-linux-zh.md`<br>`docs/install-manual-linux.md` |
| updates | 489 | `dalgenall.sh`<br>`docker-compose-env.yaml`<br>`docs/install-manual-linux-zh.md`<br>`docs/install-manual-linux.md`<br>`docs/install-manual-macos-zh.md`<br>`docs/install-manual-macos.md`<br>`specs/architecture.md`<br>`specs/contributing.md` |
| history | 148 | `specs/contributing.md`<br>`app/bff/chats/client/chats_client.go`<br>`app/bff/chats/internal/core/messages.deleteChatUser_handler.go`<br>`app/bff/chats/internal/core/messages.deleteChat_handler.go`<br>`app/bff/chats/internal/core/messages.getCommonChats_handler.go`<br>`app/bff/chats/internal/server/grpc/service/chats_service_impl.go`<br>`app/bff/contacts/internal/core/contacts.block_handler.go`<br>`app/bff/contacts/internal/core/contacts.getBlocked_handler.go` |
| secret chats | 65 | `README-env-en.md`<br>`README-zh.md`<br>`README.md`<br>`docs/install-manual-linux-zh.md`<br>`docs/install-manual-linux.md`<br>`docs/install-manual-macos-zh.md`<br>`docs/install-manual-macos.md`<br>`specs/roadmap-zh.md` |
| groups channels | 288 | `README-zh.md`<br>`README.md`<br>`docker-compose-env.yaml`<br>`docs/log-collection.md`<br>`docs/service-topology-zh.md`<br>`docs/service-topology.md`<br>`specs/roadmap-zh.md`<br>`specs/roadmap.md` |
| media | 297 | `CHANGELOG.md`<br>`README-zh.md`<br>`README.md`<br>`build.sh`<br>`dalgenall.sh`<br>`docker-compose-env.yaml`<br>`minio_init.sh`<br>`docs/install-manual-linux-zh.md` |
| transport | 1,241 | `README-zh.md`<br>`README.md`<br>`clients/teamgram-tdesktop.md`<br>`docs/install-manual-linux-zh.md`<br>`docs/install-manual-linux.md`<br>`docs/service-topology-zh.md`<br>`docs/service-topology.md`<br>`specs/README-zh.md` |
