import {toastNew} from '@components/toast';
import {LangPackKey} from '@lib/langPack';
import App from '@config/app';
import {copyTextToClipboard} from '@helpers/clipboard';
import cancelEvent from '@helpers/dom/cancelEvent';
import {attachClickEvent} from '@helpers/dom/clickEvent';

const PUBLIC_LINK_BASE = `${App.publicLinkBaseUrl}/`;
export default function anchorCopy(options: Partial<{
  // href: string,
  mePath: string,
  username: string
}> = {}) {
  const anchor = document.createElement('a');
  anchor.classList.add('anchor-copy');

  let copyWhat: string, copyText: LangPackKey = 'LinkCopied';
  if(options.mePath) {
    const href = PUBLIC_LINK_BASE + options.mePath;
    copyWhat = anchor.href = anchor.innerText = href;
  }

  if(options.username) {
    const href = PUBLIC_LINK_BASE + options.username;
    anchor.href = href;
    copyWhat = anchor.innerText = '@' + options.username;
    copyText = 'UsernameCopied';
  }

  attachClickEvent(anchor, (e) => {
    cancelEvent(e);
    copyTextToClipboard(copyWhat ?? anchor.href);
    toastNew({langPackKey: copyText});
  });

  return anchor;
}
