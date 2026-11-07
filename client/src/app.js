import {icon} from './ui/icons.js';
import {escapeHtml,usernameValid,initials,safeTime,formatDate,assertTextMessage,loadPreferences,savePreferences} from './services/security.js';
import {makeDemo,demoExpire} from './services/demo.js';
import {api} from './services/api.js';
import {live} from './services/live.js';
import {vault} from './services/vault.js';
import {encryptedStore} from './services/encryptedStorage.js';

export const FRONTEND_VERSION='v2.1.1';
const state={
  root:null,mode:'welcome',authMode:'login',route:'chats',settingsTab:'privacy',
  demo:false,user:null,chats:[],directory:[],selected:null,modal:null,modalData:null,
  search:'',directorySearch:'',contactResult:null,privacyVisible:false,
  vaultLocked:true,busy:false,toast:null,authError:'',prefs:loadPreferences(),
  connection:'offline',showMobileChat:false,lastActivity:Date.now(),recoveryKey:null,
  polling:false
};
const e=v=>escapeHtml(v??'');
const btn=(action,label,cls='btn btn-ghost',attrs='')=>`<button type="button" class="${cls}" data-action="${action}" ${attrs}>${label}</button>`;
const formBtn=(label,cls='btn btn-primary btn-block')=>`<button type="submit" class="${cls}" ${state.busy?'disabled':''}>${label}</button>`;
const avatar=(name,color='violet',size='')=>`<span class="avatar ${e(color)} ${e(size)}">${e(initials(name))}</span>`;
const banner=(text,kind='info')=>`<div class="notice ${kind}" role="status">${icon(kind==='danger'?'alert':'info',17)}<span>${e(text)}</span></div>`;
const currentChat=()=>state.chats.find(c=>c.id===state.selected);
const chatById=id=>state.chats.find(c=>c.id===id);
let toastTimer;
const showToast=(message,type='info')=>{state.toast={message,type};renderToast();clearTimeout(toastTimer);toastTimer=setTimeout(()=>{state.toast=null;renderToast();},5000);};
const generateId=()=>globalThis.crypto?.randomUUID?.()||`demo-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
const colorFor=name=>['violet','mint','pink','blue','amber','orange'][[...name].reduce((n,c)=>n+c.charCodeAt(0),0)%6];
const errorText=err=>err?.status===401?'Your session has expired. Please sign in again.':err?.message||'Something went wrong. Please try again.';
const chatLocked=chat=>state.vaultLocked||chat?.locked;
const validEmail=value=>typeof value==='string'&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)&&value.length<=254;
const validPassword=value=>typeof value==='string'&&value.length>=12&&value.length<=128;

function theme(){document.documentElement.dataset.theme=state.prefs.theme==='system'?(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'):state.prefs.theme;document.documentElement.dataset.density=state.prefs.density;}
function renderToast(){const el=state.root?.querySelector('#toast-slot');if(!el)return;el.innerHTML=state.toast?`<div role="status" class="toast ${e(state.toast.type)}">${icon(state.toast.type==='error'?'alert':'info',18)}<span>${e(state.toast.message)}</span>${btn('dismiss-toast',icon('x',16),'btn icon-btn','aria-label="Dismiss notification"')}</div>`:'';}
function render(){if(!state.root)return;theme();state.root.innerHTML=`${state.mode==='welcome'?welcomeView():state.mode==='auth'?authView():appView()}${modalView()}<div id="toast-slot" class="toast-slot"></div><div id="privacy-overlay"><div class="privacy-cover">${icon('shield',38)}<h2>Encrypto privacy screen</h2><p>Conversation content is concealed while this tab is hidden.</p></div></div>`;state.root.classList.toggle('privacy-hidden',state.privacyVisible);renderToast();if(state.modal)requestAnimationFrame(()=>state.root.querySelector('[role="dialog"] input, [role="dialog"] button')?.focus());}
function mobileBack(){return btn('back',icon('arrow',18)+' Back to conversations','btn btn-ghost mobile-page-back');}

function welcomeView(){return `<div class="welcome-shell">
  <nav class="welcome-nav"><div class="brand"><span class="brand-mark">${icon('logo',23)}</span><strong>encrypto<span class="brand-dot">.</span></strong></div><div class="welcome-nav-right"><span class="nav-status">${icon('shield',15)} Private conversations</span>${btn('show-login','Sign in','btn btn-ghost')}</div></nav>
  <main class="welcome-content"><div class="welcome-copy"><div class="eyebrow">${icon('sparkles',15)} PRIVATE CONVERSATIONS, BEAUTIFULLY SIMPLE</div><h1>Your conversations.<br><span>Your rules.</span></h1><p>Connect with people through a clean messaging experience backed by client-side cryptography, conversation passwords and local privacy controls.</p><div class="welcome-actions">${btn('show-register','Create account '+icon('right',18),'btn btn-primary btn-lg')}${btn('demo','Explore interactive demo','btn btn-secondary btn-lg')}</div><div class="welcome-footnote">${icon('info',15)} Demo mode is a visual simulation. It does not encrypt messages.</div></div>
  <div class="welcome-visual"><div class="mock-window"><div class="mock-bar"><span class="mock-dots"><b></b><b></b><b></b></span><span>Encrypto · Conversation</span>${icon('shield-check',16)}</div><div class="mock-person">${avatar('Alex','violet')}<div><strong>Alex Morgan</strong><small>Private conversation</small></div><span class="mock-lock">${icon('lock',17)}</span></div><div class="mock-conversation"><div class="mock-date">TODAY</div><div class="mock-bubble received">Hey! Did you see the new interface?<small>10:42</small></div><div class="mock-bubble sent">Yes! It looks great ✨<small>10:43</small></div><div class="mock-bubble received">Let's test it together.<small>10:44</small></div></div><div class="mock-compose"><span>Write a message...</span><span class="mock-send">${icon('send',16)}</span></div></div><div class="floating-privacy">${icon('shield-check',21)} <span><strong>Privacy-minded design</strong><small>Real cryptography in live mode</small></span></div></div></main>
  <div class="welcome-features"><div>${icon('lock',20)}<span><strong>Individual chat locks</strong><small>Keep each conversation protected</small></span></div><div>${icon('key',20)}<span><strong>Device identity keys</strong><small>Recovery and verifiable contact codes</small></span></div><div>${icon('shield',20)}<span><strong>Privacy controls</strong><small>Local vault, quick lock and more</small></span></div></div></div>`;}
function field(id,label,type,placeholder,autocomplete='off',attrs=''){
  return `<label for="${id}">${e(label)}</label><div class="field-wrap">${icon(type==='password'?'lock':type==='email'?'message':'users',17)}<input id="${id}" name="${id}" type="${type}" placeholder="${e(placeholder)}" autocomplete="${e(autocomplete)}" ${attrs} required>${type==='password'?btn('toggle-password',icon('eye',17),'btn icon-btn password-toggle',`data-target="${id}" aria-label="Show password"`):''}</div>`;
}
function authView(){const reg=state.authMode==='register';return `<div class="auth-shell"><div class="auth-decoration"><div class="brand brand-large"><span class="brand-mark">${icon('logo',26)}</span><strong>encrypto<span class="brand-dot">.</span></strong></div><div class="auth-hero"><div class="eyebrow">BUILT FOR PRIVATE COMMUNICATION</div><h1>Good conversations<br>deserve better privacy.</h1><p>Sign in to your Encrypto account, then unlock your locally encrypted device vault.</p><div class="auth-hero-bottom">${icon('shield-check',21)} Independent account, vault and chat credentials</div></div></div><main class="auth-main"><div class="auth-card auth-card-scroll">${btn('welcome',icon('arrow',17)+' Back to home','text-link')}<div class="auth-icon">${icon(reg?'users':'lock',24)}</div><h2>${reg?'Create your account':'Welcome back'}</h2><p class="subtle">${reg?'Set up your identity and local encrypted device vault.':'Sign in with your email address and account password.'}</p><form id="auth-form" novalidate>
  ${reg?field('username','Username','text','your_username','username','minlength="3" maxlength="30" pattern="[a-zA-Z0-9_]+"'):''}
  ${field('email','Email address','email','you@example.com','email','maxlength="254"')}
  ${field('password','Account password','password',reg?'At least 12 characters':'Enter your account password',reg?'new-password':'current-password','minlength="12" maxlength="128"')}
  ${reg?`${field('confirm','Confirm account password','password','Repeat account password','new-password')}${field('vaultPassword','Vault passphrase (local device)','password','Different from account password','new-password','minlength="12"')}${field('vaultConfirm','Confirm vault passphrase','password','Repeat vault passphrase','new-password','minlength="12"')}<p class="field-hint">The vault passphrase protects device keys; it is not uploaded. Save your one-time recovery key after registration.</p>`:''}
  ${state.authError?banner(state.authError,'danger'):''}${formBtn((reg?'Create account':'Sign in')+' '+icon('right',17),'btn btn-primary btn-block btn-lg')}
  </form><p class="auth-switch">${reg?'Already have an account?':'New to Encrypto?'} ${btn(reg?'show-login':'show-register',reg?'Sign in':'Create an account','text-link')}</p><div class="auth-separator">or</div>${btn('demo','Explore visual demo','btn btn-outline btn-block')}<p class="security-small">${icon('info',14)} The real website uses the provided backend and X3DH/Double Ratchet crypto module.</p></div></main></div>`;}

function appView(){return `<div class="app-shell route-${e(state.route)} ${state.showMobileChat?'mobile-chat-open':''}">${sidebarView()}<main class="main-workspace">${state.route==='chats'?chatPage():state.route==='contacts'?contactsPage():state.route==='security'?securityPage():state.route==='settings'?settingsPage():chatPage()}</main></div>${state.demo?'<div class="demo-ribbon" role="status">DEMO MODE · Messages are simulated, not encrypted</div>':''}`;}
function sidebarView(){const matches=state.chats.filter(c=>c.name.toLowerCase().includes(state.search.toLowerCase()));return `<aside class="sidebar"><div class="side-top"><div class="side-brand"><span class="brand-mark">${icon('logo',23)}</span><strong>encrypto<span class="brand-dot">.</span></strong><span class="side-top-action">${btn('open-settings',icon('settings',19),'btn icon-btn','aria-label="Settings" title="Settings"')}</span></div>
  <div class="account-tile">${avatar(state.user?.username||'You','orange')}<span class="account-title"><strong>${e(state.user?.username||'Demo user')}</strong><small>${state.demo?'Visual demo':state.vaultLocked?'Device vault locked':state.connection==='online'?'Encrypted account active':'Connection unavailable'}</small></span><span class="status-pip ${!state.demo&&!state.vaultLocked&&state.connection==='online'?'online':''}"></span></div>
  <div class="side-main-actions">${btn('new-chat',icon('plus',17)+' New chat','btn btn-primary btn-block')}</div>
  <div class="search-input">${icon('search',16)}<input type="search" data-search="chats" aria-label="Search conversations" placeholder="Search conversations" value="${e(state.search)}"></div>
  <nav class="side-nav" aria-label="Main navigation"><button type="button" class="nav-item ${state.route==='chats'?'active':''}" data-action="nav" data-route="chats">${icon('message',18)} Conversations</button><button type="button" class="nav-item ${state.route==='contacts'?'active':''}" data-action="nav" data-route="contacts">${icon('users',18)} Contacts</button><button type="button" class="nav-item ${state.route==='security'?'active':''}" data-action="nav" data-route="security">${icon('shield',18)} Privacy center</button></nav></div>
  <div class="side-list" id="sidebar-chat-list"><div class="side-list-head"><span>YOUR CONVERSATIONS</span><span>${state.chats.length}</span></div>${matches.length?matches.map(sideChat).join(''):'<div class="empty-side"><p>No conversations yet.</p></div>'}</div>
  <div class="side-bottom">${btn('lock-all',icon('lock',16)+' Lock all chats','btn btn-ghost sidebar-logout')}${btn('emergency-lock',icon('bolt',17)+' Emergency lock','btn btn-emergency btn-block')}${btn('signout',icon('logout',17)+' Sign out','btn btn-ghost sidebar-logout')}</div></aside>`;}
function sideChat(c){const preview=chatLocked(c)?'Locked conversation':state.prefs.hidePreview?'Message previews hidden':c.status==='pending'?'Invitation pending':(c.messages?.at(-1)?.text||'Start a private conversation');return `<button class="side-chat ${state.selected===c.id&&state.route==='chats'?'selected':''}" type="button" data-action="select-chat" data-id="${e(c.id)}">${avatar(c.name,c.color||'violet')}<span class="side-chat-body"><span class="side-chat-top"><strong>${e(c.name)}</strong><small>${c.lastActivity?e(safeTime(c.lastActivity)):''}</small></span><span class="side-chat-bottom"><span class="side-chat-preview">${chatLocked(c)?icon('lock',13):''} ${e(preview)}</span>${c.unread?`<span class="unread-count">${Number(c.unread)}</span>`:''}</span></span></button>`;}
function chatPage(){const c=currentChat();if(!c)return `<div class="start-panel"><div class="start-illustration">${icon('message',55)}<span>${icon('shield-check',20)}</span></div><h1>Your conversations, in one place</h1><p>Select a conversation from the left or create a new one to start private messaging.</p>${btn('new-chat',icon('plus',17)+' New conversation','btn btn-primary btn-lg')}<div class="start-tags"><span>${icon('lock',15)} Chat passwords</span><span>${icon('shield',15)} Device privacy</span></div>${state.vaultLocked?banner('Your local vault is locked. Unlock it to access encrypted conversations.','warning'):''}</div>`;
  const locked=chatLocked(c);return `<section class="chat-layout"><header class="chat-header">${btn('back',icon('arrow',19),'btn icon-btn back-btn','aria-label="Back"')}${avatar(c.name,c.color,'sm')}<button class="chat-header-contact" type="button" data-action="chat-info"><strong>${e(c.name)}</strong><span>${c.status==='pending'?'Pending invitation':locked?'Conversation locked':state.demo?'Demo — not encrypted':'End-to-end session · '+(c.verified?'Identity confirmed':'Identity not independently verified')}</span></button><div class="chat-header-actions">${btn('identity-modal',icon('shield',19),'btn icon-btn','aria-label="Identity details" title="Identity details"')}${btn('expiry-modal',icon('clock',19),'btn icon-btn','aria-label="Disappearing messages" title="Disappearing messages"')}${btn(locked?'open-unlock':'lock-chat',icon(locked?'unlock':'lock',19),'btn icon-btn','aria-label="Lock or unlock chat" title="Chat lock"')}${btn('chat-menu',icon('dots',20),'btn icon-btn','aria-label="More conversation actions" title="More actions"')}</div></header>
  <div class="security-strip">${icon(locked?'lock':'shield-check',15)}<span>${c.status==='pending'?'An invitation must be accepted before exchanging messages.':locked?'Unlock the conversation to read or send messages.':state.demo?'Simulated messages — no encryption is active.':c.verified?'Identity marked verified locally. Client-side encryption is active.':'Client-side encrypted. Compare identity codes to verify the contact.'}</span>${!locked?btn('identity-modal','Safety info','btn text-action'):''}</div>
  ${c.status==='pending'?pendingChatView(c):c.status==='declined'?`<div class="chat-locked"><h2>Invitation declined</h2><p>This conversation is not active.</p></div>`:locked?lockedChatView(c):`<div id="message-scroll" class="message-scroll"><div class="chat-day"><span>CONVERSATION</span></div>${c.messages?.length?c.messages.filter(m=>!m.expiresAt||Date.now()<new Date(m.expiresAt)).map(messageBubble).join(''):`<div class="empty-messages">${icon('message',32)}<h3>Start a private conversation</h3><p>Messages will appear here after you send or receive them.</p></div>`}</div><form id="message-form" class="composer"><div class="composer-field"><textarea id="message-text" name="message" rows="1" maxlength="4000" placeholder="Write a message..." aria-label="Message" ${state.busy?'disabled':''}></textarea><small>Enter to send · Shift+Enter for a new line</small></div><button type="submit" class="send-button" ${state.busy?'disabled':''} aria-label="Send message" title="Send">${icon('send',21)}</button></form>`}</section>`;}
function messageBubble(m){const status=m.status==='failed'?icon('alert',13):m.status==='sending'?icon('clock',13):m.status==='sent'?icon('check',13):'';return `<article class="message-row ${m.from==='me'?'outgoing':'incoming'}"><div class="message-bubble"><div class="bubble-text">${e(m.text)}</div><div class="bubble-meta"><time>${e(safeTime(m.at))}</time><span>${status}</span>${btn('message-actions',icon('dots',15),'btn message-options',`data-id="${e(m.id)}" aria-label="Message options"`)}</div></div></article>`;}
function pendingChatView(c){const incoming=c.requestedBy!==state.user?.id;return `<div class="chat-locked"><div class="locked-medallion">${icon('clock',36)}</div><h2>${incoming?'New conversation request':'Invitation sent'}</h2><p>${incoming?`${e(c.name)} would like to start a private chat.`:`Waiting for ${e(c.name)} to accept your invitation.`}</p>${incoming?`<div class="action-row">${btn('accept-invite',icon('check',17)+' Accept invitation','btn btn-primary btn-lg')}${btn('decline-invite','Decline','btn btn-outline')}</div>`:btn('refresh-chats',icon('refresh',16)+' Refresh invitations','btn btn-outline')}<span class="locked-subtext">Encrypted messages are disabled until the chat is active.</span></div>`;}
function lockedChatView(c){return `<div class="chat-locked"><div class="locked-medallion">${icon('lock',37)}</div><h2>${state.vaultLocked?'Your device vault is locked':'This conversation is locked'}</h2><p>${state.vaultLocked?'Unlock your device vault to access locally encrypted state.':state.demo?'Open this simulated conversation.':'Enter your personal chat password to access locally protected messages.'}</p>${btn('open-unlock',icon('unlock',18)+(state.vaultLocked?' Unlock vault':' Unlock conversation'),'btn btn-primary btn-lg')}<span class="locked-subtext">${e(c.name)} · Protected conversation</span></div><div class="composer composer-disabled"><div>${icon('lock',17)} Unlock to send a message</div></div>`;}
function contactsPage(){return `<div class="content-page">${mobileBack()}<header class="page-header"><div><span class="section-kicker">YOUR NETWORK</span><h1>Contacts</h1><p>Look up someone by their exact username.</p></div>${btn('new-chat',icon('plus',17)+' New chat','btn btn-primary')}</header><div class="surface-card"><form id="directory-form" class="contact-toolbar"><div class="search-input wide">${icon('search',17)}<input type="search" name="username" aria-label="Look up username" placeholder="Enter exact username" value="${e(state.directorySearch)}" maxlength="30" required></div><button type="submit" class="btn btn-outline">${icon('search',16)} Search</button></form><div id="directory-results">${state.contactResult?directoryItem(state.contactResult):state.demo?state.directory.map(directoryItem).join(''):`<div class="empty-directory">${icon('users',30)}<h3>Search by username</h3><p>The current server supports exact username lookup, not a public directory.</p></div>`}</div></div></div>`;}
function directoryItem(item){return `<div class="directory-item">${avatar(item.username,colorFor(item.username))}<span><strong>@${e(item.username)}</strong><small>${state.demo?'Demo contact':item.cryptoEnrolled?'Public encryption identity enrolled':'Encryption identity not available'}</small></span>${btn('start-with-contact','Message '+icon('right',16),'btn btn-outline',`data-username="${e(item.username)}"`)}</div>`;}
function securityPage(){return `<div class="content-page">${mobileBack()}<header class="page-header"><div><span class="section-kicker">PRIVACY CENTER</span><h1>Security overview</h1><p>Manage your local security controls and encryption identity.</p></div></header>${state.demo?banner('This is a simulated demo. No real cryptography or verification takes place.','warning'):state.vaultLocked?banner('The device vault is locked. Unlock it to access the crypto identity.','warning'):banner('The supplied X3DH / Double Ratchet module is active in this browser. Verify contact identities out of band.','info')}<div class="security-cards"><div class="security-summary"><div class="summary-icon">${icon('lock',27)}</div><h3>Device vault</h3><p>${state.vaultLocked?'Locked':'Unlocked'} · ${state.demo?'simulated':'local encrypted storage'}</p>${btn(state.vaultLocked?'unlock-vault-modal':'lock-all',icon(state.vaultLocked?'unlock':'lock',17)+(state.vaultLocked?' Unlock vault':' Lock vault'),'btn btn-outline')}</div><div class="security-summary"><div class="summary-icon">${icon('shield-check',27)}</div><h3>Identity verification</h3><p>${state.chats.filter(c=>c.verified).length} locally verified contacts</p>${btn('select-first-chat','Review identities '+icon('right',17),'btn btn-outline')}</div><div class="security-summary"><div class="summary-icon">${icon('clock',27)}</div><h3>Auto-lock</h3><p>${state.prefs.autoLock?`After ${state.prefs.autoLock} minutes`:'Disabled'}</p>${btn('settings-privacy','Configure '+icon('right',17),'btn btn-outline')}</div></div><div class="surface-card security-section"><div><h2>Quick privacy actions</h2><p>Access your device and conversation controls.</p></div>${securityRow('lock','Lock all','Hide conversations and require a vault passphrase.','lock-all','Lock now')}${securityRow('bolt','Emergency lock','Immediately conceal the entire workspace.','emergency-lock','Emergency lock','danger')}${securityRow('trash','Delete local data','Removes this browser’s Encrypto vault and cached messages.','delete-modal','Delete local data','danger')}</div><div class="surface-card security-section"><h2>Your contact code</h2><p class="small-mono">${state.demo?'Not available in demo':state.vaultLocked?'Unlock the vault to display':e(live.account?.contactCode||'Unavailable')}</p>${btn('copy-contact-code',icon('copy',16)+' Copy contact code','btn btn-outline',state.vaultLocked||state.demo?'disabled':'')}<p class="subtle">Contact codes are public. Your recovery key is private and should never be shared.</p></div><div class="surface-card security-section"><h2>Current security limitations</h2><p>Browser screenshots cannot be blocked. Shared four-digit chat codes, mutual code rotation and configurable disappearing messages are not implemented in the supplied protocol; the interface does not claim otherwise. This is a development build, not a completed security audit.</p></div></div>`;}
function securityRow(ic,title,desc,act,label,danger=''){return `<div class="security-action-row"><div class="security-action-desc">${icon(ic,21)}<span><strong>${e(title)}</strong><small>${e(desc)}</small></span></div>${btn(act,label,danger==='danger'?'btn btn-danger':'btn btn-outline')}</div>`;}
const settingTabs=[['account','users','Account'],['privacy','shield','Privacy & security'],['appearance','sun','Appearance'],['notifications','bell','Notifications'],['about','info','About']];
function settingsPage(){return `<div class="content-page settings-content">${mobileBack()}<header class="page-header"><div><span class="section-kicker">PREFERENCES</span><h1>Settings</h1><p>Make Encrypto work the way you prefer.</p></div></header><div class="settings-layout"><nav class="settings-nav" aria-label="Settings sections">${settingTabs.map(([id,ic,label])=>`<button class="settings-tab ${state.settingsTab===id?'selected':''}" type="button" data-action="settings-tab" data-tab="${id}">${icon(ic,18)} ${label}</button>`).join('')}</nav><section class="settings-panel">${settingsContent()}</section></div></div>`;}
function settingRow(ic,title,description,widget){return `<div class="setting-row"><span class="setting-icon">${icon(ic,19)}</span><span class="setting-details"><strong>${e(title)}</strong><small>${e(description)}</small></span><span class="setting-control">${widget}</span></div>`;}
function toggle(key){return `<label class="toggle" aria-label="${e(key)}"><input type="checkbox" data-pref="${e(key)}" ${state.prefs[key]?'checked':''}><span class="toggle-track"></span></label>`;}
function choice(key,options){return `<select data-pref="${e(key)}" aria-label="${e(key)}">${options.map(([val,label])=>`<option value="${e(val)}" ${String(state.prefs[key])===String(val)?'selected':''}>${e(label)}</option>`).join('')}</select>`;}
function settingsContent(){switch(state.settingsTab){
  case 'account':return `<h2>Account</h2><p class="subtle">Your authenticated Encrypto identity.</p>${settingRow('users','Username',state.user?.username||'Demo user','')}${settingRow('message','Email',state.user?.email||'Not available','')}${settingRow('key','Public contact code','Available in the Privacy center',btn('security-center','View identity','btn btn-outline'))}${settingRow('lock','Account password','Password changes are not provided by this server','<button type="button" class="btn btn-outline" disabled>Change password</button>')}${settingRow('logout','Sign out','End your account session',btn('signout','Sign out','btn btn-outline'))}`;
  case 'privacy':return `<h2>Privacy & security</h2><p class="subtle">Control the locally displayed and cached content.</p>${settingRow('clock','Auto-lock','Hide decrypted conversations after inactivity',choice('autoLock',[[0,'Never'],[1,'1 minute'],[5,'5 minutes'],[15,'15 minutes'],[30,'30 minutes']]))}${settingRow('shield','Screen privacy','Conceal the application when the tab is hidden',toggle('privacyOnHide'))}${settingRow('eye-off','Hide chat previews','Hide message snippets even while chats are unlocked',toggle('hidePreview'))}${settingRow('lock','Lock all chats','Conceal this browser vault now',btn('lock-all','Lock now','btn btn-outline'))}${settingRow('bolt','Emergency lock','Quickly conceal conversations',btn('emergency-lock','Emergency lock','btn btn-danger'))}${settingRow('trash','Delete local device data','Best-effort browser deletion',btn('delete-modal','Delete local data','btn btn-outline danger-outline'))}`;
  case 'appearance':return `<h2>Appearance</h2><p class="subtle">A familiar interface on any screen.</p>${settingRow('sun','Theme','Change the appearance',choice('theme',[['dark','Dark'],['light','Light'],['system','System']]))}${settingRow('message','Density','Choose message spacing',choice('density',[['comfortable','Comfortable'],['compact','Compact']]))}`;
  case 'notifications':return `<h2>Notifications</h2><p class="subtle">The provided backend sends realtime availability events; browser notifications are not implemented.</p>${settingRow('bell','Browser notifications','Not supported in this build','<button type="button" class="btn btn-outline" disabled>Not available</button>')}${settingRow('eye-off','Hide previews','Keep message details concealed',toggle('hidePreview'))}`;
  default:return `<h2>About Encrypto</h2><p class="subtle">Encrypto frontend · verified v2.1.1</p>${banner('Includes the provided Node.js API and Web Crypto X3DH/Double Ratchet module. No formal security audit has been performed.','info')}<p>Protected one-to-one chats, local password locks and identity verification are provided through the uploaded modules. Group messaging, screenshot prevention, shared PIN enforcement and configurable deletion timers are not available.</p>${btn('security-center',icon('shield',16)+' Privacy center','btn btn-outline')}`;
}}
function modalView(){if(!state.modal)return '';let title='',subtitle='',body='';const c=currentChat();const close=state.modal==='recovery-key'?'':btn('close-modal',icon('x',20),'btn icon-btn','aria-label="Close dialog"');
  const cancel=btn('close-modal','Cancel','btn btn-outline');
  switch(state.modal){
  case 'new-chat':title='New private conversation';subtitle='Invite a user by username';body=`${state.demo?banner('Demo conversation setup is simulated.','warning'):banner('Invitations are sent to the selected user. You will exchange messages only after acceptance.','info')}<form id="new-chat-form" class="modal-form"><label for="recipient">Username</label><input class="standalone-input" id="recipient" name="recipient" value="${e(state.modalData?.username||'')}" pattern="[a-zA-Z0-9_]{3,30}" maxlength="30" placeholder="contact_username" required><label for="chatPassword">Your personal chat password</label><input class="standalone-input" type="password" id="chatPassword" name="chatPassword" minlength="6" maxlength="1024" autocomplete="new-password" placeholder="At least 6 characters" required><label for="chatConfirm">Confirm chat password</label><input class="standalone-input" type="password" name="chatConfirm" id="chatConfirm" required>${banner('The shared 4-digit code discussed in planning is NOT implemented by the provided cryptography module. It is not required or falsely claimed here.','warning')}<div class="modal-buttons">${cancel}${formBtn('Send invitation '+icon('right',16),'btn btn-primary')}</div></form>`;break;
  case 'vault':title=state.vaultLocked?'Unlock device vault':'Device vault';subtitle='Private device state never leaves this browser';body=`${banner('Enter the separate passphrase you chose when creating the local device vault.','info')}<form id="vault-form" class="modal-form"><label for="vaultPass">Vault passphrase</label><input id="vaultPass" class="standalone-input" name="passphrase" type="password" autocomplete="off" minlength="12" placeholder="Your local vault passphrase" required><div class="modal-buttons">${cancel}${formBtn('Unlock vault '+icon('unlock',17),'btn btn-primary')}</div></form>${state.demo?'':`<div class="divider-line"></div><p class="subtle">Lost this device's vault? Restore your identity with the recovery key.</p>${btn('restore-vault','Restore with recovery key','btn btn-outline btn-block')}`}`;break;
  case 'restore':title='Restore encrypted identity';subtitle='Recover your device-side identity using the recovery key';body=`${banner('Restoring cannot recover old chat history or the previous ratchet state. Existing conversations will need new sessions.','warning')}<form id="restore-form" class="modal-form"><label for="recoveryInput">Recovery key</label><textarea id="recoveryInput" name="recoveryKey" class="standalone-input wide-input" rows="3" placeholder="Your one-time recovery key" required></textarea><label for="restorePass">New vault passphrase</label><input id="restorePass" name="vaultPassword" type="password" class="standalone-input" minlength="12" required><label for="restoreConfirm">Confirm vault passphrase</label><input id="restoreConfirm" name="vaultConfirm" type="password" class="standalone-input" minlength="12" required><div class="modal-buttons">${cancel}${formBtn('Restore identity','btn btn-primary')}</div></form>`;break;
  case 'recovery-key':title='Save your recovery key';subtitle='Shown once · Do not share it with anyone';body=`${banner('This key can recover your identity, but not old conversations or local history. Write it down securely. We do not save the recovery key.','danger')}<label class="modal-field-label" for="recoveryDisplay">Your recovery key</label><textarea class="standalone-input wide-input recovery-display" id="recoveryDisplay" readonly rows="3">${e(state.recoveryKey)}</textarea><div class="modal-buttons">${btn('copy-recovery',icon('copy',16)+' Copy','btn btn-outline')}${btn('confirm-recovery','I have saved it','btn btn-primary')}</div>`;break;
  case 'set-password':title='Protect this conversation';subtitle=`@${c?.username||''}`;body=`${banner('This password is local to your device. The other participant chooses their own password.','info')}<form id="set-password-form" class="modal-form"><label for="setChatPass">Your chat password</label><input id="setChatPass" class="standalone-input" name="password" type="password" minlength="6" required autocomplete="new-password"><label for="setChatConfirm">Confirm password</label><input id="setChatConfirm" class="standalone-input" name="confirm" type="password" minlength="6" required autocomplete="new-password"><div class="modal-buttons">${cancel}${formBtn('Protect chat','btn btn-primary')}</div></form>`;break;
  case 'unlock':title='Unlock conversation';subtitle=`Protected chat with @${c?.username||''}`;body=`${banner('Enter your independently chosen personal chat password.','info')}<form id="chat-unlock-form" class="modal-form"><label for="unlockPass">Chat password</label><input id="unlockPass" class="standalone-input" name="password" type="password" autocomplete="off" required><div class="modal-buttons">${cancel}${formBtn(icon('unlock',17)+' Unlock conversation','btn btn-primary')}</div></form>${state.demo?banner('Demo unlock is simulated; no password is checked.','warning'):''}`;break;
  case 'chat-info':title='Conversation details';subtitle=c?.name||'';body=`<div class="detail-line"><span>Contact</span><strong>@${e(c?.username||'')}</strong></div><div class="detail-line"><span>Invitation</span><strong>${e(c?.status||'')}</strong></div><div class="detail-line"><span>Chat status</span><strong>${chatLocked(c)?'Locked':'Unlocked'}</strong></div><div class="detail-line"><span>Identity verification</span><strong>${c?.verified?'Locally marked verified':'Unverified'}</strong></div><div class="modal-vertical-actions">${btn('identity-modal',icon('shield',17)+' Verify identity','btn btn-outline btn-block')}${btn('expiry-modal',icon('clock',17)+' Disappearing messages','btn btn-outline btn-block')}${btn('code-modal',icon('key',17)+' Shared-code status','btn btn-outline btn-block')}${btn('change-chat-password',icon('lock',17)+' Change my chat password','btn btn-outline btn-block')}${btn('delete-conversation-modal',icon('trash',17)+' Delete local chat data','btn btn-outline btn-block danger-outline')}</div>`;break;
  case 'identity':title='Verify contact identity';subtitle=`@${c?.username||''}`;body=`${state.demo?banner('Fingerprints cannot be verified in the simulated demo.','warning'):banner('Compare the full public contact code with your contact over a separate trusted channel before marking verified.','info')}<div class="detail-line"><span>Verified locally</span><strong>${c?.verified?'Yes':'No'}</strong></div><p class="modal-field-label">Contact code</p><div class="code-display">${e(c?.contactCode||'Unlock the vault to retrieve contact identity')}</div><div class="modal-buttons">${btn('copy-peer-code',icon('copy',16)+' Copy code','btn btn-outline',!c?.contactCode?'disabled':'')}${btn('mark-verified',icon('check',16)+' Mark verified','btn btn-primary',state.demo||state.vaultLocked||!c?.contactCode?'disabled':'')}</div>`;break;
  case 'expiry':title='Disappearing messages';subtitle='Message retention settings';body=`${banner('The supplied server retains undelivered ciphertext for up to seven days and purges acknowledged ciphertext. Custom per-chat disappearing timers are not implemented.','warning')}<div class="detail-line"><span>Server ciphertext policy</span><strong>7 days (undelivered)</strong></div><div class="detail-line"><span>Custom timer</span><strong>Unavailable</strong></div>${state.demo?`<form id="expiry-demo-form" class="modal-form"><label for="expiryValue">Demo-only local timer</label><select id="expiryValue" class="standalone-input" name="expiry"><option value="0">Off</option><option value="24">24 hours</option><option value="48">48 hours</option><option value="72">72 hours</option></select><div class="modal-buttons">${cancel}${formBtn('Apply demo timer','btn btn-primary')}</div></form>`:`<div class="modal-buttons">${btn('close-modal','Close','btn btn-outline')}</div>`}`;break;
  case 'code':title='Shared four-digit code';subtitle='Planned security feature';body=`${banner('The uploaded cryptography module does not enforce a shared four-digit code or support mutual code changes. No code is being collected, stored, or transmitted.','warning')}<p class="modal-description">Current security is based on the authenticated public identity, X3DH/Double Ratchet session, a locally protected device vault, and each participant’s own chat password.</p><div class="modal-buttons">${btn('close-modal','Close','btn btn-primary')}</div>`;break;
  case 'change-password':title='Change your chat password';subtitle=`@${c?.username||''}`;body=`<form id="change-password-form" class="modal-form"><label for="oldChatPass">Current chat password</label><input id="oldChatPass" class="standalone-input" name="current" type="password" required><label for="newChatPass">New chat password</label><input id="newChatPass" class="standalone-input" name="password" type="password" minlength="6" required><label for="newChatConfirm">Confirm new password</label><input id="newChatConfirm" class="standalone-input" name="confirm" type="password" minlength="6" required><div class="modal-buttons">${cancel}${formBtn('Change password','btn btn-primary')}</div></form>`;break;
  case 'chat-menu':title='Conversation actions';subtitle=c?.name||'';body=`<div class="modal-vertical-actions">${btn('chat-info',icon('info',17)+' Conversation details','btn btn-outline btn-block')}${btn('identity-modal',icon('shield',17)+' Verify contact','btn btn-outline btn-block')}${btn('expiry-modal',icon('clock',17)+' Disappearing messages','btn btn-outline btn-block')}${btn('code-modal',icon('key',17)+' Shared-code status','btn btn-outline btn-block')}${btn('delete-conversation-modal',icon('trash',17)+' Delete local conversation','btn btn-outline btn-block danger-outline')}</div>`;break;
  case 'delete-chat':title='Delete local conversation';subtitle=c?.name||'';body=`${banner('Deletes local messages, keys, and session for this contact. Does not remove the server invitation or the recipient’s messages. Ratchet history cannot be recovered.','danger')}<form id="delete-chat-form" class="modal-form"><label for="deleteChatConfirm">Type DELETE to confirm</label><input class="standalone-input" id="deleteChatConfirm" name="confirm" autocomplete="off" placeholder="DELETE" required><div class="modal-buttons">${cancel}${formBtn('Delete local data','btn btn-danger')}</div></form>`;break;
  case 'delete-all':title='Delete local Encrypto data';subtitle='This cannot be undone';body=`${banner('Removes encrypted local state on this browser origin. This is not guaranteed forensic erasure; remote ciphertext, messages on recipient devices and backups are unaffected. You may lose access to old chats.','danger')}<form id="delete-all-form" class="modal-form"><label for="deleteAllConfirm">Type DELETE to confirm</label><input class="standalone-input" name="confirm" id="deleteAllConfirm" autocomplete="off" placeholder="DELETE" required><div class="modal-buttons">${cancel}${formBtn('Delete local data','btn btn-danger')}</div></form>`;break;
  case 'message':{const m=c?.messages?.find(m=>m.id===state.modalData?.id);title='Message actions';subtitle=m?safeTime(m.at):'';body=`<div class="modal-vertical-actions">${btn('copy-message',icon('copy',17)+' Copy text','btn btn-outline btn-block')}${btn('message-info',icon('info',17)+' Message information','btn btn-outline btn-block')}${m?.status==='failed'?btn('retry-message',icon('refresh',17)+' Retry saved ciphertext','btn btn-outline btn-block'):''}${btn('delete-message',icon('trash',17)+' Delete local copy','btn btn-outline btn-block danger-outline')}</div>`;break;}
  case 'message-info':{const m=c?.messages?.find(m=>m.id===state.modalData?.id);title='Message details';subtitle='Local metadata';body=`<div class="detail-line"><span>Time</span><strong>${e(m?.at?`${formatDate(m.at)} ${safeTime(m.at)}`:'Unknown')}</strong></div><div class="detail-line"><span>Status</span><strong>${e(m?.status||'Unknown')}</strong></div><div class="detail-line"><span>Delivery</span><strong>Not independently confirmed</strong></div><div class="modal-buttons">${btn('close-modal','Close','btn btn-outline')}</div>`;break;}
  default:return '';
  }
  return `<div class="modal-backdrop" data-action="close-modal-backdrop"><section class="modal-card" role="dialog" aria-modal="true" aria-label="${e(title)}"><header class="modal-head"><div><h2>${e(title)}</h2><p>${e(subtitle)}</p></div>${close}</header><div class="modal-body">${body}</div></section></div>`;
}

function setRoute(route){state.route=route;state.showMobileChat=route!=='chats';state.modal=null;render();}
function closeModal(){state.modal=null;state.modalData=null;render();}
function openModal(name,data=null){state.modal=name;state.modalData=data;render();}
function setUser(user){state.user=user;state.demo=false;state.mode='app';state.route='chats';state.selected=null;state.vaultLocked=true;state.connection='online';state.showMobileChat=false;}
async function bootSession(){try{const {user}=await api.me();if(user){setUser(user);render();await refreshChats();}}catch{state.mode='welcome';render();}}
async function refreshChats(){if(state.demo)return;const {chats=[]}=await api.listChats();const old=new Map(state.chats.map(c=>[c.id,c]));state.chats=chats.map(item=>{
  const prior=old.get(item.id);
  return {...prior,id:item.id,username:item.contactUsername,name:item.contactUsername,color:colorFor(item.contactUsername),
    requestedBy:item.requestedBy,status:item.status,locked:prior?.locked??true,verified:prior?.verified??false,
    messages:prior?.messages??[],unread:prior?.unread??0,lastActivity:prior?.lastActivity||item.createdAt,contactCode:prior?.contactCode??null};
});if(state.selected&&!chatById(state.selected))state.selected=null;render();}
function leaveSession(){state.mode='welcome';state.demo=false;state.user=null;state.chats=[];state.selected=null;state.modal=null;state.vaultLocked=true;state.connection='offline';state.recoveryKey=null;state.contactResult=null;state.showMobileChat=false;render();}
async function lockAll(reason='manual'){
  state.vaultLocked=true;state.showMobileChat=false;state.modal=null;
  state.chats.forEach(c=>{c.locked=true;c.messages=[];});render();
  if(!state.demo)await live.lock();
  if(reason==='emergency')showToast('Emergency lock activated. Sensitive content is hidden.');
  else if(reason==='inactivity')showToast('Device vault locked due to inactivity.');
  else showToast('Device vault locked.');
}
async function signOut(){
  if(!state.demo){await lockAll();try{await api.logout();}catch{showToast('Signed out locally; server logout could not be confirmed.','error');}}
  leaveSession();
}
async function demoMode(){const seed=makeDemo();Object.assign(state,{demo:true,user:{...seed.user,id:'demo'},chats:seed.chats.map(c=>({...c,status:'active'})),directory:seed.directory,selected:null,mode:'app',route:'chats',vaultLocked:false,connection:'demo',showMobileChat:false});render();showToast('Interactive demo only — simulated messages, no encryption.');}
async function selectChat(id){const c=chatById(id);if(!c)return;state.route='chats';state.selected=id;state.showMobileChat=true;render();
  if(c.status!=='active')return;
  if(state.vaultLocked){openModal('vault');return;}
  if(state.demo){if(c.locked)openModal('unlock');return;}
  try{const identity=await live.identityFor(c.username);c.contactCode=identity.contactCode;c.verified=identity.verified;
    const has=await live.hasPassword(c.username);
    if(!has){openModal('set-password');return;}
    c.locked=await live.isLocked(c.username);
    if(c.locked)openModal('unlock');else {c.messages=await live.loadHistory(c.username);await syncInbox();render();scrollMessages();}
  }catch(error){showToast(errorText(error),'error');render();}
}
function scrollMessages(){requestAnimationFrame(()=>{const el=state.root.querySelector('#message-scroll');if(el)el.scrollTop=el.scrollHeight;});}
async function syncInbox(){if(state.demo||state.vaultLocked||state.polling)return;state.polling=true;try{
  const captured=await live.captureInbox();
  const processed=await live.processPending(state.chats,(chat,msg)=>{chat.messages=[...(chat.messages||[]),msg];chat.lastActivity=msg.at;if(chat.id!==state.selected)chat.unread++;});
  if(captured||processed){const draft=state.root.querySelector('#message-text')?.value||'';render();const input=state.root.querySelector('#message-text');if(input)input.value=draft;scrollMessages();}
}catch(err){if(err?.status===401){await lockAll();showToast('Session expired. Please sign in again.','error');}else showToast(`Message synchronization: ${errorText(err)}`,'error');}
finally{state.polling=false;}}
function startRealtime(){live.listener=()=>{if(!state.vaultLocked)syncInbox();};}
function getForm(form){return Object.fromEntries(new FormData(form));}
async function handleSubmit(form){if(state.busy)return;const name=form.id;const data=getForm(form);state.busy=true;const submit=form.querySelector('[type="submit"]');if(submit)submit.disabled=true;
  try{
  if(name==='auth-form'){
    if(!validEmail(data.email))throw Error('Enter a valid email address.');
    if(state.authMode==='register'){
      if(!usernameValid(data.username)&&!/^[A-Za-z0-9_]{3,30}$/.test(data.username))throw Error('Username must be 3–30 letters, numbers or underscores.');
      if(!validPassword(data.password)||data.password!==data.confirm)throw Error('Account passwords must match and have 12–128 characters.');
      if(!validPassword(data.vaultPassword)||data.vaultPassword!==data.vaultConfirm)throw Error('Vault passphrases must match and have 12–128 characters.');
      if(data.vaultPassword===data.password)throw Error('Choose a different passphrase for your device vault.');
      const {account,recoveryKey}=await live.createIdentity();
      const bundle=await account.createPreKeyUpload({oneTimePreKeyCount:20});
      const {user}=await api.register({username:data.username,email:data.email,password:data.password,publicKey:bundle.identityKey});
      await api.login(data.email,data.password);
      await live.registerDevice(user,account,data.vaultPassword);
      setUser(user);state.vaultLocked=false;startRealtime();render();
      try{await live.enroll(false,bundle);}catch(error){showToast(`Account created but encryption-key enrollment failed: ${errorText(error)}`,'error');}
      state.recoveryKey=recoveryKey;openModal('recovery-key');
    }else{
      if(!data.password)throw Error('Enter your account password.');
      const {user}=await api.login(data.email,data.password);
      setUser(user);render();await refreshChats();
      openModal('vault');
    }
  }else if(name==='vault-form'){
    if(state.demo){state.vaultLocked=false;closeModal();return;}
    await live.unlock(state.user,data.passphrase);await live.enroll();
    startRealtime();state.vaultLocked=false;state.chats.forEach(c=>{c.locked=true;c.messages=[];});
    closeModal();await refreshChats();await syncInbox();showToast('Device vault unlocked.');
  }else if(name==='restore-form'){
    if(!validPassword(data.vaultPassword)||data.vaultPassword!==data.vaultConfirm)throw Error('Vault passphrases must match and be at least 12 characters.');
    await live.restore(state.user,data.recoveryKey,data.vaultPassword);startRealtime();state.vaultLocked=false;closeModal();await refreshChats();showToast('Identity recovered. Old chat sessions and history are not restored.');
  }else if(name==='new-chat-form'){
    const username=data.recipient.trim().toLowerCase();if(!/^[a-z0-9_]{3,30}$/.test(username))throw Error('Enter a valid recipient username.');
    if(username===state.user.username)throw Error('You cannot create a conversation with yourself.');
    if(!data.chatPassword||data.chatPassword.length<6||data.chatPassword!==data.chatConfirm)throw Error('Personal chat passwords must match and have at least 6 characters.');
    if(state.demo){let c=state.chats.find(c=>c.username===username);if(!c){c={id:generateId(),username,name:username,color:colorFor(username),status:'active',requestedBy:'demo',locked:false,verified:false,unread:0,messages:[],lastActivity:new Date().toISOString()};state.chats.unshift(c);}c.locked=false;state.modal=null;await selectChat(c.id);showToast('Demo chat created. Password was not stored or verified.');}
    else{
      if(state.vaultLocked)throw Error('Unlock the device vault before creating a chat.');
      await live.identityFor(username);
      const result=await api.createChat(username);
      await live.setPassword(username,data.chatPassword);
      closeModal();await refreshChats();await selectChat(result.chatId);
      showToast('Invitation sent. Messaging starts once the contact accepts.');
    }
  }else if(name==='set-password-form'){
    const c=currentChat();if(!c)throw Error('No conversation selected.');
    if(data.password.length<6||data.password!==data.confirm)throw Error('Chat passwords must match and contain at least 6 characters.');
    if(!state.demo)await live.setPassword(c.username,data.password);
    c.locked=false;c.messages=[];closeModal();if(!state.demo)c.messages=await live.loadHistory(c.username);await syncInbox();render();scrollMessages();showToast(state.demo?'Demo chat open.':'Local chat password enabled.');
  }else if(name==='chat-unlock-form'){
    const c=currentChat();if(!c)throw Error('No conversation selected.');
    if(!state.demo)c.messages=await live.unlockChat(c.username,data.password);
    c.locked=false;c.unread=0;closeModal();await syncInbox();render();scrollMessages();
  }else if(name==='message-form'){
    const c=currentChat();if(!c||chatLocked(c))throw Error('Unlock the chat before sending.');
    const text=assertTextMessage(data.message);
    if(state.demo){c.messages.push({id:generateId(),from:'me',text,at:new Date().toISOString(),status:'demo',expiresAt:c.expiry?Date.now()+c.expiry*3600000:null});c.lastActivity=new Date().toISOString();}
    else{const prev=c.messages.slice();try{const msg=await live.sendMessage(c,text,prev);c.messages=[...prev,msg];c.lastActivity=msg.at;}
      catch(error){try{c.messages=await live.loadHistory(c.username);}catch{}throw error;}}
    render();scrollMessages();
  }else if(name==='directory-form'){
    const username=data.username.trim().toLowerCase();state.directorySearch=username;
    if(!/^[a-z0-9_]{3,30}$/.test(username))throw Error('Enter an exact username (3–30 letters, digits or underscores).');
    state.contactResult=state.demo?state.directory.find(u=>u.username===username):await api.lookup(username);
    if(!state.contactResult)throw Error('No user found with that username.');render();
  }else if(name==='change-password-form'){
    const c=currentChat();if(!c)throw Error('Select a chat.');
    if(!data.password||data.password.length<6||data.password!==data.confirm)throw Error('New chat passwords must match and contain at least six characters.');
    if(!state.demo){const {contactCode}=await live.identityFor(c.username);await live.account.changeChatPassword(contactCode,data.current,data.password);}
    closeModal();showToast('Personal chat password updated.');
  }else if(name==='expiry-demo-form'){
    const c=currentChat();if(c)c.expiry=Number(data.expiry)||0;closeModal();showToast('Demo-only timer updated.');
  }else if(name==='delete-chat-form'){
    if(data.confirm!=='DELETE')throw Error('Type DELETE exactly to confirm.');
    const c=currentChat();if(!c)throw Error('No chat selected.');
    if(!state.demo)await live.deleteLocalChat(c.username);
    c.messages=[];c.locked=true;closeModal();showToast('Local conversation state deleted.');
  }else if(name==='delete-all-form'){
    if(data.confirm!=='DELETE')throw Error('Type DELETE exactly to confirm.');
    if(!state.demo){await live.deleteDevice();try{await api.logout();}catch{}}
    leaveSession();showToast('Local Encrypto data deleted from this browser.');
  }
  }catch(error){const message=errorText(error);if(name==='auth-form'){state.authError=message;render();}else showToast(message,'error');}
  finally{state.busy=false;if(submit?.isConnected)submit.disabled=false;state.root.querySelectorAll('form [type=submit]:disabled').forEach(button=>button.disabled=false);if(currentChat()&&!chatLocked(currentChat())){const input=state.root.querySelector('#message-text');if(input)input.disabled=false;}}
}
async function handleAction(button){const action=button.dataset.action;if(!action)return;const c=currentChat();
  try{
  switch(action){
    case 'welcome':leaveSession();break;
    case 'show-login':state.mode='auth';state.authMode='login';state.authError='';render();break;
    case 'show-register':state.mode='auth';state.authMode='register';state.authError='';render();break;
    case 'demo':await demoMode();break;
    case 'nav':setRoute(button.dataset.route);break;
    case 'open-settings':setRoute('settings');break;
    case 'settings-tab':state.settingsTab=button.dataset.tab;render();break;
    case 'settings-privacy':state.settingsTab='privacy';setRoute('settings');break;
    case 'security-center':setRoute('security');break;
    case 'select-first-chat':if(state.chats.length)await selectChat(state.chats[0].id);else showToast('No conversations yet.');break;
    case 'new-chat':if(state.vaultLocked&&!state.demo){openModal('vault');showToast('Unlock your vault before creating a chat.');}else openModal('new-chat');break;
    case 'start-with-contact':if(state.vaultLocked&&!state.demo)openModal('vault');else openModal('new-chat',{username:button.dataset.username});break;
    case 'select-chat':await selectChat(button.dataset.id);break;
    case 'refresh-chats':await refreshChats();showToast('Invitations refreshed.');break;
    case 'accept-invite':{
      if(!c)return;
      if(state.demo){c.status='active';openModal('set-password');break;}
      if(state.vaultLocked){openModal('vault');break;}
      await api.acceptChat(c.id);await refreshChats();await selectChat(c.id);showToast('Invitation accepted. Set your own chat password to begin.');break;
    }
    case 'decline-invite':if(c){if(!state.demo)await api.declineChat(c.id);c.status='declined';state.selected=null;await refreshChats();showToast('Invitation declined.');}break;
    case 'back':state.showMobileChat=false;state.route='chats';state.selected=null;state.modal=null;render();break;
    case 'chat-info':openModal('chat-info');break;
    case 'identity-modal':if(c&&!state.demo&&!state.vaultLocked){const item=await live.identityFor(c.username);c.contactCode=item.contactCode;c.verified=item.verified;}openModal('identity');break;
    case 'expiry-modal':openModal('expiry');break;
    case 'chat-menu':openModal('chat-menu');break;
    case 'code-modal':openModal('code');break;
    case 'change-chat-password':if(c&&!state.vaultLocked&&!c.locked)openModal('change-password');else showToast('Unlock your chat first.','error');break;
    case 'open-unlock':if(state.vaultLocked)openModal('vault');else if(state.demo)openModal('unlock');else if(c){
      const exists=await live.hasPassword(c.username);openModal(exists?'unlock':'set-password');
    }break;
    case 'unlock-vault-modal':openModal('vault');break;
    case 'restore-vault':openModal('restore');break;
    case 'lock-chat':if(c){if(!state.demo)await live.lockChat(c.username);c.locked=true;c.messages=[];render();showToast('Conversation locked.');}break;
    case 'lock-all':await lockAll();break;
    case 'emergency-lock':await lockAll('emergency');break;
    case 'delete-modal':openModal('delete-all');break;
    case 'delete-conversation-modal':openModal('delete-chat');break;
    case 'signout':await signOut();break;
    case 'copy-contact-code':if(live.account)await navigator.clipboard.writeText(live.account.contactCode);showToast('Contact code copied.');break;
    case 'copy-peer-code':if(c?.contactCode)await navigator.clipboard.writeText(c.contactCode);showToast('Contact code copied.');break;
    case 'mark-verified':if(c&&!state.demo&&!state.vaultLocked){await live.markVerified(c.username);c.verified=true;closeModal();showToast('Contact marked verified on this device.');}break;
    case 'copy-recovery':if(state.recoveryKey){await navigator.clipboard.writeText(state.recoveryKey);showToast('Recovery key copied. Store it somewhere private.');}break;
    case 'confirm-recovery':state.recoveryKey=null;closeModal();await refreshChats();showToast('Device identity created. Recovery key will not be shown again.');break;
    case 'message-actions':openModal('message',{id:button.dataset.id});break;
    case 'message-info':openModal('message-info',state.modalData);break;
    case 'copy-message':{
      const m=c?.messages?.find(m=>m.id===state.modalData?.id);if(m)await navigator.clipboard.writeText(m.text);closeModal();showToast('Message copied to clipboard.');break;
    }
    case 'delete-message':{
      if(c){c.messages=c.messages.filter(m=>m.id!==state.modalData?.id);if(!state.demo)await live.saveHistory(c.username,c.messages);}closeModal();showToast('Local message copy deleted.');break;
    }
    case 'retry-message':{
      const id=state.modalData?.id;
      if(!c||state.demo||state.vaultLocked||c.locked)throw Error('Unlock the chat to retry sending.');
      await live.retry(c,c.messages,id);closeModal();render();showToast('Encrypted message submitted to server.');break;
    }
    case 'close-modal':if(state.modal!=='recovery-key')closeModal();break;
    case 'close-modal-backdrop':if(state.modal!=='recovery-key')closeModal();break;
    case 'dismiss-toast':state.toast=null;renderToast();break;
    case 'toggle-password':{
      const input=state.root.querySelector(`#${CSS.escape(button.dataset.target)}`);if(input){input.type=input.type==='password'?'text':'password';button.setAttribute('aria-label',input.type==='password'?'Show password':'Hide password');}break;
    }
    default:break;
  }
  }catch(err){showToast(errorText(err),'error');}
}
function changePreference(target){const key=target.dataset.pref;if(!(key in state.prefs))return;let val=target.type==='checkbox'?target.checked:target.value;if(key==='autoLock')val=Number(val);state.prefs[key]=val;savePreferences(state.prefs);theme();if(key==='privacyOnHide')state.root.classList.toggle('privacy-hidden',state.privacyVisible&&Boolean(val));else render();}
export function boot(root){state.root=root;root.dataset.frontendVersion=FRONTEND_VERSION;render();
  root.addEventListener('submit',event=>{event.preventDefault();handleSubmit(event.target);});
  root.addEventListener('click',event=>{
    const button=event.target.closest('[data-action]');if(!button)return;
    if(button.dataset.action==='close-modal-backdrop' && event.target!==button)return;
    if(button.closest('.modal-backdrop') && button.dataset.action==='close-modal-backdrop' && event.target!==button)return;
    handleAction(button);
  });
  root.addEventListener('input',event=>{
    const field=event.target;if(field.dataset.search==='chats'){
      state.search=field.value;
      const slot=root.querySelector('#sidebar-chat-list');
      if(slot){const items=state.chats.filter(c=>c.name.toLowerCase().includes(state.search.toLowerCase()));slot.innerHTML=`<div class="side-list-head"><span>YOUR CONVERSATIONS</span><span>${items.length}</span></div>${items.length?items.map(sideChat).join(''):'<div class="empty-side">No matching conversations</div>'}`;}
    }
    if(field.matches('textarea#message-text')){field.style.height='auto';field.style.height=`${Math.min(field.scrollHeight,140)}px`;}
  });
  root.addEventListener('keydown',event=>{
    if(event.key==='Escape'&&state.modal&&state.modal!=='recovery-key'){event.preventDefault();closeModal();}
    if(event.key==='Enter'&&!event.shiftKey&&event.target.id==='message-text'){event.preventDefault();event.target.form.requestSubmit();}
  });
  root.addEventListener('change',event=>{if(event.target.dataset.pref)changePreference(event.target);});
  document.addEventListener('visibilitychange',()=>{
    state.privacyVisible=Boolean(document.hidden&&state.prefs.privacyOnHide&&state.mode==='app');
    root.classList.toggle('privacy-hidden',state.privacyVisible);
    if(!document.hidden&&state.mode==='app'&&!state.vaultLocked)syncInbox();
  });
  const updateActivity=()=>{state.lastActivity=Date.now();};
  for(const kind of ['pointerdown','keydown'])document.addEventListener(kind,updateActivity,{passive:true});
  setInterval(()=>{
    if(state.mode!=='app'||state.vaultLocked)return;
    const timeout=Number(state.prefs.autoLock);
    if(timeout>0&&Date.now()-state.lastActivity>=timeout*60000){lockAll('inactivity');return;}
    if(state.demo&&demoExpire(state.chats))render();
  },5000);
  setInterval(()=>{if(state.mode==='app'&&!state.demo&&!state.vaultLocked)syncInbox();},15000);
  setInterval(()=>{if(state.mode==='app'&&!state.demo)refreshChats().catch(()=>{});},30000);
  bootSession();
}
