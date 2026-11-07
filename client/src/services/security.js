export function escapeHtml(value='') {
  return String(value).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
export function usernameValid(value) { return /^[a-z0-9_]{3,20}$/.test(String(value)); }
export function pinValid(value) { return /^\d{4}$/.test(String(value)); }
export function validatePassword(value) { return typeof value === 'string' && value.length >= 10 && value.length <= 128; }
export function safeTime(date) {
  const d = new Date(date); return Number.isNaN(+d) ? '' : d.toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'});
}
export function formatDate(date) { const d=new Date(date); return Number.isNaN(+d)?'':d.toLocaleDateString('en-US',{month:'short',day:'numeric'}); }
export function initials(name) { return String(name||'?').slice(0,2).toUpperCase(); }
export function assertTextMessage(text) { if (typeof text!=='string'||!text.trim()) throw Error('Write a message first.'); if(text.length>8000)throw Error('Message is too long (8,000 characters maximum).');return text.trim(); }
export const PUBLIC_PREF_KEY='encrypto.ui.preferences.v1';
export function loadPreferences() {
  const defaults={theme:'dark', density:'comfortable',autoLock:5,privacyOnHide:true,notifications:false,hidePreview:false};
  try { const raw=localStorage.getItem(PUBLIC_PREF_KEY); if(!raw)return defaults;const obj=JSON.parse(raw);return {...defaults,...Object.fromEntries(Object.entries(obj).filter(([k])=>k in defaults))}; } catch{return defaults;}
}
export function savePreferences(p){try{localStorage.setItem(PUBLIC_PREF_KEY,JSON.stringify(p));}catch{ /* Non-sensitive preferences may be unavailable. */ }}
