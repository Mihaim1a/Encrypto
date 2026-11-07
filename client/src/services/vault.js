/** Browser vault: wraps the crypto module's random storage key with a locally derived
 * key from a separate vault passphrase. No account password, vault passphrase or raw
 * storage key is persisted. This app-layer wrapper requires security review before deployment.
 */
const DB='encrypto-device-vault-v1';
const STORE='devices';
const enc=new TextEncoder();
function asB64(bytes){let s='';for(const byte of bytes)s+=String.fromCharCode(byte);return btoa(s);}
function unB64(value){return Uint8Array.from(atob(value),c=>c.charCodeAt(0));}
function getDB(){return new Promise((resolve,reject)=>{
  const req=indexedDB.open(DB,1);
  req.onupgradeneeded=()=>req.result.createObjectStore(STORE);
  req.onsuccess=()=>resolve(req.result);
  req.onerror=()=>reject(req.error||new Error('Vault database unavailable'));
});}
async function change(mode,key,value){const db=await getDB();return new Promise((resolve,reject)=>{
  const tx=db.transaction(STORE,mode);const obj=tx.objectStore(STORE);
  const req=value===undefined?(mode==='readwrite'?obj.delete(key):obj.get(key)):obj.put(value,key);
  let result;
  req.onsuccess=()=>{result=req.result;};
  tx.oncomplete=()=>{db.close();resolve(result);};
  tx.onerror=()=>{db.close();reject(tx.error||new Error('Vault storage error'));};
  tx.onabort=()=>{db.close();reject(tx.error||new Error('Vault storage aborted'));};
});}
async function derive(passphrase,salt){
  const material=await crypto.subtle.importKey('raw',enc.encode(passphrase),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:600000},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
const context=(userId)=>enc.encode(`encrypto-vault:v1:${userId}`);
export const vault={
  async exists(userId){return Boolean(await change('readonly',userId));},
  async create(userId,passphrase,storageKey,blob){
    if(typeof passphrase!=='string'||passphrase.length<12)throw Error('Vault passphrase must contain at least 12 characters.');
    if(await this.exists(userId))throw Error('This device already has an Encrypto vault for this account.');
    const salt=crypto.getRandomValues(new Uint8Array(16));
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const key=await derive(passphrase,salt);
    const wrapped=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:context(userId)},key,enc.encode(storageKey));
    await change('readwrite',userId,{v:1,salt:asB64(salt),iv:asB64(iv),wrapped:asB64(new Uint8Array(wrapped)),blob});
  },
  async unlock(userId,passphrase){
    const entry=await change('readonly',userId);
    if(!entry||entry.v!==1)throw Error('No local vault found. Restore your identity with your recovery key.');
    let key;
    try{
      const derived=await derive(passphrase,unB64(entry.salt));
      const bytes=await crypto.subtle.decrypt({name:'AES-GCM',iv:unB64(entry.iv),additionalData:context(userId)},derived,unB64(entry.wrapped));
      key=new TextDecoder().decode(bytes);
    }catch {throw Error('Incorrect vault passphrase or corrupted local vault.');}
    return {storageKey:key,blob:entry.blob};
  },
  async save(userId,blob){
    const entry=await change('readonly',userId);
    if(!entry)throw Error('Device vault not found');
    await change('readwrite',userId,{...entry,blob});
  },
  async delete(userId){await change('readwrite',userId);},
  async deleteDatabase(){
    const db=await getDB();db.close();
    return new Promise((resolve,reject)=>{const r=indexedDB.deleteDatabase(DB);r.onsuccess=resolve;r.onerror=()=>reject(r.error);r.onblocked=()=>reject(Error('Close other Encrypto tabs and try again.'));});
  }
};
export async function aesKeyFromStorageKey(storageKey){
  const raw=unB64(storageKey);
  if(raw.length!==32)throw Error('Invalid storage key');
  return crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);
}
