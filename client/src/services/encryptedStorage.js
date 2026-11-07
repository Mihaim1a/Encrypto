/** Encrypted IndexedDB. This service NEVER creates or persists its own key.
 * The reviewed crypto/vault implementation supplies a non-extractable AES-GCM CryptoKey.
 * Never pass password strings or raw private keys as the key.
 */
const DB_NAME='encrypto-encrypted-state-v1', STORE='records';
function openDB(){
  return new Promise((resolve,reject)=>{
    if(!('indexedDB' in globalThis)){reject(new Error('IndexedDB unavailable'));return;}
    const req=indexedDB.open(DB_NAME,1);
    req.onupgradeneeded=()=>{if(!req.result.objectStoreNames.contains(STORE))req.result.createObjectStore(STORE);};
    req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);
  });
}
function transact(db,mode,fn){return new Promise((resolve,reject)=>{const tx=db.transaction(STORE,mode);let result;const request=fn(tx.objectStore(STORE));request.onsuccess=()=>{result=request.result;};tx.oncomplete=()=>resolve(result);tx.onabort=()=>reject(tx.error||new Error('IndexedDB transaction aborted'));tx.onerror=()=>reject(tx.error||new Error('IndexedDB transaction failed'));});}
const encoder=new TextEncoder(),decoder=new TextDecoder();
export class EncryptedStore {
  #key=null; #db=null;
  async open(){if(!this.#db)this.#db=await openDB();return this;}
  unlock(key){if(!key || key.type!=='secret'||key.algorithm?.name!=='AES-GCM'||!key.usages?.includes('encrypt')||!key.usages?.includes('decrypt'))throw new Error('Expected a vault-managed AES-GCM CryptoKey');this.#key=key;}
  lock(){this.#key=null;}
  get unlocked(){return Boolean(this.#key);}
  #assert(){if(!this.#db)throw Error('Encrypted storage not initialized');if(!this.#key)throw Error('Encrypted storage is locked');}
  async put(name,value){this.#assert();const iv=crypto.getRandomValues(new Uint8Array(12));const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:encoder.encode(name)},this.#key,encoder.encode(JSON.stringify(value)));return transact(this.#db,'readwrite',s=>s.put({v:1,iv:Array.from(iv),ciphertext:Array.from(new Uint8Array(ciphertext))},name));}
  async get(name){this.#assert();const packet=await transact(this.#db,'readonly',s=>s.get(name));if(!packet)return null;if(packet.v!==1)throw Error('Unsupported encrypted record version');const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:Uint8Array.from(packet.iv),additionalData:encoder.encode(name)},this.#key,Uint8Array.from(packet.ciphertext));return JSON.parse(decoder.decode(plaintext));}
  async delete(name){if(!this.#db)throw Error('Encrypted storage not initialized');return transact(this.#db,'readwrite',s=>s.delete(name));}
  async clear(){if(!this.#db)throw Error('Encrypted storage not initialized');return transact(this.#db,'readwrite',s=>s.clear());}
  close(){this.lock();this.#db?.close();this.#db=null;}
}
export const encryptedStore=new EncryptedStore();
