/** Browser integration with the supplied crypto/src/account.js and backend.
 * All protocol state transitions are saved by Account.enableAutoSave before
 * ciphertext is posted or an incoming message is acknowledged.
 */
import {Account, ChatLockedError, UntrustedIdentityError, NoSessionError} from '/client-crypto/index.js';
import {api} from './api.js';
import {vault,aesKeyFromStorageKey} from './vault.js';
import {encryptedStore} from './encryptedStorage.js';
const USERS_KEY=(id)=>`encrypto:user:${id}`;
export class LiveClient {
  account=null;user=null;storageKey=null;ws=null;listener=null;pending=false;releaseDeviceLock=null;deviceLockPromise=null;
  get unlocked(){return Boolean(this.account&&this.storageKey&&encryptedStore.unlocked);}
  async createIdentity(){return Account.create();}
  async registerDevice(user,account,passphrase){
    const storageKey=Account.generateStorageKey();
    const blob=await account.exportState(storageKey);
    await vault.create(user.id,passphrase,storageKey,blob);
    await this.attach(user,account,storageKey);
  }
  async acquireDeviceLock(userId){
    if(!navigator.locks?.request)throw Error('This browser does not support the lock manager required for safe single-tab ratchet state. Use a modern secure-context browser.');
    let accepted, declined;
    const acquired=new Promise((resolve,reject)=>{accepted=resolve;declined=reject;});
    this.deviceLockPromise=navigator.locks.request(`encrypto-account:${userId}`,{mode:'exclusive',ifAvailable:true},async lock=>{
      if(!lock){declined(Error('This Encrypto account is already unlocked in another tab. Lock it there first.'));return;}
      accepted();await new Promise(resolve=>{this.releaseDeviceLock=resolve;});
    });
    await acquired;
  }
  async attach(user,account,storageKey){
    this.disconnect();this.user=user;
    await this.acquireDeviceLock(user.id);
    await encryptedStore.open();
    encryptedStore.unlock(await aesKeyFromStorageKey(storageKey));
    await account.enableAutoSave({storageKey,save:blob=>vault.save(user.id,blob)});
    this.account=account;this.storageKey=storageKey;
    this.connect();
  }
  async unlock(user,passphrase){
    const {storageKey,blob}=await vault.unlock(user.id,passphrase);
    const account=await Account.importState(blob,storageKey);
    await this.attach(user,account,storageKey);
    return account.contactCode;
  }
  async restore(user,recoveryKey,passphrase){
    const account=await Account.restore(recoveryKey);
    const peer=await api.lookup(user.username);
    if(peer.contactCode && peer.contactCode!==account.contactCode)throw Error('Recovery key does not match this registered identity.');
    await this.registerDevice(user,account,passphrase);
    await this.enroll(true);
  }
  async enroll(resetPreKeys=false,initialBundle=null){
    this.require();
    const status=await api.keyStatus();
    if(status.enrolled && status.contactCode!==this.account.contactCode)throw Error('Server identity mismatch. Stop and verify your account keys.');
    if(status.enrolled && status.oneTimePreKeys>=5 && !this.account.getPreKeyStatus().signedPreKeyRotationDue && !resetPreKeys)return status;
    const {challenge}=await api.keyChallenge();
    const proof=await this.account.signRecoveryChallenge(challenge);
    const bundle=initialBundle||await this.account.createPreKeyUpload({oneTimePreKeyCount:20});
    return api.uploadKeys({bundle,contactCode:this.account.contactCode,challenge,proof,resetPreKeys});
  }
  require(){if(!this.unlocked)throw Error('Unlock your local vault first.');}
  async identityFor(username){
    this.require();
    const item=await api.lookup(username);
    if(!item.cryptoEnrolled||!item.contactCode)throw Error('This contact has not enrolled encryption keys yet.');
    const key=`pin:${this.user.id}:${username.toLowerCase()}`;
    const cached=await encryptedStore.get(key);
    if(cached && cached.contactCode!==item.contactCode)throw new UntrustedIdentityError('Contact identity changed. Messages are blocked pending manual investigation.');
    if(!cached)await encryptedStore.put(key,{contactCode:item.contactCode,verified:false});
    return {...item, verified:Boolean(cached?.verified)};
  }
  async markVerified(username){
    const identity=await this.identityFor(username);
    await encryptedStore.put(`pin:${this.user.id}:${username.toLowerCase()}`,{contactCode:identity.contactCode,verified:true});
  }
  async setPassword(username,password){
    const identity=await this.identityFor(username);
    if(!await this.account.hasChatPassword(identity.contactCode))await this.account.setChatPassword(identity.contactCode,password);
  }
  async hasPassword(username){const identity=await this.identityFor(username);return this.account.hasChatPassword(identity.contactCode);}
  async unlockChat(username,password){const identity=await this.identityFor(username);await this.account.unlockChat(identity.contactCode,password);return this.loadHistory(username);}
  async lockChat(username){const identity=await this.identityFor(username);await this.account.lockChat(identity.contactCode);}
  async isLocked(username){const identity=await this.identityFor(username);return this.account.isChatLocked(identity.contactCode);}
  historyKey(username){return `history:${this.user.id}:${username.toLowerCase()}`;}
  async loadHistory(username){
    const {contactCode}=await this.identityFor(username);
    const record=await encryptedStore.get(this.historyKey(username));
    if(!record)return [];
    const plaintext=await this.account.openChatData(contactCode,record.sealed);
    const array=JSON.parse(plaintext);
    return Array.isArray(array)?array:[];
  }
  async saveHistory(username,messages){
    const {contactCode}=await this.identityFor(username);
    const sealed=await this.account.sealChatData(contactCode,JSON.stringify(messages));
    await encryptedStore.put(this.historyKey(username),{sealed});
  }
  async sendMessage(chat,text,messages){
    this.require();
    if(chat.status!=='active')throw Error('This invitation must be accepted before messages can be sent.');
    const {contactCode}=await this.identityFor(chat.username);
    if(!await this.account.hasChatPassword(contactCode))throw Error('Set a personal chat password before sending.');
    if(await this.account.isChatLocked(contactCode))throw Error('Unlock this chat before sending.');
    if(!await this.account.hasSession(contactCode)){
      const bundle=await api.getBundle(contactCode);
      await this.account.startSession(contactCode,bundle);
    }
    const clientMessageId=crypto.randomUUID();
    const envelope=await this.account.encrypt(contactCode,text);
    // Persist the exact ciphertext for retry. Re-encryption would advance the ratchet again.
    const outboxKey=`outbox:${this.user.id}:${clientMessageId}`;
    await encryptedStore.put(outboxKey,{chatId:chat.id,envelope,clientMessageId});
    const message={id:clientMessageId,from:'me',text,at:new Date().toISOString(),status:'sending'};
    await this.saveHistory(chat.username,[...messages,message]);
    try{
      await api.send(chat.id,clientMessageId,envelope);
      message.status='sent';
      await this.saveHistory(chat.username,[...messages,message]);
      await encryptedStore.delete(outboxKey);
    }catch(error){message.status='failed';await this.saveHistory(chat.username,[...messages,message]);throw Object.assign(error,{outboxId:clientMessageId});}
    return message;
  }
  async retry(chat,messages,id){
    const record=await encryptedStore.get(`outbox:${this.user.id}:${id}`);
    if(!record||record.chatId!==chat.id)throw Error('No locally saved ciphertext for this message.');
    await api.send(record.chatId,record.clientMessageId,record.envelope);
    const index=messages.findIndex(m=>m.id===id);
    if(index!==-1){messages[index].status='sent';await this.saveHistory(chat.username,messages);}
    await encryptedStore.delete(`outbox:${this.user.id}:${id}`);
  }
  /** Store encrypted payloads locally BEFORE acknowledging remote retention deletion. */
  async captureInbox(){
    if(!this.unlocked||this.pending)return 0;
    this.pending=true;
    try{
      const {messages=[]}=await api.inbox(100);
      let count=0;
      for(const message of messages){
        const key=`pending:${this.user.id}:${message.id}`;
        await encryptedStore.put(key,message);
        const indexKey=`pending-index:${this.user.id}`;
        const index=(await encryptedStore.get(indexKey))||[];
        if(!index.includes(message.id))await encryptedStore.put(indexKey,[...index,message.id]);
        await api.ack(message.id);count++;
      }
      return count;
    }finally{this.pending=false;}
  }
  async processPending(chats,onDecrypted){
    this.require();
    let processed=0;
    const indexKey=`pending-index:${this.user.id}`;
    let ids=(await encryptedStore.get(indexKey))||[];
    for(const id of [...ids]){
      const row=await encryptedStore.get(`pending:${this.user.id}:${id}`);
      if(!row){ids=ids.filter(x=>x!==id);await encryptedStore.put(indexKey,ids);continue;}
      const chat=chats.find(c=>c.id===row.chatId);
      if(!chat||chat.locked||chat.status!=='active')continue;
      try{
        const {contactCode}=await this.identityFor(chat.username);
        const hist=await this.loadHistory(chat.username);
        if(!hist.some(m=>m.id===id)){
          const text=await this.account.decrypt(contactCode,row.envelope);
          const msg={id,from:'them',text,at:row.createdAt,status:'received'};
          await this.saveHistory(chat.username,[...hist,msg]);
          if(onDecrypted)onDecrypted(chat,msg);
          processed++;
        }
        await encryptedStore.delete(`pending:${this.user.id}:${id}`);
        ids=ids.filter(x=>x!==id);
        await encryptedStore.put(indexKey,ids);
      }catch(error){
        if(error instanceof ChatLockedError||error instanceof NoSessionError)continue;
        // Preserve ciphertext; don't discard it after decryption or persistence failures.
        throw error;
      }
    }
    return processed;
  }
  async deleteLocalChat(username){
    const {contactCode}=await this.identityFor(username);
    await this.account.deleteChat(contactCode);
    await encryptedStore.delete(this.historyKey(username));
  }
  connect(){
    if(!this.user||typeof WebSocket==='undefined')return;
    this.disconnect();
    const uri=`${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws`;
    try{this.ws=new WebSocket(uri);}catch{return;}
    this.ws.onmessage=event=>{
      try{const payload=JSON.parse(event.data);if(['connected','message_available'].includes(payload.type))this.listener?.(payload);}catch{}
    };
    this.ws.onclose=()=>{this.ws=null;};
  }
  disconnect(){if(this.ws){this.ws.onclose=null;this.ws.close();this.ws=null;}}
  async lock(){
    this.disconnect();
    try{await this.account?.lockAllChats();}catch{}
    this.account?.disableAutoSave();this.account=null;this.storageKey=null;encryptedStore.lock();
    if(this.releaseDeviceLock){this.releaseDeviceLock();this.releaseDeviceLock=null;}
    if(this.deviceLockPromise){await this.deviceLockPromise.catch(()=>{});this.deviceLockPromise=null;}
  }
  async deleteDevice(){
    this.disconnect();await this.lock();
    await vault.delete(this.user.id);
    // All users of this browser origin share the encrypted records database.
    await encryptedStore.clear();
  }
}
export const live=new LiveClient();
