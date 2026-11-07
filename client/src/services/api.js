/** Exact HTTP contract from the provided Encrypto server/src/routes. */
export class ApiError extends Error {
  constructor(message, status=0) { super(message); this.name='ApiError'; this.status=status; }
}
export class ApiClient {
  async request(path,{method='GET',body,signal}={}) {
    let response;
    try {
      response = await fetch(`/api${path}`, {
        method,
        credentials:'same-origin',
        cache:'no-store',
        headers:body === undefined ? {} : {'Content-Type':'application/json'},
        body:body === undefined ? undefined : JSON.stringify(body),
        signal
      });
    } catch { throw new ApiError('Cannot connect to the Encrypto server.'); }
    const data = await response.json().catch(()=>null);
    if (!response.ok) throw new ApiError(data?.error || `Server returned ${response.status}`, response.status);
    return data;
  }
  health(){return this.request('/health');}
  me(){return this.request('/me');}
  register({username,email,password,publicKey}){return this.request('/auth/register',{method:'POST',body:{username,email,password,publicKey}});}
  login(email,password){return this.request('/auth/login',{method:'POST',body:{email,password}});}
  logout(){return this.request('/auth/logout',{method:'POST'});}
  lookup(username){return this.request(`/users/${encodeURIComponent(username)}/public-key`);}
  listChats(){return this.request('/chats');}
  createChat(recipientUsername){return this.request('/chats',{method:'POST',body:{recipientUsername}});}
  acceptChat(chatId){return this.request(`/chats/${encodeURIComponent(chatId)}/accept`,{method:'POST'});}
  declineChat(chatId){return this.request(`/chats/${encodeURIComponent(chatId)}/decline`,{method:'POST'});}
  keyStatus(){return this.request('/keys/status');}
  keyChallenge(){return this.request('/keys/challenge',{method:'POST'});}
  uploadKeys(fields){return this.request('/keys/upload',{method:'POST',body:fields});}
  getBundle(contactCode){return this.request('/keys/bundle',{method:'POST',body:{contactCode}});}
  inbox(limit=100){return this.request(`/secure-messages/inbox?limit=${limit}`);}
  send(chatId,clientMessageId,envelope){return this.request('/secure-messages',{method:'POST',body:{chatId,clientMessageId,envelope}});}
  ack(id){return this.request(`/secure-messages/${encodeURIComponent(id)}/ack`,{method:'POST'});}
}
export const api = new ApiClient();
