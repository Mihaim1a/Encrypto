import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const read=path=>fs.readFileSync(new URL(path,import.meta.url),'utf8');
test('frontend includes the required pages and independent lock flows',()=>{
 const source=read('../src/app.js');
 for(const text of ['Create your account','Welcome back','YOUR CONVERSATIONS','Contacts','Privacy center','Emergency lock','Unlock device vault','Unlock conversation','New private conversation','Verify contact identity','Disappearing messages','Recovery key','Change your chat password']) assert.ok(source.includes(text),text);
});
test('sidebar has no groups or settings navigation buttons',()=>{
 const source=read('../src/app.js');
 assert.doesNotMatch(source,/data-route="groups"/);
 assert.doesNotMatch(source,/data-route="settings"/);
 assert.match(source,/btn\('open-settings'/);
});
test('no raw message HTML is rendered',()=>{
 const source=read('../src/app.js');
 assert.match(source,/bubble-text">\$\{e\(m\.text\)\}/);
 assert.match(source,/const e=v=>escapeHtml/);
});
test('backend endpoint contract matches the supplied server',()=>{
 const api=read('../src/services/api.js');
 for(const route of ['/auth/register','/auth/login','/auth/logout','/me','/chats','/keys/status','/keys/challenge','/keys/upload','/keys/bundle','/secure-messages/inbox'])assert.ok(api.includes(route),route);
 assert.match(api,/login\(email,password\)/);
 assert.match(api,/credentials:'same-origin'/);
});
test('locally wrapped vault key and encrypted account-state persistence are present',()=>{
 const vault=read('../src/services/vault.js');
 const live=read('../src/services/live.js');
 assert.match(vault,/PBKDF2/);
 assert.match(vault,/600000/);
 assert.match(live,/Account\.importState/);
 assert.match(live,/enableAutoSave/);
 assert.match(live,/await encryptedStore\.put\(key,message\)/);
 assert.match(live,/await api\.ack\(message\.id\)/);
});
test('CSP is restrictive and crypto is served same-origin',()=>{
 const server=read('../../server/src/server.js');
 assert.match(server,/defaultSrc: \["'none'"\]/);
 assert.match(server,/app\.use\("\/app", express\.static/);
 assert.match(server,/"\/client-crypto"/);
});

test('account tile does not stretch or restyle the avatar',()=>{
 const app=read('../src/app.js');
 const css=read('../src/encrypto-overrides.css');
 assert.match(app,/<span class="account-title"><strong>/);
 assert.match(css,/\.account-tile > \.account-title\s*\{/);
 assert.match(css,/\.account-tile > \.avatar\s*\{[^}]*flex:0 0 42px/);
 assert.doesNotMatch(css,/\.account-tile > span:not\(\.status-pip\)/);
});
