import {readFileSync,existsSync} from 'node:fs';
const read=p=>readFileSync(new URL(`../${p}`,import.meta.url),'utf8');
const html=read('client/index.html');
const app=read('client/src/app.js');
const overrides=read('client/src/encrypto-overrides.css');
const server=read('server/src/server.js');
const tests={
  'Current root HTML has release marker':html.includes('v2.1.1-20261107'),
  'Root HTML imports current app':html.includes('/app/src/main.js?v=2.1.1'),
  'Avatar fix is loaded after base styles':html.indexOf('/app/src/styles.css')<html.indexOf('/app/src/encrypto-overrides.css'),
  'Avatar fix sizes avatar correctly':overrides.includes('flex:0 0 42px'),
  'No obsolete standalone legacy HTML':!existsSync(new URL('../frontend-legacy.html',import.meta.url)),
  'Sidebar contains no Groups or Settings tabs':!app.includes('data-route="groups"')&&!app.includes('data-route="settings"'),
  'New server serves client/index.html':server.includes('res.sendFile(path.join(clientDir, "index.html"))'),
  'Old port confusion is diagnosed':server.includes('EADDRINUSE')
};
for(const [name,ok] of Object.entries(tests))console.log(`${ok?'PASS':'FAIL'} ${name}`);
if(Object.values(tests).some(ok=>!ok))process.exitCode=1;
