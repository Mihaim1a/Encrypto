/** Verify the browser-facing server really serves the new frontend, not an old process. */
const origin = process.env.ENCRYPTO_URL || 'http://localhost:3000';
const fetchText = async path => {
  const response = await fetch(origin + path, {cache:'no-store', signal:AbortSignal.timeout(5000)});
  if(!response.ok) throw Error(`${path}: HTTP ${response.status}`);
  return response.text();
};
try {
  const [html, app, css] = await Promise.all([
    fetchText('/'),
    fetchText('/app/src/app.js?v=2.1.1'),
    fetchText('/app/src/encrypto-overrides.css?v=2.1.1')
  ]);
  const checks = [
    ['Correct frontend version marker', html.includes('encrypto-build') && html.includes('v2.1.1-20261107')],
    ['New app with conversations navigation', app.includes('YOUR CONVERSATIONS') && app.includes('open-settings')],
    ['Avatar 42px override', css.includes('.account-tile > .avatar') && css.includes('flex:0 0 42px')],
    ['No old Groups sidebar tab', !app.includes('data-route="groups"')],
    ['No old Settings sidebar tab', !app.includes('data-route="settings"')],
  ];
  for(const [name,ok] of checks) console.log(`${ok?'PASS':'FAIL'} ${name}`);
  if(checks.some(([,ok])=>!ok)) {
    console.error('A different/older Encrypto server is serving this address. Stop that process and restart from this folder.');
    process.exitCode=1;
  } else console.log(`Verified: ${origin} serves Encrypto frontend v2.1.1.`);
} catch (error) {
  console.error(`Cannot verify ${origin}: ${error.message}. Start the project from this folder with npm start.`);
  process.exitCode=1;
}
