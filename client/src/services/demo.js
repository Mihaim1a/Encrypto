/** All demo data lives only in JS memory. No real password, crypto or E2EE. */
const stamp=(hoursAgo)=>new Date(Date.now()-hoursAgo*3600000).toISOString();
const seedChats=[
 {id:'d1',name:'Alex Morgan',username:'alex',online:true,color:'violet',unread:2,verified:false,locked:true,code:'',expiry:0,lastActivity:stamp(.4),messages:[{id:'m1',from:'them',text:'Hey! The interface looks great so far.',at:stamp(5),status:'demo'},{id:'m2',from:'me',text:'Thanks! We are finishing the security flows next.',at:stamp(4.9),status:'demo'},{id:'m3',from:'them',text:'Perfect, let me know when you are ready to test.',at:stamp(.4),status:'demo'}]},
 {id:'d2',name:'Taylor Reed',username:'taylor',online:true,color:'mint',unread:0,verified:false,locked:true,code:'',expiry:0,lastActivity:stamp(2.6),messages:[{id:'m4',from:'them',text:'Can we review the design after the meeting?',at:stamp(2.6),status:'demo'}]},
 {id:'d3',name:'Jordan Lee',username:'jordan',online:false,color:'pink',unread:0,verified:false,locked:true,code:'',expiry:0,lastActivity:stamp(28),messages:[{id:'m5',from:'me',text:'I pushed the UI changes to my branch.',at:stamp(28),status:'demo'}]},
 {id:'d4',name:'Sam Wilson',username:'sam',online:false,color:'blue',unread:0,verified:false,locked:true,code:'',expiry:0,lastActivity:stamp(96),messages:[]}
];
const directory=[{username:'alex',name:'Alex Morgan',online:true,color:'violet'},{username:'taylor',name:'Taylor Reed',online:true,color:'mint'},{username:'jordan',name:'Jordan Lee',online:false,color:'pink'},{username:'sam',name:'Sam Wilson',online:false,color:'blue'},{username:'casey',name:'Casey Brooks',online:true,color:'amber'},{username:'morgan',name:'Morgan Kim',online:false,color:'mint'}];
export function makeDemo(){return {user:{username:'you',name:'You'},chats:structuredClone(seedChats),directory:structuredClone(directory),pendingCode:null};}
export function demoExpire(chats){ let changed=false;const now=Date.now();for(const chat of chats){if(!chat.expiry)continue;const n=chat.messages.length;chat.messages=chat.messages.filter(m=>!m.expiresAt||new Date(m.expiresAt).getTime()>now);if(chat.messages.length!==n)changed=true;}return changed;}
