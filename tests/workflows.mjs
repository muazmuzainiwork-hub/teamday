import assert from 'node:assert/strict';
import fs from 'node:fs';
import ts from 'typescript';
import {DatabaseSync} from 'node:sqlite';
const db=new DatabaseSync(':memory:');db.exec(fs.readFileSync('drizzle/0000_modern_nitro.sql','utf8'));
let identity=null;let cookieHeader='';const files=new Map();
globalThis.__hrTest={env:{DB:{prepare(sql){let values=[];return {bind(...v){values=v;return this},async first(){return db.prepare(sql).get(...values)},async all(){return {results:db.prepare(sql).all(...values)}},async run(){const r=db.prepare(sql).run(...values);return {meta:{changes:r.changes}}}}}},BUCKET:{async head(k){return files.get(k)||null},async put(k,v,m){files.set(k,{body:v,...m})},async get(k){return files.get(k)}}},user:()=>identity};
let authSrc=fs.readFileSync('app/email-auth.ts','utf8').replace("import {env} from 'cloudflare:workers';","const env=globalThis.__hrTest.env;").replace("import {headers} from 'next/headers';","const headers=async()=>new Headers({cookie:globalThis.__hrTest.cookie||''});");
const compile=src=>'data:text/javascript;base64,'+Buffer.from(ts.transpileModule(src,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText).toString('base64');
const authURL=compile(authSrc);globalThis.__hrTest.auth=await import(authURL);
let endpoint=fs.readFileSync('app/api/auth/route.ts','utf8').replace("import {env} from 'cloudflare:workers';","const env=globalThis.__hrTest.env;").replace("import {getChatGPTUser} from '../../chatgpt-auth';","const getChatGPTUser=async()=>globalThis.__hrTest.user();").replace("from '../../email-auth'",'from '+JSON.stringify(authURL));
const authAPI=await import(compile(endpoint));
const accounts={manager:{email:'manager@example.test',password:'Manager-test-831492'},alice:{email:'alice@example.test',password:'Alice-test-729143'},bob:{email:'bob@example.test',password:'Bob-test-654291'}};
const sessions={};
async function login(user,action='login',overrides={}){identity=user;const r=await authAPI.POST(new Request('https://test.local/api/auth',{method:'POST',headers:{origin:'https://test.local',cookie:globalThis.__hrTest.cookie||''},body:JSON.stringify({action,...accounts[user?.userId],...overrides})}));if(r.ok&&user&&r.headers.get('set-cookie'))sessions[user.userId]=r.headers.get('set-cookie').split(';')[0];return r}
async function use(user){identity=user;if(user&&accounts[user.userId]&&!sessions[user.userId]){const row=db.prepare('SELECT * FROM company').get();if(row){const person=JSON.parse(row.data).people.find(p=>p.email===user.email);if(person?.passwordHash)await login(user)}}globalThis.__hrTest.cookie=user?sessions[user.userId]||'':''}
let src=fs.readFileSync('app/api/hr/route.ts','utf8').replace("import {env} from 'cloudflare:workers';","const env=globalThis.__hrTest.env;").replace("import {getChatGPTUser} from '../../chatgpt-auth';","const getChatGPTUser=async()=>globalThis.__hrTest.user();");
src=src.replace("import {getAppUser,credentials} from '../../email-auth';","const {getAppUser,credentials}=globalThis.__hrTest.auth;");
const js=ts.transpileModule(src,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const api=await import('data:text/javascript;base64,'+Buffer.from(js).toString('base64'));
const manager={userId:'manager',displayName:'Test Manager',email:'manager@example.test'},alice={userId:'alice',displayName:'Alice Test',email:'alice@example.test'},bob={userId:'bob',displayName:'Bob Test',email:'bob@example.test'};
let count=0;
async function post(user,body,ok=true){await use(user);const r=await api.POST(new Request('https://test.local/api/hr',{method:'POST',headers:{origin:'https://test.local','Content-Type':'application/json'},body:JSON.stringify(body)}));const j=await r.json();assert.equal(r.ok,ok,JSON.stringify(j));count++;return j}
async function get(user){await use(user);const r=await api.GET();return {status:r.status,...await r.json()}}
assert.equal((await get(null)).login,true);count++;
await post(manager,{action:'setup',company:'Test Company'});
// First manager must activate without needing another manager's approval.
for(const action of ['signup','login','enroll']){
 const denied=await login(null,action,{...accounts.manager,name:'Impersonator'});
 assert.equal(denied.status,403);assert.equal((await denied.json()).code,'VERIFICATION_REQUIRED');assert.equal(denied.headers.get('set-cookie'),null);
}
assert.equal(db.prepare('SELECT COUNT(*) AS n FROM registrations').get().n,0);
const spoof={userId:'different-id',email:manager.email};
assert.equal((await login(spoof,'signup',{...accounts.manager,name:'Spoof'})).status,403);
const activation=await login(manager,'login');assert.equal(activation.status,409);assert.equal((await activation.json()).code,'ACTIVATION_REQUIRED');
// A request left by the old implementation cannot supply the manager's new password.
const stale=await globalThis.__hrTest.auth.credentials(manager.email,'untrusted-old-request');
db.prepare('INSERT INTO registrations VALUES(?,?,?,?,?)').run('stale-manager',manager.email,'Stale',stale.passwordHash,stale.passwordSalt);
// Clear the rate-limit fixture after deliberately testing five failed attempts.
db.prepare('DELETE FROM email_attempts').run();
assert.equal((await login(manager,'signup',{name:manager.displayName})).status,200);
assert.equal((await get(manager)).me.role,'Manager');
assert.equal(db.prepare('SELECT COUNT(*) AS n FROM registrations WHERE email=?').get(manager.email).n,0);
assert.equal((await login(null,'login',{...accounts.manager})).status,200);
assert.equal((await login(null,'login',{...accounts.manager,password:'untrusted-old-request'})).status,401);

for(const p of [alice,bob])await post(manager,{action:'person',name:p.displayName,email:p.email,role:'Employee',...accounts[p.userId]});
let a=await get(alice);const aid=a.me.id;assert.equal(a.people.length,1);count++;
await post(alice,{action:'person',name:'Intruder',email:'intruder@example.test'},false);
await post(alice,{action:'clock',direction:'out'},false);
await post(alice,{action:'clock',direction:'in'});
await post(alice,{action:'clock',direction:'in'},false);
await post(alice,{action:'clock',direction:'out'});
await post(alice,{action:'clock',direction:'out'},false);
await post(alice,{action:'correct',employee:aid,date:'2026-10-20',reason:'x'},false);
await post(manager,{action:'correct',employee:aid,date:'2026-10-20',in:'2026-10-20T01:00:00Z',out:'2026-10-20T10:00:00Z',reason:'Verified missed clock-out'});
assert.equal((await get(manager)).audit[0].action,'Attendance correction');count++;
await post(alice,{action:'request',type:'OT',date:'2026-10-22',quantity:1.25,reason:'Release'},false);
await post(alice,{action:'request',type:'OT',date:'2026-10-22',quantity:2,reason:'Release'});
let r=(await get(alice)).requests[0];await post(alice,{action:'decision',id:r.id,status:'Approved',reason:'Self'},false);
await post(manager,{action:'decision',id:r.id,status:'Approved',reason:'Confirmed'});
await post(manager,{action:'decision',id:r.id,status:'Rejected',reason:'Again'},false);
await post(alice,{action:'request',type:'Leave',date:'2026-10-26',end:'2026-10-30',reason:'Holiday'});
r=(await get(alice)).requests[0];await post(manager,{action:'decision',id:r.id,status:'Approved',reason:'Coverage arranged'});
a=await get(alice);assert.equal(api.balance(a,aid,'2026'),9);count++;
await post(alice,{action:'request',type:'Leave',date:'2026-10-27',end:'2026-10-29',reason:'Overlap'},false);
await post(manager,{action:'balance',employee:aid,year:'2026',allowance:4,reason:'Below used'},false);
await post(manager,{action:'balance',employee:aid,year:'2026',allowance:20,reason:'Contract allowance'});
assert.equal(api.balance(await get(alice),aid,'2026'),15);count++;
files.set(aid+'/receipt',{body:'test'});
await post(alice,{action:'request',type:'Claim',date:'2026-10-22',quantity:32.5,category:'Travel',reason:'Client visit',receipt:aid+'/receipt'});
r=(await get(alice)).requests[0];await post(manager,{action:'decision',id:r.id,status:'Rejected',reason:'Wrong receipt'});
await post(bob,{action:'request',type:'Claim',date:'2026-10-22',quantity:10,category:'Travel',reason:'Forged',receipt:aid+'/receipt'},false);
const b=await get(bob);assert.equal(b.attendance.length,0);assert.equal(b.requests.length,0);assert.equal(b.audit.length,0);assert.equal(b.people.length,1);count++;
assert.equal((await get({userId:'outsider',email:'outsider@example.test'})).login,true);count++;
assert.equal((await get(alice)).requests.length,3);count++;
console.log(`${count} workflow and authorization checks passed (real SQLite; mocked platform identity/storage).`);

await post(alice,{action:'request',type:'Leave',leaveType:'Medical Leave',date:'2026-11-02',end:'2026-11-03',reason:'Medical leave'});
r=(await get(alice)).requests[0];await post(manager,{action:'decision',id:r.id,status:'Approved',reason:'Confirmed'});
a=await get(alice);assert.equal(api.balance(a,aid,'2026','Medical Leave'),10);assert.equal(api.balance(a,aid,'2026'),15);assert.equal(a.people[0].passwordHash,undefined);assert.equal(a.me.passwordSalt,undefined);
await post(alice,{action:'request',type:'Leave',leaveType:'Medical Leave',date:'2026-11-04',end:'2026-11-20',reason:'Too many'},false);
await post(alice,{action:'request',type:'Leave',leaveType:'Invalid',date:'2026-11-04',end:'2026-11-04',reason:'Invalid'},false);
await post(manager,{action:'balance',employee:aid,year:'2026',leaveType:'Medical Leave',allowance:1,reason:'Below used'},false);
assert.equal((await login(alice,'enroll')).status,403);
for(let i=0;i<5;i++)assert.equal((await login(bob,'login',{password:'wrong-password'})).status,401);
assert.equal((await login(bob)).status,429);
await use(alice);const saved=sessions.alice;assert.equal((await login(alice,'logout')).status,200);globalThis.__hrTest.cookie=saved;assert.equal(await globalThis.__hrTest.auth.getAppUser(),null);
console.log('Medical Leave independence, Email/password enrollment/login/logout, credential redaction and lockout checks passed.');

const newcomer={userId:'new',displayName:'New Employee',email:'new@example.test'};
accounts.new={email:newcomer.email,password:'new-employee-password'};
assert.equal((await login(newcomer,'signup',{name:'New Employee',role:'Manager'})).status,403);
assert.equal((await login(newcomer,'signup',{name:'New Employee',role:'Admin'})).status,403);
assert.equal((await login(newcomer,'signup',{name:'New Employee'})).status,200);
const wait=await login(newcomer);assert.equal(wait.status,403);assert.equal((await wait.json()).code,'APPROVAL_PENDING');assert.equal(wait.headers.get('set-cookie'),null);
assert.equal((await login(newcomer,'login',{password:'wrong-pending-password'})).status,401);
db.prepare('DELETE FROM email_attempts WHERE email=?').run(newcomer.email);

await use(manager);let pending=await get(manager);let registration=pending.registrations.find(r=>r.email===newcomer.email);
assert.ok(registration);assert.equal(registration.passwordHash,undefined);
await post(alice,{action:'approveRegistration',id:registration.id},false);
await post(manager,{action:'approveRegistration',id:registration.id});
assert.equal((await login(newcomer)).status,200);
const newcomerData=await get(newcomer);assert.equal(newcomerData.me.role,'Employee');assert.equal(newcomerData.people.length,1);assert.equal(newcomerData.registrations,undefined);
assert.equal((await login(newcomer,'signup',{name:'Replacement',password:'replacement-password'})).status,409);
assert.equal((await login(newcomer,'login',{password:'replacement-password'})).status,401);
assert.equal((await login(newcomer)).status,200);
assert.equal((await login(null,'login',{email:'bad-email',password:'abcdefgh'})).status,400);
assert.equal((await login(null,'signup',{email:'short@example.test',name:'Short',password:'123'})).status,400);
console.log('Sign-up approval, duplicate-account protection, employee role enforcement and input validation passed.');

// Already provisioned users of both roles activate via identity verification, preserving IDs and records.
for (const role of ['Manager','Employee']) {
 const id='legacy-'+role.toLowerCase(),email=id+'@example.test';
 const user={userId:id,email,displayName:'Legacy '+role};accounts[id]={email,password:'verified-'+id+'-password'};
 const row=db.prepare('SELECT * FROM company').get(),state=JSON.parse(row.data);
 state.people.push({id,uid:id,name:user.displayName,email,role,joined:'2026-01-01',pinHash:'obsolete',pinSalt:'obsolete'});
 state.attendance.push({id:'attendance-'+id,employee:id,date:'2026-01-01',in:'2026-01-01T01:00:00Z',out:'2026-01-01T10:00:00Z'});
 db.prepare('UPDATE company SET data=?,revision=revision+1 WHERE id=1').run(JSON.stringify(state));
 const old=await globalThis.__hrTest.auth.credentials(email,'old-pending-password');
 db.prepare('INSERT INTO registrations VALUES(?,?,?,?,?)').run('old-'+id,email,user.displayName,old.passwordHash,old.passwordSalt);
 const before=await get(manager);assert.ok(!before.registrations.some(r=>r.email===email));
 await post(manager,{action:'approveRegistration',id:'old-'+id},false);
 const firstLogin=await login(null,'login',accounts[id]);assert.equal(firstLogin.status,403);assert.equal((await firstLogin.json()).code,'VERIFICATION_REQUIRED');
 const view=await get(user);assert.equal(view.enroll,true);assert.equal(view.activation.role,role);
 assert.equal((await login(user,'enroll')).status,200);
 const active=await get(user);assert.equal(active.me.id,id);assert.equal(active.me.role,role);assert.ok(active.attendance.some(a=>a.id==='attendance-'+id));
 assert.equal(active.me.passwordHash,undefined);assert.equal(active.me.pinHash,undefined);
 assert.equal(db.prepare('SELECT COUNT(*) AS n FROM registrations WHERE email=?').get(email).n,0);
 assert.equal((await login(null,'login',accounts[id])).status,200);
 assert.equal((await login(null,'login',{...accounts[id],password:'wrong-password'})).status,401);
}
const outsider={userId:'no-membership',email:'no-membership@example.test'};
assert.equal((await login(outsider,'enroll',{email:outsider.email,password:'outsider-password'})).status,403);
console.log('First-manager sign-up/login, existing-role activation, stale pending-request recovery, role spoofing and identity mismatch checks passed.');
