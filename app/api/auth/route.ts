import {env} from 'cloudflare:workers';
import {getChatGPTUser} from '../../chatgpt-auth';
import {credentials,emailAddress,passwordHash,tables,tokenHash,cookie} from '../../email-auth';
export const dynamic='force-dynamic';
const result=(body:any,status=200)=>Response.json(body,{status,headers:{'Cache-Control':'no-store'}});
export async function POST(req:Request){try{
 if(req.headers.get('origin')!==new URL(req.url).origin)return result({error:'Invalid origin'},403);
 const db=(env as any).DB;await tables();const b=await req.json() as any;
 if(b.action==='logout'){
  const token=req.headers.get('cookie')?.match(/(?:^|;\s*)teamday_session=([^;]+)/)?.[1];
  if(token)await db.prepare('DELETE FROM email_sessions WHERE token=?').bind(await tokenHash(token)).run();
  return Response.json({ok:true},{headers:{'Set-Cookie':cookie('',0),'Cache-Control':'no-store'}});
 }
 if(!['login','signup','enroll'].includes(b.action))throw Error('Invalid action');
 const email=emailAddress(b.email),now=Date.now();
 await db.prepare('INSERT INTO email_attempts(email,attempts,expires) VALUES(?,1,?) ON CONFLICT(email) DO UPDATE SET attempts=CASE WHEN expires<=? THEN 1 ELSE attempts+1 END, expires=CASE WHEN expires<=? THEN excluded.expires ELSE expires END').bind(email,now+900000,now,now).run();
 const limit=await db.prepare('SELECT attempts FROM email_attempts WHERE email=?').bind(email).first();
 if(limit.attempts>5)return result({error:'Too many attempts. Try again in 15 minutes.'},429);
 const row=await db.prepare('SELECT * FROM company WHERE id=1').first();
 if(!row)return result({code:'SETUP_REQUIRED',error:'The workspace must be set up before accounts can sign in.'},409);
 const s=JSON.parse(row.data),p=s.people.find((v:any)=>v.email.toLowerCase()===email);
 const u=await getChatGPTUser();
 // Membership/role comes only from the existing company record. Email input alone is not proof of identity.
 const verified=!!(u&&p&&(p.uid?p.uid===u.userId:p.email.toLowerCase()===u.email.toLowerCase()));
 if(p&&!p.passwordHash){
  if(!verified)return result({code:'VERIFICATION_REQUIRED',error:'This account is already authorized. Verify your existing account to set its first password; manager approval is not required.'},403);
  if(b.action==='login')return result({code:'ACTIVATION_REQUIRED',error:'Your account is already authorized. Set and confirm your first password to continue; no manager approval is needed.'},409);
  Object.assign(p,await credentials(email,b.password),{uid:u!.userId});delete p.pinHash;delete p.pinSalt;
  s.audit.unshift({id:crypto.randomUUID(),at:new Date().toISOString(),actor:p.name,employee:p.id,action:'Password activated',reason:'Existing authorized account verified; role unchanged'});
  const updated=await db.prepare('UPDATE company SET data=?,revision=revision+1 WHERE id=1 AND revision=?').bind(JSON.stringify(s),row.revision).run();
  if(!updated.meta.changes)return result({error:'Workspace changed. Please retry.'},409);
  // Discard stale requests from the previous blanket-approval flow; never adopt an unverified request's password.
  await db.prepare('DELETE FROM registrations WHERE email=?').bind(email).run();
 }else if(b.action==='enroll'){
  return result({code:'ACTIVATION_UNAVAILABLE',error:'Password activation requires an existing authorized account without a password. If you have a password, log in.'},403);
 }else if(b.action==='signup'){
  if(p)return result({code:'ACCOUNT_EXISTS',error:'This account already has a password. Log in with your existing credentials.'},409);
  if(b.role&&b.role!=='Employee')return result({code:'MANAGER_PROVISIONING_REQUIRED',error:'Public sign-up is for employees. A current manager must provision additional manager accounts.'},403);
  const c=await credentials(email,b.password);
  if(typeof b.name!=='string'||!b.name.trim()||b.name.length>100)throw Error('Enter your full name');
  await db.prepare('INSERT OR IGNORE INTO registrations(id,email,name,passwordHash,passwordSalt) VALUES(?,?,?,?,?)').bind(crypto.randomUUID(),email,b.name.trim(),c.passwordHash,c.passwordSalt).run();
  return result({ok:true,pending:true,message:'Employee registration submitted. A manager must approve your access before you can sign in.'});
 }else{
  // A pending message is shown only after the submitted password proves ownership of that registration.
  const pending=!p?await db.prepare('SELECT * FROM registrations WHERE email=?').bind(email).first():null;
  const hash=await passwordHash(b.password,p?.passwordSalt||pending?.passwordSalt||'unregistered-email');
  if(!p?.passwordHash||hash!==p.passwordHash){
   if(pending&&hash===pending.passwordHash)return result({code:'APPROVAL_PENDING',error:'Your employee registration is awaiting manager approval. You can sign in after approval.'},403);
   return result({code:'INVALID_CREDENTIALS',error:'Incorrect email or password.'},401);
  }
 }
 await db.prepare('DELETE FROM email_attempts WHERE email=?').bind(email).run();
 const token=crypto.randomUUID()+crypto.randomUUID();
 await db.prepare('DELETE FROM email_sessions WHERE expires<=?').bind(Date.now()).run();
 await db.prepare('INSERT INTO email_sessions(token,employee,expires) VALUES(?,?,?)').bind(await tokenHash(token),p.id,Date.now()+28800000).run();
 return Response.json({ok:true},{headers:{'Set-Cookie':cookie(token),'Cache-Control':'no-store'}});
 }catch(e:any){return result({error:e.message},400)}}
