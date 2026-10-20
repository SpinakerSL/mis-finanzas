/* Mis Finanzas 1.7.0 — datos cifrados en el dispositivo (AES-256-GCM, clave derivada con PBKDF2) */
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const CLP=new Intl.NumberFormat('es-CL',{style:'currency',currency:'CLP',maximumFractionDigits:0});
const localISO=(d=new Date())=>`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
const today=localISO(),cm=today.slice(0,7),LOCK_MS=300000;
const ESC={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>ESC[c]);
const csvCell=v=>{let s=String(v??'');if(/^[=+\-@\t\r]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"'};

const sample={cats:[{id:'g1',name:'Supermercado',type:'expense'},{id:'g2',name:'Combustible',type:'expense'},{id:'g3',name:'Tecnología',type:'expense'},{id:'g4',name:'Otros',type:'expense'},{id:'i1',name:'Sueldo',type:'income'}],moves:[{id:'m1',type:'income',amount:2850000,date:cm+'-01',desc:'Sueldo mensual',cat:'i1',account:'Cuenta corriente'}],budgets:[],cards:[{id:'c1',name:'Tarjeta principal',bank:'Banco',limit:3000000,cycleStart:21,cycleEnd:20,dueDay:5}],purchases:[],statementPayments:[]};

const uid=()=>crypto.randomUUID();
const isDate=s=>/^\d{4}-\d{2}-\d{2}$/.test(s),isMonth=s=>/^\d{4}-\d{2}$/.test(s);
const str=(v,d='')=>v==null?d:String(v),num=(v,d=0)=>Number.isFinite(Number(v))?Number(v):d;

/* Valida y normaliza datos (al descifrar, al migrar y al restaurar un respaldo) */
function normalize(raw){
  const r=raw&&typeof raw==='object'&&!Array.isArray(raw)?raw:{};
  const arr=k=>Array.isArray(r[k])?r[k].filter(x=>x&&typeof x==='object'):[];
  const cats=arr('cats').map(c=>({id:str(c.id)||uid(),name:str(c.name,'Sin nombre'),type:c.type==='income'?'income':'expense'}));
  const cards=arr('cards').map(c=>({id:str(c.id)||uid(),name:str(c.name),bank:str(c.bank),limit:num(c.limit),cycleStart:num(c.cycleStart,21),cycleEnd:num(c.cycleEnd,20),dueDay:num(c.dueDay,5)}));
  const cardIds=new Set(cards.map(c=>c.id));
  const moves=arr('moves').filter(m=>isDate(str(m.date))).map(m=>{
    const v={id:str(m.id)||uid(),type:['income','expense','card_payment'].includes(m.type)?m.type:'expense',amount:num(m.amount),date:str(m.date),desc:str(m.desc),cat:str(m.cat),account:str(m.account)};
    if(m.statementPaymentId)v.statementPaymentId=str(m.statementPaymentId);
    return v});
  const purchases=arr('purchases').filter(p=>cardIds.has(str(p.cardId))&&isDate(str(p.date))).map(p=>({id:str(p.id)||uid(),cardId:str(p.cardId),date:str(p.date),desc:str(p.desc),cat:str(p.cat),installments:Math.max(1,Math.floor(num(p.installments,1))),installmentValue:num(p.installmentValue),cashPrice:p.cashPrice?num(p.cashPrice):null}));
  const budgets=arr('budgets').filter(b=>isMonth(str(b.month))).map(b=>({id:str(b.id)||uid(),month:str(b.month),cat:str(b.cat),amount:num(b.amount)}));
  const statementPayments=arr('statementPayments').filter(p=>isMonth(str(p.month))).map(p=>({id:str(p.id)||uid(),cardId:str(p.cardId),month:str(p.month),amount:num(p.amount),date:str(p.date),account:str(p.account)}));
  return{cats:cats.length?cats:structuredClone(sample.cats),moves,budgets,cards,purchases,statementPayments};
}

/* Los datos NO se cargan hasta desbloquear: mientras tanto db está vacía */
let db=normalize({});
let mode='',eid=null,timer,payCtx=null;
const cat=id=>db.cats.find(x=>x.id===id)?.name||'Sin categoría',card=id=>db.cards.find(x=>x.id===id),money=v=>CLP.format(Number(v)||0),month=()=>$('#month').value||cm;
const PALETTE=['#2563eb','#f59e0b','#10b981','#ef4444','#8b5cf6','#06b6d4','#ec4899','#84cc16','#f97316','#64748b','#14b8a6','#a855f7'];
const catColor=id=>{const i=db.cats.findIndex(c=>c.id===id);return i<0?'#94a3b8':PALETTE[i%PALETTE.length]};

/* ================= CIFRADO ================= */
const ITER=600000;                         // iteraciones PBKDF2-SHA256 (recomendación OWASP 2023)
const enc=new TextEncoder(),dec=new TextDecoder();
const AAD=t=>enc.encode('mis-finanzas:'+t+':v2');
const b64e=u=>{let s='';for(let i=0;i<u.length;i+=0x8000)s+=String.fromCharCode.apply(null,u.subarray(i,i+0x8000));return btoa(s)};
const b64d=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function deriveKey(pass,salt,iter){
  const base=await crypto.subtle.importKey('raw',enc.encode(String(pass).normalize('NFKC')),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:iter},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}   // clave NO exportable
async function seal(k,salt,iter,text,type){   // IV aleatorio nuevo en cada cifrado
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:AAD(type)},k,enc.encode(text)));
  return{app:'mis-finanzas',type,v:2,kdf:'PBKDF2-SHA256',iter,salt:b64e(salt),iv:b64e(iv),ct:b64e(ct)}}
async function unseal(k,h,type){const buf=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64d(h.iv),additionalData:AAD(type)},k,b64d(h.ct));return dec.decode(buf)}
function checkHeader(h,type){
  if(!(h&&h.app==='mis-finanzas'&&h.type===type&&h.v===2&&h.kdf==='PBKDF2-SHA256'&&Number.isInteger(h.iter)&&h.iter>=100000&&h.iter<=5000000&&['salt','iv','ct'].every(k=>typeof h[k]==='string')))throw new Error('Formato de cifrado no reconocido');
  return h}

let key=null,vaultMeta=null,saveQueue=Promise.resolve();
const LEGACY_KEYS=['mf15','mf15-pin-hash','mf15-pin-salt'];
const vaultExists=()=>!!localStorage.getItem('mf15-vault');
const legacyPinExists=()=>!!localStorage.getItem('mf15-pin-hash');

/* Cada cambio se cifra y guarda en orden (cola); los datos nunca se escriben en texto plano */
function save(){
  if(!key)return;
  const snap=JSON.stringify(db);
  saveQueue=saveQueue.then(async()=>{const h=await seal(key,vaultMeta.salt,vaultMeta.iter,snap,'vault');localStorage.setItem('mf15-vault',JSON.stringify(h))}).catch(err=>alert('No se pudieron guardar los cambios: '+err.message))}

/* Primera vez (o migración): cifra los datos actuales, verifica que se pueden descifrar y recién entonces borra el texto plano */
async function createVault(pass){
  const rawStr=localStorage.getItem('mf15');let raw=null,corrupt=false;
  try{raw=JSON.parse(rawStr||'null')}catch{corrupt=true;localStorage.setItem('mf15-corrupto',rawStr)}
  const newDb=normalize(raw||sample),snap=JSON.stringify(newDb);
  const salt=crypto.getRandomValues(new Uint8Array(16)),k=await deriveKey(pass,salt,ITER);
  localStorage.setItem('mf15-vault',JSON.stringify(await seal(k,salt,ITER,snap,'vault')));
  let back;try{back=await unseal(k,JSON.parse(localStorage.getItem('mf15-vault')),'vault')}catch{back=null}
  if(back!==snap){localStorage.removeItem('mf15-vault');throw new Error('La verificación del cifrado falló. No se modificó ningún dato.')}
  LEGACY_KEYS.forEach(n=>localStorage.removeItem(n));
  key=k;vaultMeta={salt,iter:ITER};db=newDb;
  if(corrupt)alert('Tus datos antiguos estaban dañados. Se conservó una copia en el navegador (mf15-corrupto) y se creó una base nueva; restaura un respaldo si tienes uno.')}

async function openVault(pass){
  const h=checkHeader(JSON.parse(localStorage.getItem('mf15-vault')),'vault'),salt=b64d(h.salt);
  const k=await deriveKey(pass,salt,h.iter);let plain;
  try{plain=await unseal(k,h,'vault')}catch{return false}       // clave incorrecta o archivo alterado
  db=normalize(JSON.parse(plain));key=k;vaultMeta={salt,iter:h.iter};
  LEGACY_KEYS.forEach(n=>localStorage.removeItem(n));              // limpia restos en texto plano
  return true}

/* ================= BLOQUEO ================= */
let lockMode='unlock',legacyOk=false,failCount=0,blockedUntil=0,busy=false,pendingBackup=null;
async function hashPin(pin,salt){const h=await crypto.subtle.digest('SHA-256',enc.encode(salt+pin));return [...new Uint8Array(h)].map(x=>x.toString(16).padStart(2,'0')).join('')}
const initialMode=()=>vaultExists()?'unlock':(legacyPinExists()&&!legacyOk?'legacy':'setup');
const LOCK_TEXT={
  legacy:{title:'Mis Finanzas bloqueada',text:'Introduce tu PIN actual de 6 dígitos. Después crearás una frase de contraseña para cifrar tus datos.',btn:'Continuar',ph:'••••••'},
  setup:{title:'Cifra tus finanzas',text:'Crea una frase de contraseña de 8 o más caracteres. Si la olvidas no hay forma de recuperar los datos, así que guarda también un respaldo.',btn:'Cifrar y continuar',ph:'Frase de contraseña'},
  unlock:{title:'Mis Finanzas bloqueada',text:'Introduce tu frase de contraseña',btn:'Desbloquear',ph:'Frase de contraseña'}};
function showLock(m=initialMode()){
  clearTimeout(timer);lockMode=m;$('#fab').classList.add('hide');const t=LOCK_TEXT[m],p=$('#pin');
  $('#lock').classList.remove('hide');p.value=$('#pin2').value='';
  $('#pin2').classList.toggle('hide',m!=='setup');
  p.placeholder=t.ph;$('#pin2').placeholder='Repite la frase';
  if(m==='legacy'){p.setAttribute('inputmode','numeric');p.maxLength=6}else{p.setAttribute('inputmode','text');p.removeAttribute('maxlength')}
  p.setAttribute('autocomplete',m==='setup'?'new-password':'current-password');
  $('#lockTitle').textContent=t.title;$('#lockText').textContent=t.text;$('#unlockBtn').textContent=t.btn;$('#pinError').textContent=''}

/* Borra de la pantalla y de la memoria todo lo sensible */
function wipe(){
  key=null;vaultMeta=null;db=normalize({});mode='';eid=null;payCtx=null;pendingBackup=null;
  ['catdonut','budbars','recent','movelist','cardlist','statementlist','budgetlist','catlist','fields','quickBody'].forEach(i=>$('#'+i).innerHTML='');
  ['balance','income','expense','cardExpense','mtitle'].forEach(i=>$('#'+i).textContent='');
  donutSel=null;donutCtx={mp:{},xs:[],inst:[]};qk={type:'expense',cat:null,when:'today'};
  $('#quick').classList.add('hide');$('#toast').classList.add('hide');$('#fab').classList.add('hide');
  closeModal()}
function lock(){
  clearTimeout(timer);
  if(!key)return;                      // ya bloqueada, o aún en el paso de crear la frase
  showLock('unlock');                  // 1º se tapa la pantalla…
  saveQueue=saveQueue.then(wipe)}      // …2º se terminan de guardar los cambios y se borra todo de memoria
function arm(){clearTimeout(timer);timer=setTimeout(lock,LOCK_MS)}
function afterUnlock(){$('#lock').classList.add('hide');$('#fab').classList.remove('hide');$('#pin').value=$('#pin2').value='';failCount=0;render();arm()}
function setBusy(b){busy=b;$('#unlockBtn').disabled=b;$('#unlockBtn').textContent=b?'Procesando…':LOCK_TEXT[lockMode].btn}
function failed(msg){failCount++;$('#pin').value='';if(failCount>=5){failCount=0;blockedUntil=Date.now()+30000;$('#pinError').textContent='Demasiados intentos. Espera 30 segundos.'}else $('#pinError').textContent=msg}

$('#lockForm').onsubmit=async e=>{
  e.preventDefault();if(busy)return;
  const p=$('#pin').value,p2=$('#pin2').value,err=t=>{$('#pinError').textContent=t};
  if(Date.now()<blockedUntil)return err(`Demasiados intentos. Espera ${Math.ceil((blockedUntil-Date.now())/1000)} segundos.`);
  setBusy(true);
  try{
    if(lockMode==='legacy'){
      if(!/^\d{6}$/.test(p))return err('El PIN debe tener 6 dígitos.');
      if(await hashPin(p,localStorage.getItem('mf15-pin-salt'))!==localStorage.getItem('mf15-pin-hash'))return failed('PIN incorrecto.');
      legacyOk=true;failCount=0;showLock('setup');return}
    if(lockMode==='setup'){
      if(p.length<8)return err('Usa 8 o más caracteres. Una frase de varias palabras es lo mejor.');
      if(p!==p2)return err('Las frases no coinciden.');
      await createVault(p);afterUnlock();return}
    if(!(await openVault(p)))return failed('Frase incorrecta.');
    afterUnlock()
  }catch(x){err('Error: '+x.message)}finally{setBusy(false)}};
['pointerdown','keydown','touchstart','scroll'].forEach(e=>document.addEventListener(e,()=>{$('#lock').classList.contains('hide')&&arm()},{passive:true}));
document.addEventListener('visibilitychange',()=>document.hidden&&lock());
$('#lockNow').onclick=$('#securityLock').onclick=lock;
$('#changePass').onclick=()=>openModal('Cambiar frase de contraseña',f('Frase actual','<input id="fp0" type="password" autocomplete="current-password" required>')+f('Nueva frase (8 o más caracteres)','<input id="fp1" type="password" autocomplete="new-password" required>')+f('Repite la nueva frase','<input id="fp2" type="password" autocomplete="new-password" required>')+'<small>Los respaldos que ya descargaste seguirán necesitando la frase que tenías al exportarlos.</small>','changepass');

/* ================= TARJETAS: ciclos, cuotas, estados ================= */
function addMonths(ym,n){let [y,m]=ym.split('-').map(Number),d=new Date(y,m-1+n,1);return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`}
function billingMonth(date,c){let d=new Date(date+'T12:00'),day=d.getDate(),ym=date.slice(0,7);return day<=c.cycleEnd?ym:addMonths(ym,1)}
function installments(p){let c=card(p.cardId),first=billingMonth(p.date,c);return Array.from({length:p.installments},(_,i)=>({purchaseId:p.id,index:i+1,total:p.installments,month:addMonths(first,i),amount:p.installmentValue,desc:p.desc,cat:p.cat}))}
function allInstallments(){return db.purchases.flatMap(installments)}
function usedLimit(cid){return db.purchases.filter(p=>p.cardId===cid).reduce((a,p)=>a+p.installments*p.installmentValue,0)-db.statementPayments.filter(p=>p.cardId===cid).reduce((a,p)=>a+p.amount,0)}
function statement(cid,mo){let items=allInstallments().filter(i=>i.month===mo&&db.purchases.find(p=>p.id===i.purchaseId)?.cardId===cid),total=items.reduce((a,b)=>a+b.amount,0),payment=db.statementPayments.find(p=>p.cardId===cid&&p.month===mo);return{items,total,payment}}

/* ================= RENDER (todo texto de usuario pasa por esc(); botones con data-act) ================= */
function rows(xs,act=true){
  return xs.map(x=>{
    const sign=x.type==='income'?'+':'-',colour=x.type==='income'?'green':x.type==='card_payment'?'orange':'red';
    const edit=act&&x.type!=='card_payment'?`<button class="link" data-act="editMove" data-id="${esc(x.id)}">Editar</button>`:'';
    const del=act?`<button class="link" data-act="delMove" data-id="${esc(x.id)}">Eliminar</button>`:'';
    return `<div class="row"><div class="grow"><b>${esc(x.desc)}</b><small>${esc(cat(x.cat))} · ${esc(x.account)} · ${new Date(x.date+'T12:00').toLocaleDateString('es-CL')}</small></div><span class="amt ${colour}">${sign}${money(x.amount)}</span>${edit}${del}</div>`}).join('')||'<p>Sin registros.</p>'}

function render(){
  let xs=db.moves.filter(x=>x.date.startsWith(month())),inc=xs.filter(x=>x.type==='income').reduce((a,b)=>a+b.amount,0),exp=xs.filter(x=>x.type==='expense').reduce((a,b)=>a+b.amount,0),inst=allInstallments().filter(x=>x.month===month()),ci=inst.reduce((a,b)=>a+b.amount,0);
  $('#income').textContent=money(inc);$('#expense').textContent=money(exp);$('#cardExpense').textContent=money(ci);
  $('#balance').textContent=money(inc-exp-db.moves.filter(x=>x.type==='card_payment'&&x.date.startsWith(month())).reduce((a,b)=>a+b.amount,0));
  let mp={};xs.filter(x=>x.type==='expense').forEach(x=>mp[x.cat]=(mp[x.cat]||0)+x.amount);
  inst.forEach(x=>mp[x.cat]=(mp[x.cat]||0)+x.amount);
  donutCtx={mp,xs,inst};$('#catdonut').innerHTML=donutHTML();
  $('#budbars').innerHTML=db.budgets.filter(x=>x.month===month()).map(b=>bar(cat(b.cat),mp[b.cat]||0,b.amount,`${money(mp[b.cat]||0)} / ${money(b.amount)}`)).join('')||'<p>Sin presupuestos.</p>';
  $('#recent').innerHTML=rows(xs.sort((a,b)=>b.date.localeCompare(a.date)).slice(0,5),false);
  renderMoves();renderCards();renderStatements();
  $('#budgetlist').innerHTML=db.budgets.map(b=>`<div class="row"><div class="grow"><b>${esc(cat(b.cat))}</b><small>${esc(b.month)}</small></div><span class="amt">${money(b.amount)}</span><button class="link" data-act="editBudget" data-id="${esc(b.id)}">Editar</button><button class="link" data-act="delBudget" data-id="${esc(b.id)}">Eliminar</button></div>`).join('')||'<p>Sin presupuestos.</p>';
  $('#catlist').innerHTML=db.cats.map(c=>`<div class="row"><div class="grow"><b>${esc(c.name)}</b><small>${c.type==='expense'?'Gasto':'Ingreso'}</small></div><button class="link" data-act="editCat" data-id="${esc(c.id)}">Editar</button></div>`).join('')}

function bar(n,v,max,t=money(v)){let p=Math.min(100,max?v/max*100:0);return `<div class="bar"><div class="barhead"><span>${esc(n)}</span><span>${t}</span></div><div class="track"><div class="fill ${p>=100?'over':''}" style="width:${p}%"></div></div></div>`}
function renderMoves(){let q=$('#search').value.toLowerCase(),k=$('#kind').value;$('#movelist').innerHTML=rows(db.moves.filter(x=>(k==='all'||x.type===k)&&`${x.desc} ${cat(x.cat)}`.toLowerCase().includes(q)).sort((a,b)=>b.date.localeCompare(a.date)))}

/* ================= DONA POR CATEGORÍA (SVG propio, sin librerías) ================= */
let donutSel=null,donutCtx={mp:{},xs:[],inst:[]};
function donutHTML(){
  const {mp,xs,inst}=donutCtx,total=Object.values(mp).reduce((a,b)=>a+b,0),R=70,C=2*Math.PI*R,W=28;
  let items=Object.entries(mp).filter(([,v])=>v>0).map(([id,v])=>({id,name:cat(id),v,color:catColor(id)})).sort((a,b)=>b.v-a.v);
  if(items.length>8){const rest=items.slice(7);items=[...items.slice(0,7),{id:'__otras',name:`Otras (${rest.length})`,v:rest.reduce((a,b)=>a+b.v,0),color:'#94a3b8'}]}
  if(donutSel&&!items.some(i=>i.id===donutSel))donutSel=null;
  const sel=items.find(i=>i.id===donutSel),pct=v=>{const p=v/total*100;return p<1?'<1%':Math.round(p)+'%'};
  let acc=0,segs='';
  if(!total)segs=`<circle cx="100" cy="100" r="${R}" fill="none" stroke="#e2e8f0" stroke-width="${W}"/>`;
  else items.forEach(i=>{
    const len=i.v/total*C,gap=items.length>1?Math.min(2.5,len*.25):0,on=!!sel&&sel.id===i.id;
    segs+=`<circle cx="100" cy="100" r="${R}" fill="none" stroke="${i.color}" stroke-width="${on?W+6:W}" stroke-dasharray="${(len-gap).toFixed(2)} ${(C-len+gap).toFixed(2)}" stroke-dashoffset="${(-acc).toFixed(2)}" transform="rotate(-90 100 100)" opacity="${sel&&!on?0.35:1}"${i.id==='__otras'?'':` data-act="donutSeg" data-id="${esc(i.id)}"`}/>`;
    acc+=len});
  const big=sel?money(sel.v):money(total),small=sel?`${sel.name.length>15?sel.name.slice(0,14)+'…':sel.name} · ${pct(sel.v)}`:(total?'Gastos del mes':'Sin gastos');
  const svg=`<svg class="donut" viewBox="0 0 200 200" role="img" aria-label="Gráfico de dona de gastos por categoría">${segs}<text x="100" y="98" class="${big.length>10?'c1 s':'c1'}">${esc(big)}</text><text x="100" y="116" class="c2">${esc(small)}</text></svg>`;
  const legend=items.map(i=>{
    const inner=`<span class="dot" style="background:${i.color}"></span><span class="nm">${esc(i.name)}</span><span class="pc">${pct(i.v)}</span><span class="mt">${money(i.v)}</span>`;
    return i.id==='__otras'?`<div class="lg">${inner}</div>`:`<button type="button" class="lg${sel&&sel.id===i.id?' on':''}" data-act="donutSeg" data-id="${esc(i.id)}" aria-pressed="${!!sel&&sel.id===i.id}">${inner}</button>`}).join('')||'<p>Sin gastos este mes.</p>';
  let detail='';
  if(sel){
    const det=[...xs.filter(x=>x.type==='expense'&&x.cat===sel.id).map(x=>({d:x.date,t:x.desc,s:new Date(x.date+'T12:00').toLocaleDateString('es-CL'),a:x.amount})),
               ...inst.filter(i=>i.cat===sel.id).map(i=>({d:'',t:i.desc,s:`Cuota ${i.index}/${i.total}`,a:i.amount}))].sort((a,b)=>b.d.localeCompare(a.d));
    detail=`<div class="donutdetail"><h3>${esc(sel.name)}</h3>${det.slice(0,6).map(x=>`<div class="row"><div class="grow"><b>${esc(x.t)}</b><small>${esc(x.s)}</small></div><span class="amt red">-${money(x.a)}</span></div>`).join('')}${det.length>6?`<p>y ${det.length-6} más…</p>`:''}<button type="button" class="muted" data-act="donutMoves">Ver en Movimientos</button></div>`}
  return `<div class="donutwrap">${svg}<div class="legend">${legend}</div></div>${detail||(items.length?'<p class="hint">Toca una categoría para ver su detalle.</p>':'')}`}
function setDonut(id){donutSel=donutSel===id?null:id;$('#catdonut').innerHTML=donutHTML()}
function donutMoves(){if(!donutSel)return;$('#search').value=cat(donutSel);renderMoves();$$('nav button').find(b=>b.dataset.v==='moves').click()}

function paidInstallmentCount(p){return installments(p).filter(i=>db.statementPayments.some(sp=>sp.cardId===p.cardId&&sp.month===i.month)).length}

function purchaseRow(p){let paid=paidInstallmentCount(p),pending=Math.max(0,p.installments-paid);return `<div class="row"><div class="grow"><b>${esc(p.desc)}</b><small>${p.installments} cuotas de ${money(p.installmentValue)} · Total ${money(p.installments*p.installmentValue)} · ${pending} pendiente${pending===1?'':'s'} · ${esc(p.date)}</small></div><button class="link" data-act="editPurchase" data-id="${esc(p.id)}">Editar</button><button class="link" data-act="delPurchase" data-id="${esc(p.id)}">Eliminar</button></div>`}

function projectionRows(cid){let months=[...new Set(allInstallments().filter(i=>db.purchases.find(p=>p.id===i.purchaseId)?.cardId===cid).map(i=>i.month))].sort();return months.map(m=>{let st=statement(cid,m);return `<div class="row"><div class="grow"><b>${esc(m)}</b><small>${st.payment?'Estado pagado':'Estado pendiente'}</small></div><span class="amt">${money(st.total)}</span></div>`}).join('')||'<p>Sin proyección.</p>'}

function renderCards(){$('#cardlist').innerHTML=db.cards.map(c=>{let used=Math.max(0,usedLimit(c.id)),available=c.limit-used,ps=db.purchases.filter(p=>p.cardId===c.id),active=ps.filter(p=>paidInstallmentCount(p)<p.installments),finished=ps.filter(p=>paidInstallmentCount(p)>=p.installments);return `<details class="credit accordion"><summary class="accordionSummary"><span><b>${esc(c.name)}</b><small>${esc(c.bank)} · Cupo disponible ${money(available)}</small></span><span class="chevron">⌄</span></summary><div class="accordionBody"><div class="creditHead"><div><p>Ciclo ${esc(c.cycleStart)} al ${esc(c.cycleEnd)} · Vence día ${esc(c.dueDay)}</p></div><div class="actions"><button data-act="addPurchase" data-id="${esc(c.id)}">+ Compra</button><button class="muted" data-act="editCard" data-id="${esc(c.id)}">Editar tarjeta</button></div></div><div class="metrics"><div class="metric"><span>Cupo total</span><strong>${money(c.limit)}</strong></div><div class="metric"><span>Utilizado</span><strong>${money(used)}</strong></div><div class="metric"><span>Disponible</span><strong>${money(available)}</strong></div></div><details class="subAccordion"><summary>Compras activas (${active.length})</summary><div class="subBody">${active.map(purchaseRow).join('')||'<p>Sin compras activas.</p>'}</div></details><details class="subAccordion"><summary>Compras finalizadas (${finished.length})</summary><div class="subBody">${finished.map(purchaseRow).join('')||'<p>Sin compras finalizadas.</p>'}</div></details><details class="subAccordion"><summary>Proyección futura</summary><div class="subBody">${projectionRows(c.id)}</div></details></div></details>`}).join('')||'<article class="panel"><p>Crea tu primera tarjeta.</p></article>'}

function statementMonths(cid){return [...new Set(allInstallments().filter(i=>db.purchases.find(p=>p.id===i.purchaseId)?.cardId===cid).map(x=>x.month))].sort()}

function renderStatements(){let out='';db.cards.forEach(c=>{let months=statementMonths(c.id),pending=months.filter(m=>!statement(c.id,m).payment).length;out+=`<details class="credit accordion"><summary class="accordionSummary"><span><b>${esc(c.name)}</b><small>${pending} estado${pending===1?'':'s'} pendiente${pending===1?'':'s'}</small></span><span class="chevron">⌄</span></summary><div class="accordionBody">`;months.forEach(m=>{let s=statement(c.id,m);if(!s.items.length)return;let start=addMonths(m,-1)+'-'+String(c.cycleStart).padStart(2,'0'),end=m+'-'+String(c.cycleEnd).padStart(2,'0'),paid=!!s.payment;out+=`<details class="statement"><summary><span>${esc(m)} · ${money(s.total)}</span><span class="tag ${paid?'paid':''}">${paid?'Pagado':'Pendiente'}</span></summary><div class="statementDetail"><p>Período ${esc(start)} al ${esc(end)}. Vencimiento día ${esc(c.dueDay)} del mes siguiente.</p>${s.items.map(i=>`<div class="row"><div class="grow"><b>${esc(i.desc)}</b><small>Cuota ${i.index}/${i.total}</small></div><span class="amt">${money(i.amount)}</span></div>`).join('')}${paid?`<p>Pagado el ${esc(s.payment.date)} desde ${esc(s.payment.account)}.</p><button class="muted" data-act="undoPayment" data-id="${esc(s.payment.id)}">Deshacer pago</button>`:`<button data-act="payStatement" data-id="${esc(c.id)}" data-month="${esc(m)}">Registrar pago del estado</button>`}</div></details>`});out+='</div></details>'});$('#statementlist').innerHTML=out||'<p>Aún no hay cuotas facturadas.</p>'}

/* ================= MODAL Y FORMULARIOS ================= */
function opts(t,s){return db.cats.filter(x=>x.type===t).map(x=>`<option value="${esc(x.id)}" ${x.id===s?'selected':''}>${esc(x.name)}</option>`).join('')}
function f(n,h){return `<div class="field"><label>${n}</label>${h}</div>`}
function openModal(title,html,m,id=null){mode=m;eid=id;$('#mtitle').textContent=title;$('#fields').innerHTML=html;$('#modal').classList.remove('hide')}
function closeModal(){$('#modal').classList.add('hide')}

const ACCOUNTS=['Débito','Cuenta corriente','Efectivo','Transferencia'];
function editMove(id=null){
  const found=db.moves.find(y=>y.id===id);
  if(found&&found.type==='card_payment')return alert('Los pagos de tarjeta se administran en la pestaña Estados (usa "Deshacer pago").');
  const x=found||{type:'expense',amount:'',date:today,desc:'',cat:'g1',account:'Débito'};
  const accounts=ACCOUNTS.includes(x.account)?ACCOUNTS:[...ACCOUNTS,x.account];
  const accOpts=accounts.map(a=>`<option value="${esc(a)}" ${a===x.account?'selected':''}>${esc(a)}</option>`).join('');
  openModal(id?'Editar movimiento':'Nuevo movimiento',f('Tipo',`<select id="ft"><option value="expense" ${x.type==='expense'?'selected':''}>Gasto</option><option value="income" ${x.type==='income'?'selected':''}>Ingreso</option></select>`)+`<div class="two">${f('Monto',`<input id="fa" type="number" min="1" value="${esc(x.amount)}" required>`)}${f('Fecha',`<input id="fd" type="date" value="${esc(x.date)}" required>`)}</div>`+f('Descripción',`<input id="fdesc" value="${esc(x.desc)}" required>`)+f('Categoría',`<select id="fc">${opts(x.type,x.cat)}</select>`)+f('Medio',`<select id="fac">${accOpts}</select>`),'move',id);
  $('#ft').onchange=e=>$('#fc').innerHTML=opts(e.target.value)}

function editCard(id=null){let x=db.cards.find(y=>y.id===id)||{name:'',bank:'',limit:'',cycleStart:21,cycleEnd:20,dueDay:5};openModal(id?'Editar tarjeta':'Nueva tarjeta',f('Nombre',`<input id="fn" value="${esc(x.name)}" required>`)+f('Banco',`<input id="fb" value="${esc(x.bank)}" required>`)+f('Cupo total',`<input id="fl" type="number" min="1" value="${esc(x.limit)}" required>`)+`<div class="two">${f('Inicio ciclo',`<input id="fs" type="number" min="1" max="28" value="${esc(x.cycleStart)}" required>`)}${f('Cierre',`<input id="fe" type="number" min="1" max="28" value="${esc(x.cycleEnd)}" required>`)}</div>`+f('Día de vencimiento',`<input id="fdue" type="number" min="1" max="28" value="${esc(x.dueDay)}" required>`),'card',id)}

function editPurchase(id=null,cid=null){let x=db.purchases.find(y=>y.id===id)||{cardId:cid||db.cards[0]?.id,date:today,desc:'',cat:'g3',installments:1,installmentValue:'',cashPrice:''};openModal(id?'Editar compra':'Nueva compra',f('Tarjeta',`<select id="fcard">${db.cards.map(c=>`<option value="${esc(c.id)}" ${c.id===x.cardId?'selected':''}>${esc(c.name)}</option>`).join('')}</select>`)+f('Descripción',`<input id="fdesc" value="${esc(x.desc)}" required>`)+`<div class="two">${f('Fecha compra',`<input id="fd" type="date" value="${esc(x.date)}" required>`)}${f('Categoría',`<select id="fc">${opts('expense',x.cat)}</select>`)}</div>`+`<div class="two">${f('Número de cuotas',`<input id="fi" type="number" min="1" max="60" value="${esc(x.installments)}" required>`)}${f('Valor de cada cuota',`<input id="fv" type="number" min="1" value="${esc(x.installmentValue)}" required>`)}</div>`+f('Precio al contado opcional',`<input id="fcash" type="number" min="0" value="${esc(x.cashPrice||'')}"><small>El total financiado se calcula como cuotas × valor cuota.</small>`),'purchase',id)}

function editBudget(id=null){let x=db.budgets.find(y=>y.id===id)||{month:month(),cat:'g1',amount:''};openModal(id?'Editar presupuesto':'Nuevo presupuesto',f('Mes',`<input id="fm" type="month" value="${esc(x.month)}" required>`)+f('Categoría',`<select id="fc">${opts('expense',x.cat)}</select>`)+f('Monto',`<input id="fa" type="number" min="1" value="${esc(x.amount)}" required>`),'budget',id)}
function editCat(id=null){let x=db.cats.find(y=>y.id===id)||{name:'',type:'expense'};openModal(id?'Editar categoría':'Nueva categoría',f('Nombre',`<input id="fn" value="${esc(x.name)}" required>`)+f('Tipo',`<select id="ft"><option value="expense" ${x.type==='expense'?'selected':''}>Gasto</option><option value="income" ${x.type==='income'?'selected':''}>Ingreso</option></select>`),'cat',id)}

function payStatement(cid,mo){
  const st=statement(cid,mo);if(!st.items.length||st.payment)return;
  payCtx={cid,mo};
  openModal('Pagar estado de cuenta',f('Monto del estado',`<input value="${esc(st.total)}" disabled>`)+f('Fecha de pago',`<input id="fpd" type="date" value="${esc(today)}" required>`)+f('Cuenta de origen',`<select id="fpa"><option>Cuenta corriente</option><option>Cuenta vista</option><option>Ahorro</option></select>`),'payment',null)}

function applyBackup(plain){db=normalize(JSON.parse(plain));save();render()}

$('#form').onsubmit=async e=>{
  e.preventDefault();
  const id=eid||uid();
  switch(mode){
    case 'move':{
      const v={id,type:$('#ft').value,amount:+$('#fa').value,date:$('#fd').value,desc:$('#fdesc').value.trim(),cat:$('#fc').value,account:$('#fac').value};
      db.moves=eid?db.moves.map(x=>x.id===id?v:x):[...db.moves,v];break}
    case 'card':{
      const v={id,name:$('#fn').value.trim(),bank:$('#fb').value.trim(),limit:+$('#fl').value,cycleStart:+$('#fs').value,cycleEnd:+$('#fe').value,dueDay:+$('#fdue').value};
      db.cards=eid?db.cards.map(x=>x.id===id?v:x):[...db.cards,v];break}
    case 'purchase':{
      const v={id,cardId:$('#fcard').value,date:$('#fd').value,desc:$('#fdesc').value.trim(),cat:$('#fc').value,installments:+$('#fi').value,installmentValue:+$('#fv').value,cashPrice:+$('#fcash').value||null};
      const total=v.installments*v.installmentValue,old=eid?db.purchases.find(x=>x.id===eid):null;
      const available=card(v.cardId).limit-usedLimit(v.cardId)+(old?old.installments*old.installmentValue:0);
      if(total>available){alert('La compra supera el cupo disponible.');return}
      db.purchases=eid?db.purchases.map(x=>x.id===id?v:x):[...db.purchases,v];break}
    case 'budget':{
      const v={id,month:$('#fm').value,cat:$('#fc').value,amount:+$('#fa').value};
      db.budgets=eid?db.budgets.map(x=>x.id===id?v:x):[...db.budgets.filter(x=>!(x.month===v.month&&x.cat===v.cat)),v];break}
    case 'cat':{
      const v={id,name:$('#fn').value.trim(),type:$('#ft').value};
      db.cats=eid?db.cats.map(x=>x.id===id?v:x):[...db.cats,v];break}
    case 'payment':{
      const {cid,mo}=payCtx||{},st=statement(cid,mo);
      if(!payCtx||st.payment||!card(cid)){closeModal();return}
      const payment={id:uid(),cardId:cid,month:mo,amount:st.total,date:$('#fpd').value,account:$('#fpa').value};
      db.statementPayments.push(payment);
      db.moves.push({id:uid(),type:'card_payment',amount:st.total,date:payment.date,desc:`Pago estado ${mo} ${card(cid).name}`,cat:'g4',account:payment.account,statementPaymentId:payment.id});
      payCtx=null;break}
    case 'changepass':{
      const p0=$('#fp0').value,p1=$('#fp1').value,p2=$('#fp2').value;
      if(p1.length<8){alert('La nueva frase debe tener 8 o más caracteres.');return}
      if(p1!==p2){alert('Las frases nuevas no coinciden.');return}
      try{
        const cur=checkHeader(JSON.parse(localStorage.getItem('mf15-vault')),'vault');
        let okCur=true;try{await unseal(await deriveKey(p0,vaultMeta.salt,vaultMeta.iter),cur,'vault')}catch{okCur=false}
        if(!okCur){alert('La frase actual es incorrecta.');return}
        // el cambio de clave entra en la misma cola que los guardados para que nada se cruce
        const job=saveQueue.then(async()=>{
          const salt=crypto.getRandomValues(new Uint8Array(16)),k=await deriveKey(p1,salt,ITER);
          localStorage.setItem('mf15-vault',JSON.stringify(await seal(k,salt,ITER,JSON.stringify(db),'vault')));
          key=k;vaultMeta={salt,iter:ITER}});
        saveQueue=job.catch(()=>{});await job;
        closeModal();alert('Frase de contraseña actualizada.')
      }catch(x){alert('No se pudo cambiar la frase: '+x.message)}
      return}
    case 'restorepass':{
      const h=pendingBackup;if(!h){closeModal();return}
      try{const k=await deriveKey($('#fbp').value,b64d(h.salt),h.iter);applyBackup(await unseal(k,h,'backup'));pendingBackup=null;closeModal();alert('Respaldo restaurado')}
      catch{alert('Frase incorrecta o respaldo dañado.')}
      return}
  }
  save();closeModal();render()};

function undoPayment(id){db.statementPayments=db.statementPayments.filter(x=>x.id!==id);db.moves=db.moves.filter(x=>x.statementPaymentId!==id);save();render()}
function delMove(id){
  const m=db.moves.find(x=>x.id===id);if(!m)return;
  if(!confirm(m.type==='card_payment'?'¿Eliminar este pago? El estado de cuenta volverá a quedar pendiente.':'¿Eliminar movimiento?'))return;
  db.moves=db.moves.filter(x=>x.id!==id);
  if(m.statementPaymentId)db.statementPayments=db.statementPayments.filter(x=>x.id!==m.statementPaymentId);
  save();render()}
function delBudget(id){db.budgets=db.budgets.filter(x=>x.id!==id);save();render()}
function delPurchase(id){if(confirm('¿Eliminar compra y sus cuotas futuras?')){db.purchases=db.purchases.filter(x=>x.id!==id);save();render()}}

/* Todos los botones usan data-act (no hay JavaScript dentro del HTML): permite una política CSP estricta */
const ACTIONS={editMove,delMove,editBudget,delBudget,editCat,editCard,editPurchase,delPurchase,undoPayment,closeModal,addPurchase:id=>editPurchase(null,id),payStatement,quick:openQuick,closeQuick,qType:setQType,qCat:setQCat,qDate:setQDate,qSave:id=>saveQuick(id==='again'),donutSeg:setDonut,donutMoves};
document.addEventListener('click',e=>{const b=e.target.closest('[data-act]');if(!b)return;const a=b.getAttribute('data-act');if(!Object.hasOwn(ACTIONS,a))return;e.preventDefault();ACTIONS[a](b.getAttribute('data-id')??undefined,b.getAttribute('data-month')??undefined)});

/* ================= REGISTRO RÁPIDO (botón +) ================= */
let qk={type:'expense',cat:null,when:'today'};
const parseAmount=v=>Number(String(v).replace(/\D/g,''))||0;
function usageCounts(type){const c={};db.moves.forEach(m=>{if(m.type===type)c[m.cat]=(c[m.cat]||0)+1});return c}
function defaultAccount(type){const l=db.moves.filter(m=>m.type===type).sort((a,b)=>a.date.localeCompare(b.date)).at(-1);return l?l.account:(type==='income'?'Cuenta corriente':'Débito')}
function accountOptions(sel){const used=db.moves.filter(m=>m.type==='income'||m.type==='expense').map(m=>m.account).filter(Boolean);return [...new Set([...ACCOUNTS,...used,sel])].map(a=>`<option value="${esc(a)}" ${a===sel?'selected':''}>${esc(a)}</option>`).join('')}
function fillQuickCats(){
  const u=usageCounts(qk.type),list=db.cats.filter(c=>c.type===qk.type).sort((a,b)=>(u[b.id]||0)-(u[a.id]||0));   // las más usadas primero
  $('#qcats').innerHTML=list.map(c=>`<button type="button" class="chip${c.id===qk.cat?' on':''}" data-act="qCat" data-id="${esc(c.id)}" aria-pressed="${c.id===qk.cat}"><span class="dot" style="background:${catColor(c.id)}"></span>${esc(c.name)}</button>`).join('')||'<p>Crea una categoría primero.</p>'}
function quickHTML(){
  return `<div class="seg" role="group" aria-label="Tipo"><button type="button" class="on" data-act="qType" data-id="expense" aria-pressed="true">Gasto</button><button type="button" data-act="qType" data-id="income" aria-pressed="false">Ingreso</button></div>
<label class="qlabel" for="qa">Monto</label><div class="qamt"><span>$</span><input id="qa" inputmode="numeric" autocomplete="off" placeholder="0"></div>
<div class="qlabel">Categoría</div><div id="qcats" class="chips"></div>
<div class="qlabel">Fecha</div><div class="chips"><button type="button" class="chip on" data-act="qDate" data-id="today" aria-pressed="true">Hoy</button><button type="button" class="chip" data-act="qDate" data-id="yesterday" aria-pressed="false">Ayer</button><button type="button" class="chip" data-act="qDate" data-id="other" aria-pressed="false">Otra fecha</button></div><input id="qd" type="date" class="hide" value="${esc(localISO())}" aria-label="Fecha">
<div class="two"><div class="field"><label for="qac">Medio</label><select id="qac">${accountOptions(defaultAccount('expense'))}</select></div><div class="field"><label for="qn">Nota (opcional)</label><input id="qn" autocomplete="off"></div></div>
<p id="qerr" class="error" role="alert"></p>
<div class="qbtns"><button type="submit">Guardar</button><button type="button" class="muted" data-act="qSave" data-id="again">Guardar y agregar otro</button></div>`}
function openQuick(){
  if(!key)return;                                   // bloqueada: no hace nada
  closeModal();qk={type:'expense',cat:null,when:'today'};
  $('#quickBody').innerHTML=quickHTML();fillQuickCats();
  $('#quick').classList.remove('hide');$('#qa').focus()}
function closeQuick(){$('#quick').classList.add('hide');if(!$('#fab').classList.contains('hide'))$('#fab').focus()}
function setQType(t){qk.type=t;qk.cat=null;$$('#quickBody .seg button').forEach(b=>{const on=b.getAttribute('data-id')===t;b.classList.toggle('on',on);b.setAttribute('aria-pressed',on)});fillQuickCats();$('#qac').innerHTML=accountOptions(defaultAccount(t));$('#qerr').textContent=''}
function setQCat(id){qk.cat=id;fillQuickCats();$('#qerr').textContent=''}
function setQDate(w){qk.when=w;$$('#quickBody [data-act="qDate"]').forEach(b=>{const on=b.getAttribute('data-id')===w;b.classList.toggle('on',on);b.setAttribute('aria-pressed',on)});$('#qd').classList.toggle('hide',w!=='other');if(w==='other')$('#qd').focus()}
function toast(msg){const t=$('#toast');t.textContent=msg;t.classList.remove('hide');clearTimeout(toast.t);toast.t=setTimeout(()=>t.classList.add('hide'),2600)}
function saveQuick(again){
  if(!key)return;
  const err=t=>{$('#qerr').textContent=t},amount=parseAmount($('#qa').value);
  if(!amount)return err('Escribe un monto.');
  if(!qk.cat||!db.cats.some(c=>c.id===qk.cat))return err('Elige una categoría.');
  const d=new Date();let date=localISO(d);
  if(qk.when==='yesterday'){d.setDate(d.getDate()-1);date=localISO(d)}else if(qk.when==='other')date=$('#qd').value;
  if(!isDate(date))return err('Elige una fecha válida.');
  const c=db.cats.find(x=>x.id===qk.cat);
  db.moves=[...db.moves,{id:uid(),type:qk.type,amount,date,desc:$('#qn').value.trim()||c.name,cat:c.id,account:$('#qac').value}];
  save();render();
  toast(`${qk.type==='income'?'Ingreso':'Gasto'} guardado · ${money(amount)}`);
  if(again){$('#qa').value='';$('#qn').value='';err('');$('#qa').focus()}else closeQuick()}
$('#quickForm').onsubmit=e=>{e.preventDefault();saveQuick(false)};
document.addEventListener('input',e=>{if(e.target.id==='qa'){const d=e.target.value.replace(/\D/g,'').slice(0,10).replace(/^0+/,'');e.target.value=d?Number(d).toLocaleString('es-CL'):''}});   // 45200 -> 45.200
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!$('#quick').classList.contains('hide'))closeQuick()});

/* ================= NAVEGACIÓN, EXPORTAR, RESTAURAR ================= */
$$('nav button').forEach(b=>b.onclick=()=>{$$('nav button,.view').forEach(x=>x.classList.remove('on'));b.classList.add('on');$('#'+b.dataset.v).classList.add('on')});
$('#month').value=cm;$('#month').onchange=render;$('#search').oninput=renderMoves;$('#kind').onchange=renderMoves;
function dl(n,t,tp){let a=document.createElement('a');a.href=URL.createObjectURL(new Blob([t],{type:tp}));a.download=n;a.click()}
/* Respaldo JSON CIFRADO: reutiliza la sal y la clave de tu frase actual, con un IV nuevo */
$('#json').onclick=async()=>{
  if(!key)return;await saveQueue;
  const h=await seal(key,vaultMeta.salt,vaultMeta.iter,JSON.stringify(db),'backup');h.created=today;
  dl(`finanzas-1.7.0-${today}.cifrado.json`,JSON.stringify(h,null,2),'application/json')};
$('#csv').onclick=()=>{
  if(!confirm('El CSV NO está cifrado: cualquiera que abra el archivo verá tus movimientos. ¿Descargarlo de todas formas?'))return;
  dl('movimientos.csv','﻿Fecha;Tipo;Descripción;Categoría;Monto;Cuenta\n'+db.moves.map(x=>[x.date,x.type,x.desc,cat(x.cat),x.amount,x.account].map(csvCell).join(';')).join('\n'),'text/csv')};
$('#restore').onchange=e=>{
  const file=e.target.files[0];if(!file)return;
  const r=new FileReader();
  r.onload=async()=>{
    try{
      const imported=JSON.parse(r.result);
      if(!imported||typeof imported!=='object'||Array.isArray(imported))throw new Error('formato');
      if(imported.ct!==undefined){                         // respaldo cifrado
        const h=checkHeader(imported,'backup');
        if(vaultMeta&&h.salt===b64e(vaultMeta.salt)&&h.iter===vaultMeta.iter){applyBackup(await unseal(key,h,'backup'));alert('Respaldo restaurado')}   // misma frase: sin preguntar
        else{pendingBackup=h;openModal('Restaurar respaldo cifrado',f('Frase de contraseña con la que se exportó el respaldo','<input id="fbp" type="password" autocomplete="off" required>'),'restorepass')}
      }else{db=normalize(imported);save();render();alert('Respaldo restaurado')}   // respaldo antiguo en texto plano
    }catch{alert('Archivo no válido')}
    e.target.value=''};
  r.readAsText(file)};
$('#reset').onclick=()=>{if(confirm('¿Restablecer datos?')){db=normalize(sample);save();render()}};

if('serviceWorker'in navigator)addEventListener('load',()=>navigator.serviceWorker.register('./service-worker.js'));
showLock();
