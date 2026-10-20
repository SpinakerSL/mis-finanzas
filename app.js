/* Mis Finanzas 1.5.2 — misma clave de datos (mf15): tus datos actuales se conservan */
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const CLP=new Intl.NumberFormat('es-CL',{style:'currency',currency:'CLP',maximumFractionDigits:0});
/* Fecha LOCAL (antes usaba UTC y en Chile "hoy" pasaba a ser mañana después de ~21:00) */
const localISO=(d=new Date())=>`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
const today=localISO(),cm=today.slice(0,7),LOCK_MS=300000;
/* Escapado de HTML para todo texto ingresado por el usuario */
const ESC={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>ESC[c]);
/* Celda CSV segura: comillas duplicadas y neutraliza fórmulas (=, +, -, @) */
const csvCell=v=>{let s=String(v??'');if(/^[=+\-@\t\r]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"'};

const sample={cats:[{id:'g1',name:'Supermercado',type:'expense'},{id:'g2',name:'Combustible',type:'expense'},{id:'g3',name:'Tecnología',type:'expense'},{id:'g4',name:'Otros',type:'expense'},{id:'i1',name:'Sueldo',type:'income'}],moves:[{id:'m1',type:'income',amount:2850000,date:cm+'-01',desc:'Sueldo mensual',cat:'i1',account:'Cuenta corriente'}],budgets:[],cards:[{id:'c1',name:'Tarjeta principal',bank:'Banco',limit:3000000,cycleStart:21,cycleEnd:20,dueDay:5}],purchases:[],statementPayments:[]};

const uid=()=>crypto.randomUUID();
const isDate=s=>/^\d{4}-\d{2}-\d{2}$/.test(s),isMonth=s=>/^\d{4}-\d{2}$/.test(s);
const str=(v,d='')=>v==null?d:String(v),num=(v,d=0)=>Number.isFinite(Number(v))?Number(v):d;

/* Valida y normaliza datos (al cargar y al restaurar un respaldo) */
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

let db;try{db=normalize(JSON.parse(localStorage.getItem('mf15')||'null')||sample)}catch{db=structuredClone(sample)}
let mode='',eid=null,timer,changeMode=false,payCtx=null;
const save=()=>localStorage.setItem('mf15',JSON.stringify(db)),cat=id=>db.cats.find(x=>x.id===id)?.name||'Sin categoría',card=id=>db.cards.find(x=>x.id===id),money=v=>CLP.format(Number(v)||0),month=()=>$('#month').value||cm;

/* ---------- PIN / bloqueo (sin cambios) ---------- */
async function hashPin(pin,salt){const h=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(salt+pin));return [...new Uint8Array(h)].map(x=>x.toString(16).padStart(2,'0')).join('')}
function pinConfigured(){return !!localStorage.getItem('mf15-pin-hash')}
function showLock(setup=false){clearTimeout(timer);$('#lock').classList.remove('hide');$('#pin').value=$('#pin2').value='';$('#pin2').classList.toggle('hide',!setup);$('#lockTitle').textContent=setup?'Protege tus finanzas':'Mis Finanzas bloqueada';$('#lockText').textContent=setup?'Crea y confirma un PIN de 6 dígitos':'Introduce tu PIN de 6 dígitos';$('#unlockBtn').textContent=setup?'Crear PIN':'Desbloquear';$('#pinError').textContent=''}
function lock(){showLock(false)}
function arm(){clearTimeout(timer);timer=setTimeout(lock,LOCK_MS)}

$('#unlockBtn').onclick=async()=>{
  let p=$('#pin').value,p2=$('#pin2').value;
  if(!/^\d{6}$/.test(p))return $('#pinError').textContent='El PIN debe tener 6 dígitos.';
  if(!pinConfigured()||changeMode){
    if(p!==p2)return $('#pinError').textContent='Los PIN no coinciden.';
    let salt=uid();localStorage.setItem('mf15-pin-salt',salt);localStorage.setItem('mf15-pin-hash',await hashPin(p,salt));
    changeMode=false;$('#lock').classList.add('hide');arm();return}
  if(await hashPin(p,localStorage.getItem('mf15-pin-salt'))===localStorage.getItem('mf15-pin-hash')){$('#lock').classList.add('hide');arm()}
  else{$('#pinError').textContent='PIN incorrecto.';$('#pin').value=''}};
['pointerdown','keydown','touchstart','scroll'].forEach(e=>document.addEventListener(e,()=>{$('#lock').classList.contains('hide')&&arm()},{passive:true}));
document.addEventListener('visibilitychange',()=>document.hidden&&lock());
$('#lockNow').onclick=$('#securityLock').onclick=lock;
$('#changePin').onclick=()=>{changeMode=true;showLock(true)};

/* ---------- Tarjetas: ciclos, cuotas, estados ---------- */
function addMonths(ym,n){let [y,m]=ym.split('-').map(Number),d=new Date(y,m-1+n,1);return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`}
function billingMonth(date,c){let d=new Date(date+'T12:00'),day=d.getDate(),ym=date.slice(0,7);return day<=c.cycleEnd?ym:addMonths(ym,1)}
function installments(p){let c=card(p.cardId),first=billingMonth(p.date,c);return Array.from({length:p.installments},(_,i)=>({purchaseId:p.id,index:i+1,total:p.installments,month:addMonths(first,i),amount:p.installmentValue,desc:p.desc,cat:p.cat}))}
function allInstallments(){return db.purchases.flatMap(installments)}
function usedLimit(cid){return db.purchases.filter(p=>p.cardId===cid).reduce((a,p)=>a+p.installments*p.installmentValue,0)-db.statementPayments.filter(p=>p.cardId===cid).reduce((a,p)=>a+p.amount,0)}
function statement(cid,mo){let items=allInstallments().filter(i=>i.month===mo&&db.purchases.find(p=>p.id===i.purchaseId)?.cardId===cid),total=items.reduce((a,b)=>a+b.amount,0),payment=db.statementPayments.find(p=>p.cardId===cid&&p.month===mo);return{items,total,payment}}

/* ---------- Render (todo texto de usuario pasa por esc(); los botones usan data-act en vez de onclick con datos) ---------- */
function rows(xs,act=true){
  return xs.map(x=>{
    const sign=x.type==='income'?'+':'-',colour=x.type==='income'?'green':x.type==='card_payment'?'orange':'red';
    const edit=act&&x.type!=='card_payment'?`<button class="link" data-act="editMove" data-id="${esc(x.id)}">Editar</button>`:'';
    const del=act?`<button class="link" data-act="delMove" data-id="${esc(x.id)}">Eliminar</button>`:'';
    return `<div class="row"><div class="grow"><b>${esc(x.desc)}</b><small>${esc(cat(x.cat))} · ${esc(x.account)} · ${new Date(x.date+'T12:00').toLocaleDateString('es-CL')}</small></div><span class="amt ${colour}">${sign}${money(x.amount)}</span>${edit}${del}</div>`}).join('')||'<p>Sin registros.</p>'}

function render(){
  let xs=db.moves.filter(x=>x.date.startsWith(month())),inc=xs.filter(x=>x.type==='income').reduce((a,b)=>a+b.amount,0),exp=xs.filter(x=>x.type==='expense').reduce((a,b)=>a+b.amount,0),ci=allInstallments().filter(x=>x.month===month()).reduce((a,b)=>a+b.amount,0);
  $('#income').textContent=money(inc);$('#expense').textContent=money(exp);$('#cardExpense').textContent=money(ci);
  $('#balance').textContent=money(inc-exp-db.moves.filter(x=>x.type==='card_payment'&&x.date.startsWith(month())).reduce((a,b)=>a+b.amount,0));
  let mp={};xs.filter(x=>x.type==='expense').forEach(x=>mp[x.cat]=(mp[x.cat]||0)+x.amount);
  allInstallments().filter(x=>x.month===month()).forEach(x=>mp[x.cat]=(mp[x.cat]||0)+x.amount);
  let mx=Math.max(1,...Object.values(mp));
  $('#catbars').innerHTML=Object.entries(mp).map(([k,v])=>bar(cat(k),v,mx)).join('')||'<p>Sin gastos.</p>';
  $('#budbars').innerHTML=db.budgets.filter(x=>x.month===month()).map(b=>bar(cat(b.cat),mp[b.cat]||0,b.amount,`${money(mp[b.cat]||0)} / ${money(b.amount)}`)).join('')||'<p>Sin presupuestos.</p>';
  $('#recent').innerHTML=rows(xs.sort((a,b)=>b.date.localeCompare(a.date)).slice(0,5),false);
  renderMoves();renderCards();renderStatements();
  $('#budgetlist').innerHTML=db.budgets.map(b=>`<div class="row"><div class="grow"><b>${esc(cat(b.cat))}</b><small>${esc(b.month)}</small></div><span class="amt">${money(b.amount)}</span><button class="link" data-act="editBudget" data-id="${esc(b.id)}">Editar</button><button class="link" data-act="delBudget" data-id="${esc(b.id)}">Eliminar</button></div>`).join('')||'<p>Sin presupuestos.</p>';
  $('#catlist').innerHTML=db.cats.map(c=>`<div class="row"><div class="grow"><b>${esc(c.name)}</b><small>${c.type==='expense'?'Gasto':'Ingreso'}</small></div><button class="link" data-act="editCat" data-id="${esc(c.id)}">Editar</button></div>`).join('')}

function bar(n,v,max,t=money(v)){let p=Math.min(100,max?v/max*100:0);return `<div class="bar"><div class="barhead"><span>${esc(n)}</span><span>${t}</span></div><div class="track"><div class="fill ${p>=100?'over':''}" style="width:${p}%"></div></div></div>`}
function renderMoves(){let q=$('#search').value.toLowerCase(),k=$('#kind').value;$('#movelist').innerHTML=rows(db.moves.filter(x=>(k==='all'||x.type===k)&&`${x.desc} ${cat(x.cat)}`.toLowerCase().includes(q)).sort((a,b)=>b.date.localeCompare(a.date)))}

function paidInstallmentCount(p){return installments(p).filter(i=>db.statementPayments.some(sp=>sp.cardId===p.cardId&&sp.month===i.month)).length}

function purchaseRow(p){let paid=paidInstallmentCount(p),pending=Math.max(0,p.installments-paid);return `<div class="row"><div class="grow"><b>${esc(p.desc)}</b><small>${p.installments} cuotas de ${money(p.installmentValue)} · Total ${money(p.installments*p.installmentValue)} · ${pending} pendiente${pending===1?'':'s'} · ${esc(p.date)}</small></div><button class="link" data-act="editPurchase" data-id="${esc(p.id)}">Editar</button><button class="link" data-act="delPurchase" data-id="${esc(p.id)}">Eliminar</button></div>`}

function projectionRows(cid){let months=[...new Set(allInstallments().filter(i=>db.purchases.find(p=>p.id===i.purchaseId)?.cardId===cid).map(i=>i.month))].sort();return months.map(m=>{let st=statement(cid,m);return `<div class="row"><div class="grow"><b>${esc(m)}</b><small>${st.payment?'Estado pagado':'Estado pendiente'}</small></div><span class="amt">${money(st.total)}</span></div>`}).join('')||'<p>Sin proyección.</p>'}

function renderCards(){$('#cardlist').innerHTML=db.cards.map(c=>{let used=Math.max(0,usedLimit(c.id)),available=c.limit-used,ps=db.purchases.filter(p=>p.cardId===c.id),active=ps.filter(p=>paidInstallmentCount(p)<p.installments),finished=ps.filter(p=>paidInstallmentCount(p)>=p.installments);return `<details class="credit accordion"><summary class="accordionSummary"><span><b>${esc(c.name)}</b><small>${esc(c.bank)} · Cupo disponible ${money(available)}</small></span><span class="chevron">⌄</span></summary><div class="accordionBody"><div class="creditHead"><div><p>Ciclo ${esc(c.cycleStart)} al ${esc(c.cycleEnd)} · Vence día ${esc(c.dueDay)}</p></div><div class="actions"><button data-act="addPurchase" data-id="${esc(c.id)}">+ Compra</button><button class="muted" data-act="editCard" data-id="${esc(c.id)}">Editar tarjeta</button></div></div><div class="metrics"><div class="metric"><span>Cupo total</span><strong>${money(c.limit)}</strong></div><div class="metric"><span>Utilizado</span><strong>${money(used)}</strong></div><div class="metric"><span>Disponible</span><strong>${money(available)}</strong></div></div><details class="subAccordion"><summary>Compras activas (${active.length})</summary><div class="subBody">${active.map(purchaseRow).join('')||'<p>Sin compras activas.</p>'}</div></details><details class="subAccordion"><summary>Compras finalizadas (${finished.length})</summary><div class="subBody">${finished.map(purchaseRow).join('')||'<p>Sin compras finalizadas.</p>'}</div></details><details class="subAccordion"><summary>Proyección futura</summary><div class="subBody">${projectionRows(c.id)}</div></details></div></details>`}).join('')||'<article class="panel"><p>Crea tu primera tarjeta.</p></article>'}

function statementMonths(cid){return [...new Set(allInstallments().filter(i=>db.purchases.find(p=>p.id===i.purchaseId)?.cardId===cid).map(x=>x.month))].sort()}

function renderStatements(){let out='';db.cards.forEach(c=>{let months=statementMonths(c.id),pending=months.filter(m=>!statement(c.id,m).payment).length;out+=`<details class="credit accordion"><summary class="accordionSummary"><span><b>${esc(c.name)}</b><small>${pending} estado${pending===1?'':'s'} pendiente${pending===1?'':'s'}</small></span><span class="chevron">⌄</span></summary><div class="accordionBody">`;months.forEach(m=>{let s=statement(c.id,m);if(!s.items.length)return;let start=addMonths(m,-1)+'-'+String(c.cycleStart).padStart(2,'0'),end=m+'-'+String(c.cycleEnd).padStart(2,'0'),paid=!!s.payment;out+=`<details class="statement"><summary><span>${esc(m)} · ${money(s.total)}</span><span class="tag ${paid?'paid':''}">${paid?'Pagado':'Pendiente'}</span></summary><div class="statementDetail"><p>Período ${esc(start)} al ${esc(end)}. Vencimiento día ${esc(c.dueDay)} del mes siguiente.</p>${s.items.map(i=>`<div class="row"><div class="grow"><b>${esc(i.desc)}</b><small>Cuota ${i.index}/${i.total}</small></div><span class="amt">${money(i.amount)}</span></div>`).join('')}${paid?`<p>Pagado el ${esc(s.payment.date)} desde ${esc(s.payment.account)}.</p><button class="muted" data-act="undoPayment" data-id="${esc(s.payment.id)}">Deshacer pago</button>`:`<button data-act="payStatement" data-id="${esc(c.id)}" data-month="${esc(m)}">Registrar pago del estado</button>`}</div></details>`});out+='</div></details>'});$('#statementlist').innerHTML=out||'<p>Aún no hay cuotas facturadas.</p>'}

/* ---------- Modal y formularios ---------- */
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

/* Pago de estado: ahora es un modo más del único handler de submit (antes pisaba el handler y no lo restauraba) */
function payStatement(cid,mo){
  const st=statement(cid,mo);if(!st.items.length||st.payment)return;
  payCtx={cid,mo};
  openModal('Pagar estado de cuenta',f('Monto del estado',`<input value="${esc(st.total)}" disabled>`)+f('Fecha de pago',`<input id="fpd" type="date" value="${esc(today)}" required>`)+f('Cuenta de origen',`<select id="fpa"><option>Cuenta corriente</option><option>Cuenta vista</option><option>Ahorro</option></select>`),'payment',null)}

$('#form').onsubmit=e=>{
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
  }
  save();closeModal();render()};

function undoPayment(id){db.statementPayments=db.statementPayments.filter(x=>x.id!==id);db.moves=db.moves.filter(x=>x.statementPaymentId!==id);save();render()}
/* Borrar un pago de tarjeta desde Movimientos ahora también deshace el pago del estado */
function delMove(id){
  const m=db.moves.find(x=>x.id===id);if(!m)return;
  if(!confirm(m.type==='card_payment'?'¿Eliminar este pago? El estado de cuenta volverá a quedar pendiente.':'¿Eliminar movimiento?'))return;
  db.moves=db.moves.filter(x=>x.id!==id);
  if(m.statementPaymentId)db.statementPayments=db.statementPayments.filter(x=>x.id!==m.statementPaymentId);
  save();render()}
function delBudget(id){db.budgets=db.budgets.filter(x=>x.id!==id);save();render()}
function delPurchase(id){if(confirm('¿Eliminar compra y sus cuotas futuras?')){db.purchases=db.purchases.filter(x=>x.id!==id);save();render()}}

/* Botones generados dinámicamente: delegación de eventos con data-* (sin interpolar datos dentro de JS) */
const ACTIONS={editMove,delMove,editBudget,delBudget,editCat,editCard,editPurchase,delPurchase,undoPayment,addPurchase:id=>editPurchase(null,id),payStatement};
document.addEventListener('click',e=>{const b=e.target.closest('[data-act]');if(!b||!Object.hasOwn(ACTIONS,b.dataset.act))return;e.preventDefault();ACTIONS[b.dataset.act](b.dataset.id,b.dataset.month)});

/* ---------- Navegación, exportar, restaurar ---------- */
$$('nav button').forEach(b=>b.onclick=()=>{$$('nav button,.view').forEach(x=>x.classList.remove('on'));b.classList.add('on');$('#'+b.dataset.v).classList.add('on')});
$('#month').value=cm;$('#month').onchange=render;$('#search').oninput=renderMoves;$('#kind').onchange=renderMoves;
function dl(n,t,tp){let a=document.createElement('a');a.href=URL.createObjectURL(new Blob([t],{type:tp}));a.download=n;a.click()}
$('#json').onclick=()=>dl(`finanzas-1.5.2-${today}.json`,JSON.stringify(db,null,2),'application/json');
$('#csv').onclick=()=>dl('movimientos.csv','﻿Fecha;Tipo;Descripción;Categoría;Monto;Cuenta\n'+db.moves.map(x=>[x.date,x.type,x.desc,cat(x.cat),x.amount,x.account].map(csvCell).join(';')).join('\n'),'text/csv');
$('#restore').onchange=e=>{
  const file=e.target.files[0];if(!file)return;
  const r=new FileReader();
  r.onload=()=>{try{const imported=JSON.parse(r.result);if(!imported||typeof imported!=='object'||Array.isArray(imported))throw new Error('formato');db=normalize(imported);save();render();alert('Respaldo restaurado')}catch{alert('Archivo no válido')}e.target.value=''};
  r.readAsText(file)};
$('#reset').onclick=()=>{if(confirm('¿Restablecer datos?')){db=normalize(sample);save();render()}};
render();showLock(!pinConfigured());
