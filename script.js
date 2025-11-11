/* Terminal-like GUI firewall simulator
   - GUI buttons & forms drive the simulator
   - Terminal-style animated output in the right pane (typing effect)
   - Functions: add/del/list rules, NAT, simulate packet, toggle stateful, logs, export/import
*/

const screen = document.getElementById('screen');
const importFile = document.getElementById('importFile');

// status display
const statusStateful = document.getElementById('statusStateful');
const statusNat = document.getElementById('statusNat');
const statusRun = document.getElementById('statusRun');
const statusRules = document.getElementById('statusRules');
const statusNATC = document.getElementById('statusNATC');

// buttons
const btnStart = document.getElementById('btnStart');
const btnStop = document.getElementById('btnStop');
const btnStep = document.getElementById('btnStep');
const btnShowRules = document.getElementById('btnShowRules');
const btnAddRule = document.getElementById('btnAddRule');
const btnDelRule = document.getElementById('btnDelRule');
const btnShowNat = document.getElementById('btnShowNat');
const btnAddNat = document.getElementById('btnAddNat');
const btnDelNat = document.getElementById('btnDelNat');
const btnSimPkt = document.getElementById('btnSimPkt');
const btnAutoMal = document.getElementById('btnAutoMal');
const btnStateful = document.getElementById('btnStateful');
const btnShowLogs = document.getElementById('btnShowLogs');
const btnClearLogs = document.getElementById('btnClearLogs');
const btnExport = document.getElementById('btnExport');
const btnImport = document.getElementById('btnImport');
const btnClear = document.getElementById('btnClear');
const btnScrollBottom = document.getElementById('btnScrollBottom');

const formAddRule = document.getElementById('formAddRule');
const fAction = document.getElementById('fAction');
const fProto = document.getElementById('fProto');
const fSrc = document.getElementById('fSrc');
const fDst = document.getElementById('fDst');
const fPort = document.getElementById('fPort');
const fLog = document.getElementById('fLog');

// state
let running = false;
let ticker = null;
let autoMal = false;
let stateful = true;
let natEnabled = true;

function idGen(){ return Math.random().toString(36).slice(2,9); }
function now(){ return new Date().toLocaleTimeString(); }

// core simulator data
let rules = [
  {id:idGen(), action:'DENY', proto:'TCP', src:'any', dst:'10.0.0.5', port:'22', log:true},
  {id:idGen(), action:'ALLOW', proto:'any', src:'any', dst:'10.0.0.5', port:'any', log:false}
];
let natTable = [
  {id:idGen(), external:8080, internalHost:'10.0.0.5', internalPort:80}
];
let logs = [];
let connTable = [];

// ---------------- Terminal output with typing animation ----------------
let typingQueue = [];
let typing = false;
function pushLog(line, cls='line'){
  // append raw to logs (for show logs)
  logs.unshift(`[${now()}] ${line}`);
  if(logs.length>400) logs.pop();
  enqueueType(line, cls);
}
function enqueueType(text, cls='line'){
  typingQueue.push({text, cls});
  if(!typing) runTyping();
}
function runTyping(){
  if(typingQueue.length===0){ typing=false; return; }
  typing = true;
  const item = typingQueue.shift();
  const el = document.createElement('div');
  el.className = item.cls;
  screen.appendChild(el);
  screen.scrollTop = screen.scrollHeight;
  let i=0;
  const speed = 8 + Math.random()*22; // ms per char
  function tick(){
    if(i < item.text.length){
      el.textContent += item.text[i++];
      screen.scrollTop = screen.scrollHeight;
      setTimeout(tick, speed);
    } else {
      // small pause then next
      setTimeout(runTyping, 80);
    }
  }
  tick();
}

// quick helper to render immediate line (no typing)
function printLine(text, cls='line'){
  const el = document.createElement('div');
  el.className = cls;
  el.textContent = text;
  screen.appendChild(el);
  screen.scrollTop = screen.scrollHeight;
}

// ---------------- state helpers ----------------
function refreshStatus(){
  statusStateful.textContent = stateful ? 'ON' : 'OFF';
  statusNat.textContent = natEnabled ? 'ON' : 'OFF';
  statusRun.textContent = running ? 'YES' : 'NO';
  statusRules.textContent = rules.length;
  statusNATC.textContent = natTable.length;
}
refreshStatus();

// ---------------- Rule engine ----------------
function ipMatch(ruleIp, ip){
  if(!ruleIp || ruleIp.toLowerCase()==='any') return true;
  return ruleIp.trim() === ip.trim();
}
function protoMatch(ruleProto, proto){
  if(!ruleProto || ruleProto.toLowerCase()==='any') return true;
  return ruleProto.trim().toLowerCase() === proto.trim().toLowerCase();
}
function portMatch(rulePort, pktPort){
  if(!rulePort || rulePort.toLowerCase()==='any') return true;
  if(rulePort.includes('-')){
    const [a,b] = rulePort.split('-').map(Number); return pktPort >= a && pktPort <= b;
  }
  if(rulePort.includes(',')){
    return rulePort.split(',').map(x=>Number(x.trim())).includes(Number(pktPort));
  }
  return Number(rulePort) === Number(pktPort);
}

function matchPacket(pkt){
  // stateful check
  if(stateful){
    const flow = `${pkt.src}:${pkt.srcPort||'(ephemeral)'}->${pkt.dst}:${pkt.dstPort}/${pkt.proto}`;
    const rev = `${pkt.dst}:${pkt.dstPort}->${pkt.src}:${pkt.srcPort||'(ephemeral)'}${'/' + pkt.proto}`;
    if(connTable.find(e=>e.flow===flow || e.flow===rev)){
      return {action:'ALLOW', ruleId:'(stateful)'};
    }
  }
  // NAT translation
  if(natEnabled){
    const nat = natTable.find(n => Number(n.external) === Number(pkt.dstPort));
    if(nat){
      pkt._origDst = pkt.dst; pkt._origDstPort = pkt.dstPort;
      pkt.dst = nat.internalHost; pkt.dstPort = Number(nat.internalPort);
      pushLog(`NAT applied: external ${nat.external} → ${pkt.dst}:${pkt.dstPort}`);
    }
  }
  // top-down rules
  for(let r of rules){
    if(ipMatch(r.src, pkt.src) && ipMatch(r.dst, pkt.dst) && protoMatch(r.proto, pkt.proto) && portMatch(r.port, pkt.dstPort)){
      return {action: r.action, ruleId: r.id, log: r.log};
    }
  }
  return {action:'DENY', ruleId:'(default)'};
}

// ---------------- Packet model ----------------
function createPacket({proto='TCP', src='198.51.100.7', dst='10.0.0.5', dstPort=80, threat='benign', payload='' }){
  const pkt = {id:idGen(), proto, src, dst, dstPort, threat, payload, created:Date.now()};
  // evaluate quickly and log outcome
  // simple IDS signature check
  if(payload && payload.toLowerCase().includes('union select')){ pushLog('IDS: SQLi signature detected'); pkt.threat='exploit'; }
  if(payload && payload.toLowerCase().includes('<script')){ pushLog('IDS: XSS signature detected'); pkt.threat='exploit'; }

  // match
  const res = matchPacket(Object.assign({}, pkt));
  if(res.action === 'ALLOW'){
    pushLog(`ALLOW [${res.ruleId}] ${pkt.proto} ${pkt.src} -> ${pkt.dst}:${pkt.dstPort}`);
    if(stateful){
      const flow = `${pkt.src}:*->${pkt.dst}:${pkt.dstPort}/${pkt.proto}`;
      connTable.unshift({flow, last: now()});
      connTable = connTable.slice(0,80);
    }
    enqueueType(`→ ${pkt.proto} ${pkt.src}:${pkt.dstPort} -> ${pkt.dst}  → ${'ALLOWED'} (rule:${res.ruleId})`, 'line');
  } else {
    pushLog(`BLOCK [${res.ruleId}] ${pkt.proto} ${pkt.src} -> ${pkt.dst}:${pkt.dstPort}`);
    enqueueType(`→ ${pkt.proto} ${pkt.src}:${pkt.dstPort} -> ${pkt.dst}  → ${'BLOCKED'} (rule:${res.ruleId})`, 'err');
  }
  refreshStatus();
}

// ---------------- Actions bound to GUI ----------------
btnStart.addEventListener('click', ()=>{
  if(running) { enqueueType('Simulation already running'); return; }
  running = true;
  ticker = setInterval(()=> {
    // step simulation: spawn occasional packets
    if(Math.random() < 0.32) createPacket({proto: Math.random()<0.6?'TCP':'UDP', src:`198.51.100.${Math.floor(Math.random()*220)}`, dst:'10.0.0.5', dstPort:[22,80,443,8080][Math.floor(Math.random()*4)], threat:'benign'});
    if(autoMal && Math.random() < 0.22){
      // spawn malicious burst
      if(Math.random() < 0.6){
        // port scan
        const src = `203.0.113.${Math.floor(Math.random()*220)}`;
        for(let i=0;i<4;i++) createPacket({proto:'TCP', src, dst:'10.0.0.5', dstPort: 20 + Math.floor(Math.random()*1000), threat:'scan'});
      } else {
        createPacket({proto:'TCP', src:`203.0.113.${Math.floor(Math.random()*220)}`, dst:'10.0.0.5', dstPort: 8080, threat:'exploit', payload:'/bin/bash -i'});
      }
    }
  }, 420);
  enqueueType('Simulation started', 'line');
  refreshStatus();
});

btnStop.addEventListener('click', ()=>{
  if(!running) { enqueueType('Simulation not running'); return; }
  running = false;
  clearInterval(ticker); ticker = null;
  enqueueType('Simulation stopped', 'line');
  refreshStatus();
});

btnStep.addEventListener('click', ()=> {
  createPacket({proto:'TCP', src:`198.51.100.${Math.floor(Math.random()*200)}`, dst:'10.0.0.5', dstPort:80});
  enqueueType('Single step executed', 'line');
});

// show rules
btnShowRules.addEventListener('click', ()=> {
  enqueueType('--- Firewall Rules (top→down) ---', 'line');
  if(rules.length===0) enqueueType('(no rules)', 'line');
  rules.forEach((r,i)=> enqueueType(`${i+1}. [${r.id}] ${r.action} ${r.proto} ${r.src} -> ${r.dst}:${r.port} ${r.log?'{log}':''}`, 'line'));
});

// add rule via modal/form immediate
btnAddRule.addEventListener('click', ()=> {
  // read form values
  const act = fAction.value || 'ALLOW';
  const proto = fProto.value.trim() || 'any';
  const src = fSrc.value.trim() || 'any';
  const dst = fDst.value.trim() || 'any';
  const port = fPort.value.trim() || 'any';
  const log = fLog.checked;
  const r = {id:idGen(), action:act, proto:proto.toUpperCase(), src, dst, port, log};
  rules.unshift(r); // top priority
  enqueueType(`Rule added: [${r.id}] ${r.action} ${r.proto} ${r.src} -> ${r.dst}:${r.port} ${log?'{log}':''}`, 'line');
  // clear form
  fProto.value=''; fSrc.value=''; fDst.value=''; fPort.value=''; fLog.checked=false;
  pushLog(`Rule add ${r.id}`);
  refreshStatus();
});

// delete rule by prompting small input (prompt-like)
btnDelRule.addEventListener('click', ()=> {
  const id = prompt('Enter rule id to delete (e.g. ab12cd3):');
  if(!id) { enqueueType('delete cancelled'); return; }
  const idx = rules.findIndex(r=>r.id === id);
  if(idx === -1){ enqueueType('rule id not found', 'err'); return; }
  rules.splice(idx,1);
  enqueueType(`Rule ${id} removed`, 'line');
  pushLog(`Rule del ${id}`);
  refreshStatus();
});

// show nat
btnShowNat.addEventListener('click', ()=> {
  enqueueType('--- NAT / Port-Forwards ---', 'line');
  if(natTable.length===0) enqueueType('(no nat entries)', 'line');
  natTable.forEach(n=> enqueueType(`[${n.id}] ext:${n.external} → ${n.internalHost}:${n.internalPort}`));
});

// add nat via prompt
btnAddNat.addEventListener('click', ()=>{
  const ext = prompt('External port (e.g. 8080):');
  if(!ext) { enqueueType('add nat cancelled'); return; }
  const internal = prompt('Internal host:port (e.g. 10.0.0.5:80):');
  if(!internal || !internal.includes(':')) { enqueueType('invalid internal, cancelled', 'err'); return; }
  const [h,p] = internal.split(':');
  const n = {id:idGen(), external: Number(ext), internalHost: h, internalPort: Number(p)};
  natTable.unshift(n);
  enqueueType(`NAT added: ${n.external} → ${n.internalHost}:${n.internalPort}`, 'line');
  pushLog(`NAT add ${n.id}`);
  refreshStatus();
});

// delete nat
btnDelNat.addEventListener('click', ()=>{
  const id = prompt('Enter NAT id to delete:');
  if(!id){ enqueueType('del nat cancelled'); return; }
  const idx = natTable.findIndex(n=>n.id===id);
  if(idx === -1){ enqueueType('nat id not found', 'err'); return; }
  natTable.splice(idx,1);
  enqueueType(`NAT ${id} removed`, 'line');
  pushLog(`NAT del ${id}`);
  refreshStatus();
});

// simulate packet via GUI prompts
btnSimPkt.addEventListener('click', ()=>{
  const proto = prompt('proto (TCP/UDP/ICMP) [TCP]:') || 'TCP';
  const src = prompt('src ip [198.51.100.7]:') || `198.51.100.${Math.floor(Math.random()*200)}`;
  const dst = prompt('dst ip [10.0.0.5]:') || '10.0.0.5';
  const port = Number(prompt('dst port [80]:') || 80);
  const payload = prompt('optional payload (press cancel for none):') || '';
  createPacket({proto, src, dst, dstPort:port, payload});
});

// toggle auto-mal
btnAutoMal.addEventListener('click', ()=>{
  autoMal = !autoMal;
  enqueueType(`auto-malicious set to ${autoMal}`, 'line');
});

// toggle stateful
btnStateful.addEventListener('click', ()=>{
  stateful = !stateful;
  enqueueType(`stateful = ${stateful}`, 'line');
  pushLog(`stateful set ${stateful}`);
  refreshStatus();
});

// show logs
btnShowLogs.addEventListener('click', ()=>{
  enqueueType('--- Recent Logs ---', 'line');
  if(logs.length===0) enqueueType('(no logs)', 'line');
  logs.slice(0,40).forEach(l => enqueueType(l, 'line'));
});

// clear logs
btnClearLogs.addEventListener('click', ()=>{
  logs = [];
  enqueueType('logs cleared', 'line');
});

// export config
btnExport.addEventListener('click', ()=>{
  const data = {rules, natTable};
  const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'fw-config.json'; a.click();
  URL.revokeObjectURL(url);
  enqueueType('Exported configuration (download started)', 'line');
});

// import config
btnImport.addEventListener('click', ()=> importFile.click());
importFile.addEventListener('change', (e)=>{
  const f = e.target.files[0]; if(!f) return;
  const reader = new FileReader();
  reader.onload = ev => {
    try{
      const d = JSON.parse(ev.target.result);
      if(Array.isArray(d.rules)) rules = d.rules.map(r=>({...r, id:idGen()}));
      if(Array.isArray(d.natTable)) natTable = d.natTable.map(n=>({...n, id:idGen()}));
      enqueueType('Imported configuration', 'line');
      pushLog('Config imported');
      refreshStatus();
    } catch(err){ enqueueType('Invalid JSON file', 'err'); }
  };
  reader.readAsText(f);
});

// clear screen
btnClear.addEventListener('click', ()=> { screen.innerHTML=''; enqueueType('screen cleared'); });

// scroll bottom
btnScrollBottom.addEventListener('click', ()=> screen.scrollTop = screen.scrollHeight);

// scroll-to-bottom helper after enqueueing
const originalEnqueueType = enqueueType;
function enqueueType(text, cls='line'){ typingQueue.push({text, cls}); if(!typing) runTyping(); }

// typing queue implementation (copied in to ensure local closure)
let typingQueue = [];
let typing = false;
function runTyping(){
  if(typingQueue.length===0){ typing=false; return; }
  typing = true;
  const item = typingQueue.shift();
  const el = document.createElement('div');
  el.className = item.cls;
  screen.appendChild(el);
  screen.scrollTop = screen.scrollHeight;
  let i=0;
  const speed = 6 + Math.random()*18;
  function tick(){
    if(i < item.text.length){
      el.textContent += item.text[i++];
      screen.scrollTop = screen.scrollHeight;
      setTimeout(tick, speed);
    } else {
      setTimeout(runTyping, 70);
    }
  }
  tick();
}

// initial banner
enqueueType('Firewall Simulator (GUI + Terminal look) — Karndeep Baror', 'line');
enqueueType('Use the buttons on the left to perform actions. Type-less interface, terminal animation for outputs.', 'line');
enqueueType('Default rules preloaded. Click "show rules" to inspect.', 'line');
refreshStatus();

// ---------------- utility: pushLog redefined to use enqueueType ----------------
function pushLog(msg){ logs.unshift(`[${now()}] ${msg}`); if(logs.length>500) logs.pop(); enqueueType(msg, 'line'); }

// ---------------- end of script ----------------
