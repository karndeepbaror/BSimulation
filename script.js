/* Firewall Simulator - educational
   - Real-feel rule matching + stateful connections + NAT/port-forward
   - Click packet to inspect why it was allowed/blocked
   - Export/import rules as JSON for demos
*/

/* ----------------- Helper & Utils ----------------- */
const $ = id => document.getElementById(id);
const nowTs = () => new Date().toISOString().slice(11,23);
function genId(){ return Math.random().toString(36).slice(2,9); }
function clamp(v, a, b){ return Math.max(a, Math.min(b, v)); }

// Basic IP match (supports 'any' or exact string). Keep intentionally simple.
// Could be extended to CIDR if needed.
function ipMatch(ruleIp, pktIp){
  if(!ruleIp || ruleIp.toLowerCase()==='any') return true;
  return ruleIp.trim() === pktIp.trim();
}
function protoMatch(ruleProto, pktProto){
  if(!ruleProto || ruleProto.toLowerCase()==='any') return true;
  return ruleProto.trim().toLowerCase() === pktProto.trim().toLowerCase();
}
function portMatch(rulePort, pktPort){
  if(!rulePort || rulePort.toLowerCase()==='any') return true;
  // support ranges like 1000-2000 and comma lists like 80,443
  if(rulePort.includes('-')){
    const [a,b] = rulePort.split('-').map(Number);
    return pktPort >= a && pktPort <= b;
  }
  if(rulePort.includes(',')){
    const parts = rulePort.split(',').map(p=>Number(p.trim()));
    return parts.includes(Number(pktPort));
  }
  return Number(rulePort) === Number(pktPort);
}

/* ----------------- State ----------------- */
let running = false;
let autoMalicious = false;
let stateful = true;
let natEnabled = true;

// Rules: top->down. Default sample rules included.
let rules = [
  // block SSH from internet by default (example)
  {src:'any', dst:'10.0.0.5', proto:'TCP', port:'22', action:'DENY', log:true, id: genId()},
  // allow common LAN traffic
  {src:'any', dst:'10.0.0.5', proto:'any', port:'any', action:'ALLOW', log:false, id: genId()},
];

// NAT/port-forward table
let natTable = [
  // example: external 8080 -> 10.0.0.5:80
  {external:8080, internalHost:'10.0.0.5', internalPort:80, id: genId()}
];

let packets = []; // animating packets
let logs = [];
let conntable = []; // simple stateful flows: {flow, src,dst,proto,port,last}

/* ----------------- DOM refs ----------------- */
const fwFront = $('fwFront');
const logsBox = $('logs');
const rulesList = $('rulesList');
const connTableBox = $('connTable');
const natList = $('natList');

/* ----------------- Rendering ----------------- */
function renderLogs(){
  logsBox.innerHTML = logs.slice(0,200).map(l=>`<div>${l}</div>`).join('');
}
function logLine(msg){
  logs.unshift(`[${nowTs()}] ${msg}`);
  if(logs.length>400) logs.pop();
  renderLogs();
}
function renderConn(){
  connTableBox.innerHTML = conntable.slice(0,80).map(c=>`<div class="small">${c.flow} • ${c.last}</div>`).join('');
}
function renderRules(){
  rulesList.innerHTML = rules.map(r=>`
    <div class="rule-item" data-id="${r.id}">
      <div>
        <div class="rule-meta">${r.src} → ${r.dst} • ${r.proto}/${r.port}</div>
        <div style="font-size:12px;color:#9aa4bf">${r.log? 'Log':'No Log'}</div>
      </div>
      <div style="display:flex;gap:6px;align-items:center">
        <div class="rule-action ${r.action==='ALLOW'?'allow':'deny'}">${r.action}</div>
        <button class="btn small" data-up="${r.id}">↑</button>
        <button class="btn small" data-down="${r.id}">↓</button>
        <button class="btn small" data-del="${r.id}">✖</button>
      </div>
    </div>`).join('');
  // attach listeners
  rulesList.querySelectorAll('button[data-del]').forEach(btn=>{
    btn.onclick = () => {
      const id = btn.getAttribute('data-del');
      rules = rules.filter(rr=>rr.id!==id);
      renderRules(); logLine(`Rule ${id} removed`);
    };
  });
  rulesList.querySelectorAll('button[data-up]').forEach(btn=>{
    btn.onclick = () => {
      const id = btn.getAttribute('data-up');
      const idx = rules.findIndex(r=>r.id===id);
      if(idx>0){ const r = rules.splice(idx,1)[0]; rules.splice(idx-1,0,r); renderRules(); }
    };
  });
  rulesList.querySelectorAll('button[data-down]').forEach(btn=>{
    btn.onclick = () => {
      const id = btn.getAttribute('data-down');
      const idx = rules.findIndex(r=>r.id===id);
      if(idx < rules.length-1){ const r = rules.splice(idx,1)[0]; rules.splice(idx+1,0,r); renderRules(); }
    };
  });
}
function renderNat(){
  natList.innerHTML = natTable.map(n=>`
    <div class="rule-item" data-id="${n.id}">
      <div>
        <div class="rule-meta">EXT:${n.external} → ${n.internalHost}:${n.internalPort}</div>
      </div>
      <div style="display:flex;gap:6px;align-items:center">
        <button class="btn small" data-delnat="${n.id}">✖</button>
      </div>
    </div>`).join('');
  natList.querySelectorAll('button[data-delnat]').forEach(btn=>{
    btn.onclick = () => {
      const id = btn.getAttribute('data-delnat');
      natTable = natTable.filter(nn=>nn.id!==id);
      renderNat(); logLine(`NAT mapping ${id} removed`);
    };
  });
}

/* ----------------- Rule Engine ----------------- */
function matchPacket(pkt){
  // Stateful: if flow exists, allow related (simulate established)
  if(stateful){
    const flow = `${pkt.src}:${pkt.srcPort||'(ephemeral)'}->${pkt.dst}:${pkt.dstPort}/${pkt.proto}`;
    const rev = `${pkt.dst}:${pkt.dstPort}->${pkt.src}:${pkt.srcPort||'(ephemeral)'}${'/' + pkt.proto}`;
    const existing = conntable.find(e => e.flow === flow || e.flow === rev);
    if(existing){
      existing.last = nowTs();
      // logLine(`Stateful match: ${flow}`);
      return {action:'ALLOW', ruleId:'(stateful)'};
    }
  }

  // NAT: if packet destined to firewall external IP and nat enabled, map internal
  if(natEnabled){
    // Check if dstPort matches external mapping
    const nat = natTable.find(n => Number(n.external) === Number(pkt.dstPort));
    if(nat){
      // simulate translation: new dst becomes internal host & internal port
      pkt._originalDst = pkt.dst;
      pkt._originalDstPort = pkt.dstPort;
      pkt.dst = nat.internalHost;
      pkt.dstPort = Number(nat.internalPort);
      logLine(`NAT applied: external ${nat.external} → ${pkt.dst}:${pkt.dstPort}`);
      // continue to rule matching with translated dst
    }
  }

  // Top-down rule matching (first match wins)
  for(let r of rules){
    if(ipMatch(r.src, pkt.src) && ipMatch(r.dst, pkt.dst) && protoMatch(r.proto, pkt.proto) && portMatch(r.port, pkt.dstPort)){
      return {action: r.action, ruleId: r.id, log: r.log};
    }
  }

  // default: DENY
  return {action:'DENY', ruleId:'(default)'};
}

/* ----------------- Packet Model & Animation ----------------- */
function createPacket({proto='TCP', src='203.0.113.5', dst='10.0.0.5', dstPort=80, threat='benign', payload='' }){
  const id = genId();
  const el = document.createElement('div');
  el.className = 'pkt' + (threat!=='benign' ? ' mal' : '');
  el.textContent = proto[0];
  el.style.top = `${18 + Math.random()*30}px`;
  el.style.left = '10px';
  el.dataset.id = id;
  fwFront.appendChild(el);

  const pkt = { id, el, proto, src, dst, dstPort, threat, payload, state:'in', created:Date.now() };
  packets.push(pkt);

  el.addEventListener('click', ()=>inspectPacket(pkt));
  return pkt;
}

function inspectPacket(pkt){
  const lines = [
    `Packet ${pkt.id}`,
    `proto: ${pkt.proto}`,
    `src: ${pkt.src}:${pkt.srcPort||'(ephemeral)'}`,
    `dst: ${pkt.dst}:${pkt.dstPort}`,
    `threat: ${pkt.threat}`,
    `payload: ${pkt.payload||'(none)'}`
  ];
  alert(lines.join('\n'));
}

/* animation step */
function stepSimulation(){
  // move each packet a bit to right; when reaching decision area, evaluate
  packets.forEach((p, idx) => {
    const el = p.el;
    const left = (parseFloat(el.style.left)||10) + (p.threat==='benign' ? 2.2 : 4.0);
    el.style.left = left + 'px';

    // decision point (near right side)
    const decisionX = fwFront.clientWidth - 240;
    if(left >= decisionX && p.state === 'in'){
      p.state = 'deciding';
      // clone a small object for evaluation (so NAT translation doesn't permanently mutate original except intentionally)
      const pktEval = { proto: p.proto, src: p.src, dst: p.dst, dstPort: p.dstPort, payload: p.payload };
      // IDS signature check — reject on signature
      const sigMatch = detectSignature(pktEval.payload);
      if(sigMatch){
        logLine(`IDS signature matched (${sigMatch}) — flagged as exploit`);
        p.threat = 'exploit';
        p.el.classList.add('mal');
      }

      const res = matchPacket(pktEval);
      if(res.action === 'ALLOW'){
        el.classList.add('pass');
        // Add connection entry for stateful simulation
        const flow = `${p.src}:${p.srcPort||12345}->${p.dst}:${p.dstPort}/${p.proto}`;
        conntable.unshift({flow, last: nowTs()});
        conntable = conntable.slice(0,80);
        renderConn();
        logLine(`ALLOW [${res.ruleId}] ${p.src}:${p.dstPort} -> ${p.dst}`);
      } else {
        el.classList.add('block');
        logLine(`BLOCK [${res.ruleId}] ${p.src}:${p.dstPort} -> ${p.dst}`);
      }

      // visual outcome then remove
      setTimeout(()=>{
        if(res.action === 'ALLOW'){
          el.style.left = (fwFront.clientWidth - 40) + 'px';
          setTimeout(()=>{ el.animate([{opacity:1},{opacity:0}],{duration:600}).onfinish = ()=>{ el.remove(); packets = packets.filter(x=>x.id!==p.id); }; }, 450);
        } else {
          el.animate([{transform:'translateY(0)'},{transform:'translateY(-18px) rotate(-8deg)'},{opacity:0}],{duration:700}).onfinish = ()=>{ el.remove(); packets = packets.filter(x=>x.id!==p.id); };
        }
      }, 380);
    }
  });

  // occasionally auto-generate benign traffic & malicious bursts
  // (handled in start loop)
  // refresh logs & conn
  renderLogs();
}

/* ----------------- IDS simple signature detection ----------------- */
function detectSignature(payload){
  if(!payload) return null;
  const pm = payload.toLowerCase();
  if(pm.includes('union select')) return 'SQLi - UNION SELECT';
  if(pm.includes('<script') || pm.includes('onerror')) return 'XSS - <script>';
  if(pm.includes('/bin/bash') || pm.includes('wget ')) return 'Shell / Remote Exec';
  return null;
}

/* ----------------- Controls & UI wiring ----------------- */
$('startBtn').onclick = start;
$('stopBtn').onclick = stop;
$('stepBtn').onclick = stepOnce;
$('autoMal').onchange = e => { autoMalicious = e.target.checked; logLine('Auto-malicious ' + (autoMalicious?'enabled':'disabled')); };
$('statefulToggle').onchange = e => { stateful = e.target.checked; logLine('Stateful ' + (stateful?'ON':'OFF')); renderConn(); };
$('natToggle').onchange = e => { natEnabled = e.target.checked; logLine('NAT ' + (natEnabled?'ON':'OFF')); renderConn(); };

// Add rule
$('addRule').onclick = ()=>{
  const src = $('ruleSrc').value.trim() || 'any';
  const dst = $('ruleDst').value.trim() || 'any';
  const proto = $('ruleProto').value.trim() || 'any';
  const port = $('rulePort').value.trim() || 'any';
  const action = $('ruleAction').value || 'DENY';
  const log = $('ruleLog').value === 'true';
  const r = {src,dst,proto,port,action,log,id:genId()};
  rules.unshift(r); // high priority inserted at top
  renderRules();
  logLine(`Rule added: ${src} → ${dst} ${proto}/${port} ${action} (log=${log})`);
  $('ruleSrc').value='';$('ruleDst').value='';$('ruleProto').value='';$('rulePort').value='';
};

// NAT add
$('addNat').onclick = ()=>{
  const ext = Number($('natExternal').value.trim());
  const internal = $('natInternal').value.trim();
  if(!ext || !internal || !internal.includes(':')) { alert('Enter valid external port and internal host:port (e.g. 8080 and 10.0.0.5:80)'); return; }
  const [host, port] = internal.split(':');
  natTable.unshift({external:ext, internalHost:host, internalPort:Number(port), id:genId()});
  renderNat(); logLine(`NAT mapping added: ${ext} → ${host}:${port}`);
  $('natExternal').value=''; $('natInternal').value='';
};

// Manual packet send
$('sendPkt').onclick = ()=>{
  const proto = $('protoSel').value || 'TCP';
  const src = $('srcIp').value.trim() || `198.51.100.${Math.floor(Math.random()*200)}`;
  const dst = $('dstIp').value.trim() || '10.0.0.5';
  const port = Number($('port').value) || 80;
  const threat = $('threatSelect').value;
  const payloadKey = $('payloadSignature').value || '';
  const payload = payloadKey === 'sql' ? '... UNION SELECT ...' : payloadKey === 'xss' ? '<script>alert(1)</script>' : payloadKey === 'shell' ? '/bin/bash -i' : '';
  createPacket({proto, src, dst, dstPort:port, threat, payload});
  logLine(`Manual packet: ${src} → ${dst}:${port} (${threat})`);
};

// Templates
$('tplHttp').onclick = ()=>{ createPacket({proto:'TCP', src:`198.51.100.${Math.floor(Math.random()*200)}`, dst:'10.0.0.5', dstPort:80, threat:'benign', payload:'GET / HTTP/1.1'}); };
$('tplScan').onclick = ()=>{ // spawn multiple quick scan packets
  const src = `203.0.113.${Math.floor(Math.random()*200)}`; for(let i=0;i<6;i++){ createPacket({proto:'TCP', src, dst:'10.0.0.5', dstPort: 20 + Math.floor(Math.random()*1000), threat:'scan'}); }
};
$('tplExploit').onclick = ()=>{ createPacket({proto:'TCP', src:`203.0.113.${Math.floor(Math.random()*200)}`, dst:'10.0.0.5', dstPort:8080, threat:'exploit', payload:'/bin/bash -i'}); logLine('Exploit template sent'); };

/* ----------------- Simulation loop controls ----------------- */
let ticker = null;
function start(){
  if(running) return;
  running = true;
  ticker = setInterval(() => {
    // animate step
    stepSimulation();

    // auto spawn benign traffic
    if(Math.random() < 0.28) createPacket({proto: Math.random()<0.6?'TCP':'UDP', src:`198.51.100.${Math.floor(Math.random()*200)}`, dst:'10.0.0.5', dstPort: [22,80,443,8080][Math.floor(Math.random()*4)], threat:'benign' });
    // auto malicious burst
    if(autoMalicious && Math.random() < 0.25){
      if(Math.random() < 0.5) {
        // scan
        const src = `203.0.113.${Math.floor(Math.random()*220)}`;
        const port = 20 + Math.floor(Math.random()*2000);
        createPacket({proto:'TCP', src, dst:'10.0.0.5', dstPort: port, threat:'scan'});
      } else {
        // exploit/payload
        createPacket({proto:'TCP', src:`203.0.113.${Math.floor(Math.random()*220)}`, dst:'10.0.0.5', dstPort: 8080, threat:'exploit', payload:'/bin/bash -i'});
      }
    }

  }, 140);
  logLine('Simulation started');
}
function stop(){
  running = false;
  clearInterval(ticker);
  ticker = null;
  logLine('Simulation stopped');
}
function stepOnce(){
  createPacket({proto:'TCP', src:`198.51.100.${Math.floor(Math.random()*200)}`, dst:'10.0.0.5', dstPort: 80, threat:'benign'});
  stepSimulation();
  logLine('Single step');
}

/* ----------------- Export / Import ----------------- */
$('exportBtn').onclick = ()=>{
  const data = { rules, natTable };
  const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'fw-config.json'; a.click();
  URL.revokeObjectURL(url);
  logLine('Exported rules & NAT table');
};
$('importBtn').onclick = ()=> $('importFile').click();
$('importFile').onchange = (e)=>{
  const f = e.target.files[0]; if(!f) return;
  const reader = new FileReader();
  reader.onload = ev => {
    try{
      const data = JSON.parse(ev.target.result);
      if(data.rules) rules = data.rules.map(r=>({...r, id: genId()}));
      if(data.natTable) natTable = data.natTable.map(n=>({...n, id: genId()}));
      renderRules(); renderNat();
      logLine('Imported configuration');
    }catch(err){ alert('Invalid JSON'); }
  };
  reader.readAsText(f);
};

/* ----------------- Initial render & cleanup ----------------- */
renderRules();
renderNat();
renderLogs();
renderConn();

/* ----------------- Periodic cleanup of connection table (old entries) ----------------- */
setInterval(()=>{
  // remove entries older than 60s (educational)
  // conntable has strings for last timestamp; we simply keep a rolling list length for demo
  conntable = conntable.slice(0,80);
  renderConn();
}, 5000);

/* ----------------- Final notes ----------------- */
// This is intentionally client-side only for education — it simulates behavior and decisions of a firewall.
// Extensions you may add later:
// - CIDR / IP range matching
// - Deep packet inspection rules with regex
// - Stateful timeout values & explicit FIN/close simulation
// - Visual legend for where NAT applied (external → internal)
// - Save/load presets and README for Github demo

// End of script
