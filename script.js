/* Firewall CLI Simulator
   Interactive terminal-style simulator.
   Commands: help, show rules, add rule, del rule, move rule, set stateful on/off,
             set nat on/off, add nat, del nat, show nat, simulate pkt, show logs,
             clear logs, show conn, export, import (paste JSON), status, clear.
*/

/* ---------- Utilities ---------- */
const $ = id => document.getElementById(id);
const screen = $('screen');
const input = $('cmdInput');
let history = [], histPos = -1;

function nowTs(){ return new Date().toLocaleTimeString(); }
function writeln(text, cls='line'){ const el = document.createElement('div'); el.className = cls; el.textContent = text; screen.appendChild(el); screen.scrollTop = screen.scrollHeight; }
function writeHTML(html){ const el = document.createElement('div'); el.className='line'; el.innerHTML = html; screen.appendChild(el); screen.scrollTop = screen.scrollHeight; }
function banner(){
  writeHTML(`<span class="out">Firewall CLI Simulator — by Karndeep Baror</span> <span class="badge">demo</span>`);
  writeln(`Type 'help' for commands. Example: add rule allow tcp any 10.0.0.5 80 log`, 'line');
}
function clearScreen(){ screen.innerHTML=''; }

/* ---------- Simulator State ---------- */
let rules = [
  {id: idGen(), action:'DENY', proto:'TCP', src:'any', dst:'10.0.0.5', port:'22', log:true},
  {id: idGen(), action:'ALLOW', proto:'any', src:'any', dst:'10.0.0.5', port:'any', log:false}
];
let natTable = []; // {id, external, internalHost, internalPort}
let connTable = []; // {flow,last}
let logs = []; // newest first
let stateful = true;
let natEnabled = true;

/* ---------- ID / Helpers ---------- */
function idGen(){ return Math.random().toString(36).slice(2,9); }
function pushLog(msg){ logs.unshift(`[${nowTs()}] ${msg}`); if(logs.length>400) logs.pop(); }
function showLogs(n=40){ if(!logs.length) writeln('(no logs)'); else logs.slice(0,n).forEach(l=>writeln(l)); }

/* ---------- Rule matching ---------- */
function ipMatch(ruleIp, ip){
  if(!ruleIp || ruleIp.toLowerCase()==='any') return true;
  return ruleIp === ip;
}
function protoMatch(ruleProto, proto){
  if(!ruleProto || ruleProto.toLowerCase()==='any') return true;
  return ruleProto.toLowerCase() === proto.toLowerCase();
}
function portMatch(rulePort, p){
  if(!rulePort || rulePort.toLowerCase()==='any') return true;
  if(rulePort.includes('-')){
    const [a,b] = rulePort.split('-').map(Number); return p>=a && p<=b;
  }
  if(rulePort.includes(',')){ return rulePort.split(',').map(x=>Number(x.trim())).includes(Number(p)); }
  return Number(rulePort) === Number(p);
}

function matchPacket(pkt){
  // stateful check
  if(stateful){
    const flow = `${pkt.src}:${pkt.srcPort||'(ephemeral)'}->${pkt.dst}:${pkt.dstPort}/${pkt.proto}`;
    const rev = `${pkt.dst}:${pkt.dstPort}->${pkt.src}:${pkt.srcPort||'(ephemeral)'}/${pkt.proto}`;
    if(connTable.find(c=>c.flow===flow || c.flow===rev)){
      return {action:'ALLOW', ruleId:'(stateful)'};
    }
  }
  // NAT translation
  if(natEnabled){
    const nat = natTable.find(n=>Number(n.external) === Number(pkt.dstPort));
    if(nat){
      pkt._origDst = pkt.dst; pkt._origDstPort = pkt.dstPort;
      pkt.dst = nat.internalHost; pkt.dstPort = Number(nat.internalPort);
      pushLog(`NAT applied: external ${nat.external} → ${pkt.dst}:${pkt.dstPort}`);
    }
  }
  for(let r of rules){
    if(ipMatch(r.src, pkt.src) && ipMatch(r.dst, pkt.dst) && protoMatch(r.proto, pkt.proto) && portMatch(r.port, pkt.dstPort)){
      return {action: r.action, ruleId: r.id, log: r.log};
    }
  }
  return {action:'DENY', ruleId:'(default)'};
}

/* ---------- Packet simulation (no heavy animation in CLI) ---------- */
function simulatePacketCommand(parts){
  // syntax: simulate pkt tcp 203.0.113.5 10.0.0.5 80 [payload]
  if(parts.length < 6){ writeln('Usage: simulate pkt <proto> <src> <dst> <port> [payload]'); return; }
  const proto = parts[2].toUpperCase();
  const src = parts[3];
  const dst = parts[4];
  const dstPort = Number(parts[5]);
  const payload = parts.slice(6).join(' ') || '';
  writeln(`→ Simulating packet: ${proto} ${src}:${'(ephemeral)'} -> ${dst}:${dstPort}`, 'line');
  const pkt = {proto, src, dst, dstPort, payload};
  // simple IDS signature detection
  if(payload.toLowerCase().includes('union select')){ writeln('! IDS: SQLi signature detected (UNION SELECT)', 'line'); pkt._sig='sqli'; }
  if(payload.toLowerCase().includes('<script')){ writeln('! IDS: XSS signature detected', 'line'); pkt._sig='xss'; }
  // match
  const res = matchPacket(pkt);
  if(res.action === 'ALLOW'){
    writeln(`> MATCH: ALLOW (rule: ${res.ruleId})`, 'line');
    pushLog(`ALLOWED ${proto} ${src}:${dstPort} -> ${dst} (rule:${res.ruleId})`);
    // add to conn table if stateful
    if(stateful){
      const flow = `${src}:*->${dst}:${dstPort}/${proto}`;
      connTable.unshift({flow, last: nowTs()});
      connTable = connTable.slice(0,100);
    }
  } else {
    writeln(`> MATCH: DENY (rule: ${res.ruleId})`, 'line');
    pushLog(`BLOCKED ${proto} ${src}:${dstPort} -> ${dst} (rule:${res.ruleId})`);
  }
}

/* ---------- CLI commands ---------- */
function help(){
  writeHTML(`<span class="out">Available commands:</span>`);
  writeln(`help                      — show this`);
  writeln(`clear                     — clear screen`);
  writeln(`show rules                — list firewall rules (top→down)`);
  writeln(`add rule <allow|deny> <proto|any> <src> <dst> <port|any> [log]`);
  writeln(`    e.g. add rule allow tcp any 10.0.0.5 80 log`);
  writeln(`del rule <rule-id>        — remove rule by id`);
  writeln(`move rule <id> up|down    — change priority`);
  writeln(`show nat                  — list NAT/port-forward entries`);
  writeln(`add nat <external> <host:port>   — example: add nat 8080 10.0.0.5:80`);
  writeln(`del nat <nat-id>`);
  writeln(`set stateful on|off       — toggle stateful tracking`);
  writeln(`set nat on|off            — toggle NAT handling`);
  writeln(`simulate pkt ...          — simulate one packet (see syntax below)`);
  writeln(`    simulate pkt tcp 203.0.113.5 10.0.0.5 80`);
  writeln(`show conn                 — show stateful connection table`);
  writeln(`show logs                 — show recent logs`);
  writeln(`clear logs                — clear logs`);
  writeln(`export config             — download JSON of rules & nat`);
  writeln(`import config             — paste JSON to import (cmd will prompt)`);
  writeln(`status                    — show firewall status (stateful/nat/rule-count)`);
}

/* ---------- Command processor ---------- */
function processCommand(line){
  if(!line.trim()) return;
  writeln(`fw-sim> ${line}`, 'line'); // echo
  const parts = line.trim().split(/\s+/);
  const cmd = parts[0].toLowerCase();

  try {
    if(cmd === 'help') help();
    else if(cmd === 'clear'){ clearScreen(); banner(); }
    else if(cmd === 'show'){
      const sub = parts[1];
      if(sub === 'rules'){
        if(!rules.length) writeln('(no rules)');
        rules.forEach((r,i)=> writeln(`${i+1}. [${r.id}] ${r.action} ${r.proto} ${r.src} -> ${r.dst}:${r.port} ${r.log? ' (log)':''}`));
      } else if(sub === 'logs'){ showLogs(); }
      else if(sub === 'conn'){ renderConnCLI(); }
      else if(sub === 'nat'){ if(!natTable.length) writeln('(no nat entries)'); natTable.forEach(n=>writeln(`[${n.id}] ${n.external} → ${n.internalHost}:${n.internalPort}`)); }
      else if(sub === 'conn' || sub === 'connection') renderConnCLI();
      else writeln('unknown show target');
    }
    else if(cmd === 'add'){
      if(parts[1] === 'rule'){
        // add rule allow tcp any 10.0.0.5 80 log
        const action = parts[2] ? parts[2].toUpperCase() : null;
        const proto = parts[3] || 'any';
        const src = parts[4] || 'any';
        const dst = parts[5] || 'any';
        const port = parts[6] || 'any';
        const log = (parts[7] && parts[7].toLowerCase()==='log') ? true : false;
        if(!action || !['ALLOW','DENY'].includes(action)){ writeln('invalid action — use allow or deny'); return; }
        const r = {id: idGen(), action, proto: proto.toUpperCase(), src, dst, port, log};
        rules.unshift(r); writeln(`Rule added: [${r.id}] ${r.action} ${r.proto} ${r.src}->${r.dst}:${r.port}`); pushLog(`Rule add ${r.id}`);
      } else if(parts[1] === 'nat'){
        // add nat 8080 10.0.0.5:80
        const ext = Number(parts[2]);
        const internal = parts[3];
        if(!ext || !internal || !internal.includes(':')){ writeln('Usage: add nat <external> <host:port>'); return; }
        const [host, port] = internal.split(':');
        const n = {id: idGen(), external: ext, internalHost: host, internalPort: Number(port)};
        natTable.unshift(n);
        writeln(`NAT mapping added: ${n.external} → ${n.internalHost}:${n.internalPort} (id:${n.id})`);
        pushLog(`NAT add ${n.id}`);
      } else writeln('invalid add target');
    }
    else if(cmd === 'del'){
      if(parts[1] === 'rule'){
        const id = parts[2];
        const idx = rules.findIndex(r=>r.id===id);
        if(idx===-1) writeln('rule id not found'); else { rules.splice(idx,1); writeln(`Rule ${id} removed`); pushLog(`Rule del ${id}`); }
      } else if(parts[1] === 'nat'){
        const id = parts[2];
        const idx = natTable.findIndex(n=>n.id===id);
        if(idx===-1) writeln('nat id not found'); else { natTable.splice(idx,1); writeln(`NAT ${id} removed`); pushLog(`NAT del ${id}`); }
      } else writeln('invalid del target');
    }
    else if(cmd === 'move' && parts[1]==='rule'){
      const id = parts[2], dir = parts[3];
      const i = rules.findIndex(r=>r.id===id); if(i===-1){ writeln('rule not found'); return; }
      if(dir === 'up' && i>0){ const r = rules.splice(i,1)[0]; rules.splice(i-1,0,r); writeln(`Rule ${id} moved up`); }
      else if(dir === 'down' && i < rules.length-1){ const r = rules.splice(i,1)[0]; rules.splice(i+1,0,r); writeln(`Rule ${id} moved down`); }
      else writeln('cannot move');
    }
    else if(cmd === 'set'){
      if(parts[1] === 'stateful'){ stateful = (parts[2]==='on' || parts[2]==='true'); writeln(`stateful = ${stateful}`); pushLog(`stateful set ${stateful}`); }
      else if(parts[1] === 'nat'){ natEnabled = (parts[2]==='on' || parts[2]==='true'); writeln(`natEnabled = ${natEnabled}`); pushLog(`nat set ${natEnabled}`); }
      else writeln('unknown set');
    }
    else if(cmd === 'simulate' && parts[1] === 'pkt'){ simulatePacketCommand(parts); }
    else if(cmd === 'show' && parts[1] === 'status'){
      writeln(`stateful: ${stateful} | nat: ${natEnabled} | rules: ${rules.length} | nat entries: ${natTable.length}`);
    }
    else if(cmd === 'status'){ writeln(`stateful: ${stateful} | nat: ${natEnabled} | rules: ${rules.length} | nat entries: ${natTable.length}`); }
    else if(cmd === 'show' && parts[1] === 'conn'){ renderConnCLI(); }
    else if(cmd === 'show' && parts[1] === 'logs'){ showLogs(); }
    else if(cmd === 'clear' && parts[1] === 'logs'){ logs = []; writeln('logs cleared'); }
    else if(cmd === 'clear' && parts[1] !== 'logs'){ clearScreen(); banner(); }
    else if(cmd === 'export' && parts[1] === 'config'){
      const data = {rules, natTable};
      const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
      const url = URL.createObjectURL(blob);
      writeHTML(`Exported config → <a href="${url}" download="fw-config.json" style="color:var(--accent)">download</a>`);
      pushLog('Config exported');
    }
    else if(cmd === 'import' && parts[1] === 'config'){
      writeln('Paste JSON now (single line), then press Enter:');
      // listen once
      input.onkeydown = function(ev){
        if(ev.key === 'Enter'){
          ev.preventDefault();
          const text = input.value.trim(); input.value=''; input.onkeydown = inputKeyHandler;
          try{
            const d = JSON.parse(text);
            if(Array.isArray(d.rules)) rules = d.rules.map(r=>({...r, id: idGen()}));
            if(Array.isArray(d.natTable)) natTable = d.natTable.map(n=>({...n, id: idGen()}));
            writeln('Import successful'); pushLog('Config imported');
            renderRulesCLI();
          }catch(e){ writeln('Invalid JSON'); }
        } else if(ev.key === 'Escape'){ input.onkeydown = inputKeyHandler; writeln('Import cancelled'); input.value=''; }
      };
    }
    else if(cmd === 'show' && parts[1] === 'rules'){ renderRulesCLI(); }
    else if(cmd === 'help' || cmd === '?'){ help(); }
    else if(cmd === 'show' && parts[1] === 'nat'){ if(!natTable.length) writeln('(no nat)'); natTable.forEach(n=>writeln(`[${n.id}] ${n.external} -> ${n.internalHost}:${n.internalPort}`)); }
    else if(cmd === 'show' && parts[1] === 'logs'){ showLogs(); }
    else if(cmd === 'quit' || cmd === 'exit'){ writeln('Exiting simulator — page reload to restart'); input.disabled=true; }
    else { writeln('unknown command. Type help'); }
  } catch (err) {
    writeln('error: ' + (err.message || err), 'line err');
  }
}

/* ---------- Render helpers for CLI ---------- */
function renderRulesCLI(){
  if(!rules.length) { writeln('(no rules)'); return; }
  rules.forEach((r, idx)=> writeln(`${idx+1}. [${r.id}] ${r.action} ${r.proto} ${r.src} -> ${r.dst}:${r.port} ${r.log? '(log)':''}`));
}
function renderConnCLI(){
  if(!connTable.length) { writeln('(no connections)'); return; }
  connTable.forEach(c=> writeln(`${c.flow} • ${c.last}`));
}

/* ---------- Input handling & history ---------- */
function inputKeyHandler(e){
  if(e.key === 'Enter'){
    const line = input.value;
    if(line.trim()){
      history.unshift(line);
      histPos = -1;
      processCommand(line);
    }
    input.value = '';
  } else if(e.key === 'ArrowUp'){
    if(history.length && histPos < history.length-1){ histPos++; input.value = history[histPos]; setTimeout(()=>input.setSelectionRange(input.value.length,input.value.length),0); }
    e.preventDefault();
  } else if(e.key === 'ArrowDown'){
    if(histPos > 0){ histPos--; input.value = history[histPos]; } else { histPos = -1; input.value=''; }
    e.preventDefault();
  } else if(e.key === 'Tab'){
    e.preventDefault();
    // basic suggestions: if starts with 'add' suggest 'add rule', 'add nat'
    const val = input.value.trim();
    if(val === 'add') input.value = 'add rule ';
  }
}
input.addEventListener('keydown', inputKeyHandler);

/* ---------- Initial display ---------- */
banner();
writeln('Type "help" to begin', 'line');
input.focus();

/* ---------- Expose rerender function for CLI actions ---------- */
function renderRules(){ renderRulesCLI(); }
function renderNat(){ natTable.forEach(n=> writeln(`[${n.id}] ${n.external} -> ${n.internalHost}:${n.internalPort}`)); }

/* ---------- End ---------- */
