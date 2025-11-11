const screen = document.getElementById('screen');

let rules = [
  {id:1, action:'DENY', proto:'TCP', src:'any', dst:'10.0.0.5', port:'22'},
  {id:2, action:'ALLOW', proto:'any', src:'any', dst:'10.0.0.5', port:'any'}
];
let logs = [];
let running = false;
let timer;

// print line with typing animation
function print(line) {
  const el = document.createElement('div');
  screen.appendChild(el);
  let i = 0;
  const intv = setInterval(()=>{
    el.textContent = line.slice(0, i++);
    if(i > line.length) clearInterval(intv);
    screen.scrollTop = screen.scrollHeight;
  }, 10);
}

// simulate packet passing firewall
function simulatePacket() {
  const pkt = {
    src: `192.168.${Math.floor(Math.random()*100)}.${Math.floor(Math.random()*100)}`,
    dst: '10.0.0.5',
    proto: Math.random() > 0.5 ? 'TCP' : 'UDP',
    port: [22,80,443,8080][Math.floor(Math.random()*4)]
  };

  // rule match
  let action = 'DENY';
  for (const r of rules) {
    if ((r.proto==='any'||r.proto===pkt.proto) &&
        (r.src==='any'||r.src===pkt.src) &&
        (r.dst==='any'||r.dst===pkt.dst) &&
        (r.port==='any'||Number(r.port)===pkt.port)) {
      action = r.action;
      break;
    }
  }

  const msg = `${action} ${pkt.proto} ${pkt.src} → ${pkt.dst}:${pkt.port}`;
  logs.push(msg);
  print(msg);
}

document.getElementById('btnStart').onclick = ()=>{
  if(running) return;
  running = true;
  print('Firewall simulation started.');
  timer = setInterval(simulatePacket, 1000);
};
document.getElementById('btnStop').onclick = ()=>{
  clearInterval(timer);
  running = false;
  print('Simulation stopped.');
};
document.getElementById('btnStep').onclick = simulatePacket;
document.getElementById('btnShowRules').onclick = ()=>{
  print('--- Rules ---');
  rules.forEach(r=>print(`${r.id}. ${r.action} ${r.proto} ${r.src} -> ${r.dst}:${r.port}`));
};
document.getElementById('btnAddRule').onclick = ()=>{
  const id = rules.length+1;
  rules.push({id, action:'ALLOW', proto:'TCP', src:'any', dst:'any', port:'any'});
  print(`Rule ${id} added.`);
};
document.getElementById('btnShowLogs').onclick = ()=>{
  print('--- Logs ---');
  logs.slice(-10).forEach(l=>print(l));
};
document.getElementById('btnClearLogs').onclick = ()=>{ logs=[]; print('Logs cleared.'); };
document.getElementById('btnSimPkt').onclick = simulatePacket;
document.getElementById('formAddRule').onclick = ()=>{
  const id = rules.length+1;
  const action = document.getElementById('fAction').value;
  const proto = document.getElementById('fProto').value || 'any';
  const src = document.getElementById('fSrc').value || 'any';
  const dst = document.getElementById('fDst').value || 'any';
  const port = document.getElementById('fPort').value || 'any';
  rules.push({id, action, proto, src, dst, port});
  print(`Custom rule ${id} added.`);
};
document.getElementById('btnClear').onclick = ()=>screen.innerHTML='';
print('Firewall Simulator loaded ✅');
