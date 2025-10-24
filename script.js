// script.js
// Client-side simulated detection demo — safe for presentations.
// NOTE: This simulation does NOT analyze or execute real malware.

(() => {
  // elements
  const fileInput = document.getElementById('fileInput');
  const dropZone = document.getElementById('dropZone');
  const scanBtn = document.getElementById('scanBtn');
  const resetBtn = document.getElementById('resetBtn');
  const scanArea = document.getElementById('scanArea');
  const fileNameEl = document.getElementById('fileName');
  const fileMetaEl = document.getElementById('fileMeta');
  const scanProgress = document.getElementById('scanProgress');
  const scanStatus = document.getElementById('scanStatus');
  const resultPanel = document.getElementById('resultPanel');
  const threatNameEl = document.getElementById('threatName');
  const threatScoreEl = document.getElementById('threatScore');
  const reasonsList = document.getElementById('reasonsList');
  const sha256Sim = document.getElementById('sha256Sim');
  const suggestionsEl = document.getElementById('suggestions');
  const badgeWrap = document.getElementById('badgeWrap');

  const chatWindow = document.getElementById('chatWindow');
  const chatInput = document.getElementById('chatInput');
  const sendBtn = document.getElementById('sendBtn');
  const attachBtn = document.getElementById('attachBtn');

  let lastScan = null;

  // simulated malware names
  const MALWARE_LIST = [
    "Trojan.Generic.AI",
    "Worm.Agent.X",
    "Ransom.Win32.Locky",
    "Backdoor.Stealther",
    "Dropper.Packed.Z",
    "Spyware.DataExfil",
    "Loader.EvasiveV2",
    "Adware.UnwantedV",
    "PUP.SuspiciousInstaller"
  ];

  // legit suggestions mapping (simple)
  const LEGIT_MAP = {
    "photoshop":"https://www.adobe.com/products/photoshop.html",
    "photoshop_crack":"https://www.adobe.com/products/photoshop.html",
    "office":"https://www.office.com/",
    "msword":"https://www.office.com/",
    "winrar":"https://www.rarlab.com/",
    "steam":"https://store.steampowered.com/",
    "vlc":"https://www.videolan.org/vlc/",
    "zoom":"https://zoom.us/",
    "chrome":"https://www.google.com/chrome/",
    "firefox":"https://www.mozilla.org/firefox/",
    "android":"https://play.google.com/store"
  };

  // helpers
  function humanSize(n){
    if (n < 1024) return n + " B";
    if (n < 1024*1024) return (n/1024).toFixed(1) + " KB";
    if (n < 1024*1024*1024) return (n/(1024*1024)).toFixed(1) + " MB";
    return (n/(1024*1024*1024)).toFixed(1) + " GB";
  }

  function simpleSHA256Sim(name, size){
    // deterministic-ish pseudo-hash for demo
    let s = name + '|' + size + '|' + new Date().getTime();
    let h = 0;
    for (let i=0;i<s.length;i++){ h = (h<<5)-h + s.charCodeAt(i); h |= 0; }
    return ('00000000'+(h>>>0).toString(16)).slice(-8).repeat(8);
  }

  function pickRandom(arr){ return arr[Math.floor(Math.random()*arr.length)]; }

  function detectKeywords(name){
    name = name.toLowerCase();
    let found = [];
    for (const k of Object.keys(LEGIT_MAP)){
      if (name.includes(k)) found.push({keyword: k, url: LEGIT_MAP[k]});
    }
    if (found.length === 0){
      found.push({keyword: "official vendor", url: "https://www.google.com/search?q=official+software+download"});
      found.push({keyword: "trusted app store", url: "https://www.microsoft.com/store"});
    }
    return found;
  }

  // UI functions
  function showFileMeta(file){
    scanArea.style.display = 'block';
    fileNameEl.textContent = file.name;
    fileMetaEl.textContent = `${file.type || 'Unknown type'} • ${humanSize(file.size)}`;
    badgeWrap.innerHTML = `<span class="badge bg-secondary">Ready</span>`;
    resultPanel.style.display = 'none';
    scanProgress.style.width = '0%';
    scanStatus.textContent = 'Ready to scan';
  }

  function startScanSimulation(file){
    badgeWrap.innerHTML = `<span class="badge bg-warning text-dark">Scanning</span>`;
    scanStatus.textContent = 'Scanning…';
    let pct = 0;
    scanProgress.style.width = '0%';
    resultPanel.style.display = 'none';
    reasonsList.innerHTML = '';
    threatNameEl.textContent = '—';
    threatScoreEl.textContent = '—';
    sha256Sim.textContent = '—';
    // step simulation
    const interval = setInterval(() => {
      pct += Math.floor(Math.random()*18) + 6; // random increments
      if (pct >= 100) pct = 100;
      scanProgress.style.width = pct + '%';
      scanStatus.textContent = `Analyzing (${pct}%)`;
      if (pct === 100){
        clearInterval(interval);
        // finalize simulated detection
        const name = file.name.toLowerCase();
        // heuristic-ish logic to decide safe vs malicious (simulated)
        let scoreBase = Math.min(90, Math.floor((file.size % 100) / 1.2)); // just to vary
        // bump score if filename contains cracks/cheap keywords
        const suspiciousKeywords = ['crack','keygen','patch','serial','warez','pirate','cracked','torrent'];
        for (const kw of suspiciousKeywords){ if (name.includes(kw)) scoreBase += 35; }
        // bump for exe/apk/msi
        const ext = name.split('.').pop();
        if (['exe','dll','msi','apk','jar'].includes(ext)) scoreBase += 12;
        // random noise
        scoreBase += Math.floor(Math.random()*18)-8;
        const finalScore = Math.max(2, Math.min(99, scoreBase));

        // decide label if high
        let detected = finalScore >= 65;
        let threatName = detected ? pickRandom(MALWARE_LIST) : 'No known threats (simulated)';
        // if filename contains specific product, mock map detection label
        if (name.includes('ransom')) { threatName = 'Ransom.Win32.Simulated'; detected = true; }

        // reasons
        let reasons = [];
        if (finalScore >= 80) reasons.push('Very high heuristic risk (simulated).');
        if (name.match(/crack|keygen|patch|serial/)) reasons.push('Filename suggests pirated/cracked distribution.');
        if (ext === 'exe' || ext === 'apk' || ext === 'msi') reasons.push('Executable file type.');
        if (file.size > 5*1024*1024) reasons.push('Large file size (unusual for installers).');
        if (reasons.length === 0) reasons.push('No obvious heuristic flags — treat as likely safe (simulated).');

        // fill results
        threatNameEl.textContent = threatName + (detected ? '' : '');
        threatScoreEl.textContent = finalScore + '%';
        sha256Sim.textContent = simpleSHA256Sim(file.name, file.size);
        reasonsList.innerHTML = reasons.map(r => `<li>${r}</li>`).join('');
        suggestionsEl.innerHTML = detectKeywords(file.name).map(s => `<div><a href="${s.url}" target="_blank">${s.keyword} — ${s.url}</a></div>`).join('');

        // update UI
        resultPanel.style.display = 'block';
        scanStatus.textContent = detected ? 'Threat detected (simulated)' : 'No known threat found (simulated)';
        badgeWrap.innerHTML = detected ? `<span class="badge bg-danger">High Risk</span>` : `<span class="badge bg-success">Likely Safe</span>`;

        // save lastScan
        lastScan = {
          filename: file.name,
          size: file.size,
          humanSize: humanSize(file.size),
          sha256: simpleSHA256Sim(file.name, file.size),
          score: finalScore,
          threat: threatName,
          reasons
        };
      }
    }, 500);
  }

  // drag & drop
  dropZone.addEventListener('dragover', (e)=>{
    e.preventDefault();
    dropZone.classList.add('dragover');
  });
  dropZone.addEventListener('dragleave', (e)=>{
    dropZone.classList.remove('dragover');
  });
  dropZone.addEventListener('drop', (e)=>{
    e.preventDefault();
    dropZone.classList.remove('dragover');
    const f = e.dataTransfer.files[0];
    if (f) { fileInput.files = e.dataTransfer.files; showFileMeta(f); }
  });

  fileInput.addEventListener('change', (e)=>{
    const f = e.target.files[0];
    if (f) showFileMeta(f);
  });

  scanBtn.addEventListener('click', ()=>{
    const f = fileInput.files[0];
    if (!f){
      alert('Please choose a file first (demo).');
      return;
    }
    startScanSimulation(f);
  });

  resetBtn.addEventListener('click', ()=>{
    fileInput.value = "";
    scanArea.style.display = 'none';
    resultPanel.style.display = 'none';
    scanProgress.style.width = '0%';
    scanStatus.textContent = 'Ready to scan';
    badgeWrap.innerHTML = `<span class="badge bg-secondary">Ready</span>`;
    suggestionsEl.innerHTML = '';
    lastScan = null;
    chatWindow.innerHTML = '<div class="text-muted small text-center mb-2">Assistant ready. Click “Attach last scan” to include scan context.</div>';
  });

  // Chat logic (simulated AI)
  function appendChat(sender, text){
    const div = document.createElement('div');
    div.className = sender === 'user' ? 'user mb-2' : 'assistant mb-2';
    div.innerHTML = `<div class="bubble ${sender}">${text}</div>`;
    chatWindow.appendChild(div);
    chatWindow.scrollTop = chatWindow.scrollHeight;
  }

  sendBtn.addEventListener('click', ()=>{
    const q = chatInput.value.trim();
    if (!q) return;
    appendChat('user', q);
    chatInput.value = '';
    // simulate typing
    appendChat('assistant', '…'); // temporary
    setTimeout(()=> {
      // generate a simulated answer
      const ans = generateChatAnswer(q);
      // replace last assistant bubble
      const bubbles = chatWindow.querySelectorAll('.assistant');
      if (bubbles.length > 0) bubbles[bubbles.length-1].innerHTML = `<div class="bubble assistant">${ans}</div>`;
      chatWindow.scrollTop = chatWindow.scrollHeight;
    }, 900 + Math.random()*700);
  });

  attachBtn.addEventListener('click', ()=>{
    if (!lastScan){
      alert('No scan available to attach. Run a simulated scan first.');
      return;
    }
    chatInput.value = `Attached scan: ${lastScan.filename} (score ${lastScan.score}%). Please advise.`;
  });

  function generateChatAnswer(q){
    const low = q.toLowerCase();
    if (low.includes('remove') || low.includes('remove virus') || low.includes('how to remove')){
      return "This is a simulated demo. For real threats: isolate the device, disconnect from network, use a reputable AV/EDR product, and follow vendor removal steps. Avoid running suspicious files.";
    }
    if (low.includes('safe') || low.includes('is this file safe')){
      return lastScan ? `Based on the simulated score (${lastScan.score}%), the file is ${lastScan.score >= 65 ? 'likely risky (simulated)' : 'likely safe (simulated)'} — treat as demo output only.` : "No scan attached. Run a scan and attach it for context.";
    }
    if (low.includes('where') && low.includes('download')){
      // extract product name roughly
      const words = q.split(/\s+/);
      for (const w of words){
        const key = w.toLowerCase().replace(/[^\w]/g,'');
        if (LEGIT_MAP[key]) return `Use official source: ${LEGIT_MAP[key]}`;
      }
      return "Search the official vendor site or trusted stores (e.g., vendor website, Microsoft Store, Google Play). Avoid pirated downloads.";
    }
    return "This assistant is simulated. For serious cases, consult a cybersecurity professional. You can attach a scan for context.";
  }

  // theme toggle
  document.getElementById('themeToggle').addEventListener('click', ()=>{
    document.body.classList.toggle('light-theme');
    // simple icon swap
    const btn = document.getElementById('themeToggle');
    btn.innerHTML = document.body.classList.contains('light-theme') ? '<i class=\"fa fa-moon me-1\"></i> Theme' : '<i class=\"fa fa-sun me-1\"></i> Theme';
  });

})();
