async function send() {
  const user_id = document.getElementById('userId').value;
  const session_id = document.getElementById('sessionId').value;
  const language = document.getElementById('lang').value;
  const message = document.getElementById('msg').value;
  document.getElementById('msg').value = "";

  const res = await fetch('/chat', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({user_id, session_id, language, message})
  });
  const j = await res.json();
  log(`[user] ${message}\n[assistant] ${j.answer}\n`);
}

async function epoch() {
  const user_id = document.getElementById('userId').value;
  const session_id = document.getElementById('sessionId').value;
  const res = await fetch('/epoch', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({user_id, session_id})
  });
  const j = await res.json();
  log(`[epoch] block_hash=${j.epoch_block.block_hash}`);
}

function log(t){ const el=document.getElementById('log'); el.textContent+=t+"\n"; el.scrollTop=el.scrollHeight; }
