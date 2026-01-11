const statusEl = document.getElementById('status');
const sendBtn = document.getElementById('sendBtn');
const epochBtn = document.getElementById('epochBtn');
const latestBtn = document.getElementById('latestBtn');
const txBtn = document.getElementById('txBtn');
const addressBtn = document.getElementById('addressBtn');

const logContainer = document.getElementById('log');
const msgInput = document.getElementById('msg');
const txHashInput = document.getElementById('txHash');
const addressInput = document.getElementById('address');

function setStatus(message, type) {
  statusEl.textContent = message || '';
  statusEl.className = 'status' + (type ? ` status--${type}` : '');
}

function toggleActions(disabled) {
  sendBtn.disabled = disabled;
  epochBtn.disabled = disabled;
  latestBtn.disabled = disabled;
  txBtn.disabled = disabled;
  addressBtn.disabled = disabled;
}

function appendLog(role, text) {
  const entry = document.createElement('div');
  entry.className = 'log-entry';

  const label = document.createElement('div');
  label.className = 'log-label';
  label.textContent = role;

  const bubble = document.createElement('div');
  bubble.className = `bubble ${role.toLowerCase()}`;
  bubble.textContent = text;

  entry.append(label, bubble);
  logContainer.append(entry);

  logContainer.parentElement.scrollTop =
    logContainer.parentElement.scrollHeight;
}

function formatJSON(payload) {
  return JSON.stringify(payload, null, 2);
}

function getFormValues() {
  return {
    user_id: document.getElementById('userId').value,
    session_id: document.getElementById('sessionId').value,
    language: document.getElementById('lang').value,
  };
}

async function send() {
  const message = msgInput.value.trim();
  if (!message) {
    return setStatus('Enter a prompt first.', 'error');
  }

  const payload = { ...getFormValues(), message };
  msgInput.value = '';

  toggleActions(true);
  setStatus('Sending message...', 'progress');

  try {
    appendLog('User', message);

    const res = await fetch('/chainchat/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      throw new Error(`Request failed (${res.status})`);
    }

    const j = await res.json();
    appendLog('Assistant', j.answer);

    setStatus('Response received', 'success');
  } catch (err) {
    console.error(err);
    setStatus(err.message || 'Unable to send message', 'error');
  } finally {
    toggleActions(false);
  }
}

async function epoch() {
  const payload = getFormValues();

  toggleActions(true);
  setStatus('Fetching epoch summary...', 'progress');

  try {
    const res = await fetch('/chainchat/epoch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      throw new Error(`Request failed (${res.status})`);
    }

    const j = await res.json();
    appendLog('Epoch', `block_hash=${j.epoch_block.block_hash}`);

    setStatus('Epoch summary added', 'success');
  } catch (err) {
    console.error(err);
    setStatus(err.message || 'Unable to fetch epoch', 'error');
  } finally {
    toggleActions(false);
  }
}

async function latest() {
  toggleActions(true);
  setStatus('Fetching latest block and transaction...', 'progress');

  try {
    const res = await fetch('/chainchat/latest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(getFormValues()),
    });

    if (!res.ok) {
      throw new Error(`Request failed (${res.status})`);
    }

    const j = await res.json();
    appendLog('Latest', formatJSON(j));

    setStatus('Latest block details added', 'success');
  } catch (err) {
    console.error(err);
    setStatus(err.message || 'Unable to fetch latest data', 'error');
  } finally {
    toggleActions(false);
  }
}

async function lookupTransaction() {
  const txHash = txHashInput.value.trim();
  if (!txHash) {
    return setStatus('Enter a transaction hash first.', 'error');
  }

  toggleActions(true);
  setStatus('Fetching transaction details...', 'progress');

  try {
    const res = await fetch('/chainchat/transaction', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...getFormValues(),
        tx_hash: txHash,
      }),
    });

    if (!res.ok) {
      throw new Error(`Request failed (${res.status})`);
    }

    const j = await res.json();
    appendLog('Transaction', formatJSON(j));

    setStatus('Transaction details added', 'success');
  } catch (err) {
    console.error(err);
    setStatus(
      err.message || 'Unable to fetch transaction details',
      'error'
    );
  } finally {
    toggleActions(false);
  }
}

async function lookupAddress() {
  const address = addressInput.value.trim();
  if (!address) {
    return setStatus('Enter a wallet address first.', 'error');
  }

  toggleActions(true);
  setStatus('Fetching address details...', 'progress');

  try {
    const res = await fetch('/chainchat/address', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...getFormValues(),
        address,
      }),
    });

    if (!res.ok) {
      throw new Error(`Request failed (${res.status})`);
    }

    const j = await res.json();
    appendLog('Address', formatJSON(j));

    setStatus('Address details added', 'success');
  } catch (err) {
    console.error(err);
    setStatus(
      err.message || 'Unable to fetch address details',
      'error'
    );
  } finally {
    toggleActions(false);
  }
}

msgInput?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
    e.preventDefault();
    send();
  }
});
