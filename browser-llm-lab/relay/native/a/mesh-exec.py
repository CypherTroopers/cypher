import os
from pathlib import Path

# Explicit research fixture only; production uses the separately managed Common.
runtime = Path(__file__).resolve().parent
canonical_binary = Path("/root/cypher/build/bin/cypher-linux-amd64")
os.execv(str(canonical_binary), [str(canonical_binary), '--config', str(runtime / 'node.toml'), '--datadir', str(runtime / 'data'), '--networkid', '10101919', '--syncmode', 'full', '--cache', '64', '--rnetport', '7312', '--nat', 'extip:127.0.0.1', '--nodiscover', '--ipcpath', str(runtime / 'node.ipc'), '--verbosity', '2', '--browser.public-relay', '--browser.public-relay.config', str(runtime / 'source.json')])
