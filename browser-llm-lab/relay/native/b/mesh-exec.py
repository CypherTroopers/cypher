import os, subprocess, json, time
from pathlib import Path

# Explicit research fixture only; production uses the separately managed Common.
runtime = Path(__file__).resolve().parent
canonical_binary = Path("/root/cypher/build/bin/cypher-linux-amd64")
subprocess.run(["ip","link","set","lo","up"],check=True)
interfaces=json.loads(subprocess.check_output(["ip","-j","link","show"],text=True))
assert {x["ifname"] for x in interfaces} == {"lo"}, "Isolated namespace must contain only loopback"
routes4=json.loads(subprocess.check_output(["ip","-j","route","show"],text=True))
routes6=json.loads(subprocess.check_output(["ip","-j","-6","route","show"],text=True))
assert not routes4 and all(x.get("dev")=="lo" for x in routes6), "Unexpected non-loopback route"
(runtime / "logs/namespace-bootstrap.json").write_text(json.dumps({"pid":os.getpid(),"recordedAt":time.time(),"namespace":os.readlink("/proc/self/ns/net"),"interfaces":interfaces,"routes4":routes4,"routes6":routes6},indent=2)+"\n")
os.execv(str(canonical_binary), [str(canonical_binary), '--config', str(runtime / 'node.toml'), '--datadir', str(runtime / 'data'), '--networkid', '10101919', '--syncmode', 'full', '--cache', '64', '--rnetport', '7314', '--nat', 'extip:127.0.0.1', '--nodiscover', '--ipcpath', str(runtime / 'node.ipc'), '--verbosity', '2', '--browser.public-relay', '--browser.public-relay.config', str(runtime / 'source.json')])
