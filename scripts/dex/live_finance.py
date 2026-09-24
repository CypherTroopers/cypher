#!/usr/bin/env python3
"""Bounded finance driver for the named PM2 generation. Default: offline plan.

No init, PM2, DB mutation, key printing, approval creation or network fallback.
--execute enables only ordinary signed CLX TX and loopback DEX signed actions.
Certified parents schedule work; only descendant proof verifies DEX finality.
The scheduler stops before errors/funding exhaustion; it does not repair FROZEN.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from live_observe import rpc, BLOCK_FIELDS
from live_clx_accounting import number

REPO = Path(__file__).resolve().parents[2]
ATOM = 10**18
SOURCE = "0x3555d2c2af8ff75009f7dbfcf7de7ed80f68588d"
CUSTODY = "0x0000000000000000000000000000000000de0001"
MAX_TX, MAX_ACTIONS, GAS_PRICE = 1024, 512, 10**9
MAX_GAS_RESERVATION = ATOM  # runner only; submission budgets are separate funded lanes


def address_equal(left, right):
    return isinstance(left, str) and left.lower() == right.lower()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def atomic(path, value):
    raw = canonical(value) + b"\n"
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("runner journal byte budget")
    temporary = path.with_suffix(".next")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def web(url, data=None, content="application/json"):
    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password:
        raise ValueError("only explicit loopback HTTP is permitted")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": content})
    with urllib.request.urlopen(req, timeout=8) as response:
        raw = response.read(3 * 1024 * 1024 + 1)
    if len(raw) > 3 * 1024 * 1024:
        raise ValueError("response byte limit")
    return json.loads(raw)


def http(method, params):
    answer = web("http://127.0.0.1:8999", canonical(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
    if "error" in answer:
        raise ValueError("normal Common RPC error code " + str(answer["error"].get("code")))
    return answer["result"]


class HelperRejected(ValueError):
    def __init__(self, answer):
        super().__init__("helper: " + answer.get("error", "rejected"))
        self.category = answer.get("category")


class Helper:
    def __init__(self, binary, candidate):
        self.command = [str(binary.resolve()), "--candidate", str(candidate)]
        self.sent_bytes = self.requests = 0
        self.process = subprocess.Popen(self.command,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        self.buffer = b""

    def call(self, op, **values):
        raw = canonical(dict(Op=op, **values))
        if len(raw) > 3 * 1024 * 1024:
            raise ValueError("helper request bound")
        if self.sent_bytes + len(raw)+1 > 32*1024*1024 or self.requests >= 1000:
            # Stateless verifier only: no vote key/WAL/nonce state resides in
            # this child. Bounded replacement does not restart a validator.
            self.close()
            self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL, bufsize=0)
            self.buffer = b""
            self.sent_bytes = self.requests = 0
        self.process.stdin.write(raw + b"\n")
        self.sent_bytes += len(raw)+1
        self.requests += 1
        deadline = time.monotonic() + 20
        while b"\n" not in self.buffer:
            if not select.select([self.process.stdout], [], [], max(0, deadline-time.monotonic()))[0]:
                raise ValueError("helper response deadline")
            part = os.read(self.process.stdout.fileno(), 65536)
            if not part or len(self.buffer) + len(part) > 3 * 1024 * 1024:
                raise ValueError("helper response unavailable/bound")
            self.buffer += part
        line, self.buffer = self.buffer.split(b"\n", 1)
        answer = json.loads(line)
        if not answer.get("ok"):
            raise HelperRejected(answer)
        return answer["result"]

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()  # only this owned pure helper handle
            self.process.wait(timeout=5)


class SourceObserver(Helper):
    def __init__(self, binary, manifest, directory):
        # Keep symlinks visible to the helper's ownership checks; only make
        # relative CLI paths absolute, never resolve the journal through links.
        self.command = [str(binary.resolve()), "--manifest", str(manifest.absolute()), "--directory", str(directory.absolute())]
        self.sent_bytes = self.requests = 0
        self.process = subprocess.Popen(self.command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL,bufsize=0)
        self.buffer = b""

    def advance(self):
        try:
            return self.call("advance")
        except HelperRejected as error:
            if error.category == "proof_unavailable":
                return None
            raise


def authenticated_projection(helper, observer, anchor=None):
    anchor = anchor or observer.call("current")
    if not anchor["Height"]:
        raise ValueError("no authenticated non-genesis CLX anchor")
    block_hash = "0x" + bytes(anchor["BlockHash"]).hex()
    keys = helper.call("projection-keys")["slots"]
    evidence = observer.call("account",Height=anchor["Height"],Hash=block_hash,Address=CUSTODY,Keys=keys)
    if evidence["anchor"] != anchor or set(evidence["values"]) != set(keys):
        raise ValueError("native proof differs from requested authenticated anchor/slots")
    result = helper.call("projection",Slots=evidence["values"],Balance=evidence["balance"])
    return {"anchor":anchor,"account_evidence":evidence,"projection":result}


def anchored_block(anchor, block):
    if not isinstance(block, dict) or number(block["number"]) != anchor["Height"] or block["hash"].lower() != "0x"+bytes(anchor["BlockHash"]).hex() or block["stateRoot"].lower() != "0x"+bytes(anchor["StateRoot"]).hex():
        raise ValueError("canonical ledger endpoint differs from authenticated CLX anchor")
    return block


def relay_drained(status, target, now):
    # This checks an observation from a formally verifying relay. It is not a
    # new trust root; final native account proof is independently verified.
    counts = status.get("Counts", {})
    authenticated = status.get("Authenticated", {})
    if not isinstance(counts, dict) or not counts or any(type(v) is not int or v < 0 for v in counts.values()):
        return False
    return (status.get("Version") == 1 and status.get("Devnet") is True and
            0 <= now-status.get("ObservedAt", 0) <= 10 and
            authenticated.get("CLXSequenceVerified") is True and
            authenticated.get("CLXSequence", -1) >= target and
            authenticated.get("DEXSequence", -1) >= target and
            sum(counts.values()) == status.get("TotalJobs") and
            all(k == "complete" or v == 0 for k,v in counts.items()))


def submission_mode(inventory):
    integrated = inventory.get("LeaderSubmissionConfigs", [])
    legacy = inventory.get("RelayConfigs", [])
    if integrated and legacy:
        raise ValueError("candidate mixes integrated and standalone submission owners")
    if integrated:
        participants = inventory.get("Participants", [])
        if (len(integrated) != 7 or len(set(integrated)) != 7 or len(participants) != 7 or
                [p.get("SubmissionConfig") for p in participants] != integrated):
            raise ValueError("seven member-specific submission configurations required")
        return "leader", "submission", 7
    if len(legacy) == 2 and len(set(legacy)) == 2:
        return "historical-standalone", "relay", 2
    raise ValueError("candidate lacks a complete submission ownership layout")


def funding_plan(inventory):
    amounts = {"trader-a": 105, "trader-b": 105, "support-owner": 21,
               "insurance-owner": 6, "synthetic-oracle": 1}
    _, prefix, count = submission_mode(inventory)
    for i in range(count):
        for lane in ("anchor", "checkpoint", "claim"):
            amounts[f"{prefix}-{i}-{lane}-gas"] = 6 if lane == "checkpoint" else 1
    addresses = {k["Purpose"]: k["Address"] for k in inventory["Keys"]}
    if (len(addresses) != len(inventory["Keys"]) or not set(amounts) <= addresses.keys() or
            sum(amounts.values()) != 238+8*count or
            len({addresses[k].lower() for k in amounts}) != len(amounts)):
        raise ValueError("funding identities/total")
    return [{"purpose": k, "recipient": addresses[k], "atoms": str(v * ATOM)} for k, v in amounts.items()]


def submission_paths(inventory, candidate):
    mode, _, count = submission_mode(inventory)
    configs = inventory["LeaderSubmissionConfigs"] if mode == "leader" else inventory["RelayConfigs"]
    result = []
    for index, name in enumerate(configs):
        path = Path(name)
        if not path.is_absolute() or not path.is_relative_to(candidate) or any(p.is_symlink() for p in (path, *path.parents)) or path.stat().st_size > 64*1024:
            raise ValueError("submission configuration path/type/size")
        config = json.loads(path.read_text())
        data = Path(config["DataDir"])
        if not data.is_absolute() or not data.is_relative_to(candidate) or any(p.is_symlink() for p in (data, *data.parents)):
            raise ValueError("submission data path")
        if mode == "leader":
            participant = inventory["Participants"][index]
            if data != Path(participant["DEXDataDir"])/"submission" or config["DEXURL"] != "http://"+participant["API"]:
                raise ValueError("submission does not belong to this DEX member")
        result.append(data/"status.json")
    if len(result) != count or len(set(result)) != count:
        raise ValueError("duplicate submission storage owner")
    return mode, result


def submission_accepted(status, target, now):
    # Local status is only progress telemetry. The drain caller must separately
    # verify the native CLX account proof against authenticated source finality.
    authenticated = status.get("Authenticated", {})
    return (status.get("Version") == 1 and status.get("Devnet") is True and
            0 <= now-status.get("ObservedAt", 0) <= 10 and
            authenticated.get("CLXSequenceVerified") is True and
            authenticated.get("CLXSequence", -1) >= target and
            authenticated.get("DEXSequence", -1) >= target)


def prepare_output(output, identity):
    path = output.absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("runner output must not traverse symlinks")
    allowed = path.parent == REPO/"build/stage" or path.parent == Path("/tmp")
    if not allowed or not path.name.startswith("live-finance-"):
        raise ValueError("use a dedicated build/stage/live-finance-* or /tmp/live-finance-* directory")
    if path.exists() and not path.is_dir():
        raise ValueError("runner output is not a directory")
    path.mkdir(mode=0o700, exist_ok=True)
    marker = path/"OWNER.json"
    expected = {"tool":"common-dex-live-finance-v1", "uid":os.getuid(), "identity":identity}
    if marker.exists():
        if marker.is_symlink() or json.loads(marker.read_text()) != expected or path.stat().st_uid != os.getuid():
            raise ValueError("runner directory ownership/generation mismatch")
    else:
        if any(path.iterdir()):
            raise ValueError("refusing unowned nonempty output directory")
        atomic(marker, expected)
    if path.stat().st_mode & 0o077:
        raise ValueError("runner output directory must be private mode 0700")
    return path


class Runner:
    def __init__(self, args):
        self.args = args
        self.candidate = args.candidate.resolve()
        self.inventory = json.loads((self.candidate / "public/inventory.json").read_text())
        self.keys = {k["Purpose"]: k["Address"] for k in self.inventory["Keys"]}
        self.helper = Helper(args.helper, self.candidate)
        self.identity = self.helper.call("identity")
        self.plan = funding_plan(self.inventory)
        self.submission_mode, self.submission_status_paths = submission_paths(self.inventory, self.candidate)
        self.path = prepare_output(args.output, self.identity)
        self.lock = os.fdopen(os.open(self.path / "LOCK", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600), "a")
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.journal = self.path / "journal.json"
        if self.journal.exists():
            if self.journal.stat().st_size > 8*1024*1024:
                raise ValueError("journal bound")
            fd = os.open(self.journal, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd) as stream:
                self.state = json.load(stream)
            if self.state["identity"] != self.identity or self.state.get("funding_plan_hash") != hashlib.sha256(canonical(self.plan)).hexdigest():
                raise ValueError("runner journal belongs to another generation")
        else:
            self.state = {"version": 1, "identity": self.identity, "funding_plan_hash": hashlib.sha256(canonical(self.plan)).hexdigest(), "transactions": {}, "actions": [],
                          "phase": 0, "cycle": 0, "active_seconds": 0, "funded": False}
        self.active = args.active_indices
        self.primary = 19000+self.active[0]
        self.last_control = 0
        self.last_head = None
        self.last_head_progress = time.monotonic()
        self.started = time.monotonic()
        self.control_purpose = getattr(args, "control_purpose", "funding-source")
        if self.control_purpose not in ("funding-source", "synthetic-oracle"):
            raise ValueError("unsupported normal control sender")
        old_purpose = self.state.get("control_purpose")
        old_controls = {v["purpose"] for k,v in self.state["transactions"].items() if k.startswith("control-")}
        if (old_purpose is not None and old_purpose != self.control_purpose) or old_controls - {self.control_purpose}:
            raise ValueError("control sender belongs to another run journal")
        self.state["control_purpose"] = self.control_purpose
        self.observer = None
        if args.observer and args.mode != "plan":
            self.observer = SourceObserver(args.observer, Path(self.inventory["Participants"][0]["Manifest"]), self.path/"source-observer")

    def save(self):
        atomic(self.journal, self.state)

    def event(self, event_type, **values):
        raw = canonical(dict(event=event_type, unix_ns=time.time_ns(), **values))
        if len(raw) > 3*1024*1024:
            raise ValueError("event byte limit")
        path = self.path / "events.jsonl"
        if path.exists() and path.stat().st_size > 64*1024*1024:
            raise ValueError("event disk budget")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "ab") as stream:
            stream.write(raw + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

    def preflight(self):
        if self.identity["genesis"].lower() != http("eth_getBlockByNumber", ["0x0", False])["hash"].lower() or number(http("eth_chainId", [])) != self.identity["chain_id"]:
            raise ValueError("new candidate generation is not running; no TX was signed/sent")
        if self.identity["schema"] != (6 if self.inventory["ConfigurationVersion"] == 5 else 5) or self.identity["financial_version"] != 6:
            raise ValueError("runner schema mismatch")
        self.guard()
        for i in range(7):
            endpoint = REPO / f"chaindb{i}/cypher.ipc"
            if rpc(endpoint, "eth_getBlockByNumber", ["0x0", False])["hash"].lower() != self.identity["genesis"].lower():
                raise ValueError("committee genesis differs")
        if "start" not in self.state:
            self.state["start"] = http("eth_getBlockByNumber", ["latest", False])
            self.save()

    def guard(self):
        available = int(next(s.split()[1] for s in Path("/proc/meminfo").read_text().splitlines() if s.startswith("MemAvailable:"))) * 1024
        disk = os.statvfs(self.path)
        if available < self.args.min_memory_gib * (1 << 30) or disk.f_bavail*disk.f_frsize < 2*(1 << 30):
            raise ValueError("resource floor reached; new input stopped, no host setting changed")
        if (self.path / "STOP_INPUT").exists():
            raise ValueError("operator STOP_INPUT reached; journal preserved")

    def tx(self, business, purpose, recipient, value, data="0x", gas=100000):
        transactions = self.state["transactions"]
        if business not in transactions:
            self.guard()
            if len(transactions) >= MAX_TX or sum(t["gas"] for t in transactions.values())*GAS_PRICE + gas*GAS_PRICE > MAX_GAS_RESERVATION:
                raise ValueError("runner transaction/gas budget exhausted")
            sender = SOURCE if purpose == "funding-source" else self.keys[purpose]
            latest = number(http("eth_getTransactionCount", [sender, "latest"]))
            pending = number(http("eth_getTransactionCount", [sender, "pending"]))
            owned = {t["nonce"] for t in transactions.values() if t["sender"].lower() == sender.lower() and t["nonce"] >= latest}
            if any(n not in owned for n in range(latest, pending)) or len(owned) > 8:
                raise ValueError("foreign pending nonce or owned pending window full")
            nonce = max([pending] + [n+1 for n in owned])
            if any(n not in owned for n in range(latest, nonce)):
                raise ValueError("owned sender nonce gap; resume recorded intent")
            if number(http("eth_getBalance", [sender, "latest"])) < value + gas*GAS_PRICE:
                raise ValueError("insufficient owned sender balance")
            args = {"from": sender, "to": recipient, "value": hex(value), "gas": hex(gas), "gasPrice": hex(GAS_PRICE), "nonce": hex(nonce), "data": data}
            if purpose == "funding-source":
                signed = rpc(REPO / "chaindb0/cypher.ipc", "eth_signTransaction", [args])
                if not isinstance(signed, dict) or not signed.get("raw"):
                    raise ValueError("existing owner signing unavailable; unlock through live_auth")
            else:
                signed = self.helper.call("sign-tx", Purpose=purpose, To=recipient, Value=str(value), Nonce=nonce, Gas=gas, GasPrice=str(GAS_PRICE), Data=data)
            verified = self.helper.call("verify-tx", Data=signed["raw"])
            if (verified["sender"].lower(), verified["to"].lower(), verified["value"], verified["nonce"], verified["gas"], verified["gas_price"], verified["data"]) != (sender.lower(), recipient.lower(), str(value), nonce, gas, str(GAS_PRICE), data):
                raise ValueError("signed transaction differs from persisted intended economics")
            transactions[business] = dict(verified, raw=signed["raw"], stage="signed_not_sent", purpose=purpose)
            self.save()  # signed bytes + nonce + business intent fsynced before network
        item = transactions[business]
        receipt = http("eth_getTransactionReceipt", [item["hash"]])
        if receipt:
            if number(receipt["status"]) != 1:
                raise ValueError("canonical TX failed: " + business)
            item["stage"], item["receipt"] = "canonical_receipt_not_independent_finality", receipt
            self.save()
            return receipt
        known = http("eth_getTransactionByHash", [item["hash"]])
        if known is not None:
            if known["hash"].lower() != item["hash"].lower() or address_equal(known.get("from"), item["sender"]) is False or number(known["nonce"]) != item["nonce"]:
                raise ValueError("known transaction metadata differs from durable intent")
            item["stage"] = "mempool_or_inclusion_observed_not_finality"
            self.save()
            return None
        answer = http("eth_sendRawTransaction", [item["raw"]])
        if answer.lower() != item["hash"].lower():
            raise ValueError("RPC returned foreign TX hash")
        item["stage"] = "rpc_ack_not_finality"
        self.save()
        self.event("clx_rpc_ack", business=business, hash=item["hash"], nonce=item["nonce"])
        return None

    def control(self):
        head = http("eth_getBlockByNumber", ["latest", False])["hash"]
        if head != self.last_head:
            self.last_head, self.last_head_progress = head, time.monotonic()
        if time.monotonic()-self.last_head_progress < 5 or time.monotonic()-self.last_control < 2:
            return
        controls = sorted(k for k in self.state["transactions"] if k.startswith("control-"))
        pending = []
        for k in controls:
            item = self.state["transactions"][k]
            if "receipt" not in item:
                receipt = http("eth_getTransactionReceipt", [item["hash"]])
                if receipt:
                    item["receipt"], item["stage"] = receipt, "canonical_receipt_not_independent_finality"
                else:
                    pending.append(k)
        business = pending[0] if len(pending) >= 4 else f"control-{len(controls):04d}"
        purpose = getattr(self, "control_purpose", "funding-source")
        recipient = self.keys["synthetic-oracle"] if purpose == "funding-source" else SOURCE
        self.tx(business, purpose, recipient, 1)
        self.last_control = time.monotonic()

    def clx_progress(self):
        """Finite ordinary-CLX workload while DEX financial input is paused.

        This uses the same nonce journal/gas budget as drive; it cannot complete
        or remove a pending DEX action or call a settlement adapter directly.
        """
        if not self.state["funded"]:
            raise ValueError("CLX progress requires the existing funded run")
        self.event("clx_progress_start", seconds=self.args.seconds,
                   scope="ordinary one-atom test transfers only; no DEX financial input")
        end = time.monotonic()+self.args.seconds
        while time.monotonic() < end:
            self.guard()
            self.control()
            self.save()
            time.sleep(.5)
        self.event("clx_progress_end", dex_pending_intent_retained=bool(self.state.get("pending_action")))

    def wait_tx(self, business, purpose, recipient, value, data="0x", gas=100000):
        deadline = time.monotonic()+120
        while time.monotonic() < deadline:
            if self.tx(business, purpose, recipient, value, data, gas):
                return
            self.control()  # bounded owned nonce descendants through the same admission path
            time.sleep(.5)
        raise ValueError("canonical receipt deadline (ACK is not finality): "+business)

    def fund_wallets(self):
        for item in self.plan:
            self.wait_tx("fund-"+item["purpose"], "funding-source", item["recipient"], int(item["atoms"]))
        self.state["wallets_funded"] = True
        self.save()

    def fund(self):
        self.fund_wallets()
        for purpose, kind, coins in [("trader-a", "deposit", 100), ("trader-b", "deposit", 100), ("support-owner", "support", 20), ("insurance-owner", "insurance", 5)]:
            data = self.helper.call("native-call", Kind=kind)["data"]
            self.wait_tx("initial-"+kind+"-"+purpose, purpose, CUSTODY, coins*ATOM, data, 300000)
        self.state["funded"] = True
        self.save()
        self.event("funding_receipts_observed", funding_atoms=str(sum(int(x["atoms"]) for x in self.plan)), deposit_atoms=str(225*ATOM), finality="awaiting_authenticated_submission_inbox")

    def statuses(self):
        result = []
        for i in self.active:
            # The actor can explicitly return 503 during a bounded storage
            # cut or transport recovery. Record it and retry reads only. No
            # signed action is resent, no failed node is excluded, and a
            # sustained outage still stops the driver with its journal intact.
            for attempt in range(3):
                try:
                    result.append(web(f"http://127.0.0.1:{19000+i}/v1/status"))
                    break
                except urllib.error.HTTPError as error:
                    if error.code != 503:
                        raise
                    self.event("dex_status_unavailable", participant=i, attempt=attempt+1, http_status=503)
                    if attempt == 2:
                        raise
                    time.sleep(.1 * (attempt+1))
        return result

    def certified(self, height=None):
        height = height or min(s["Certified"] for s in self.statuses())
        if height == 0:
            return None, None
        record = web(f"http://127.0.0.1:{self.primary}/v1/certified?height={height}&selected=true")["Record"]
        verified = self.helper.call("verify-certified", Record=record)
        return record, verified

    def finalized(self, height):
        answer = web(f"http://127.0.0.1:{self.primary}/v1/checkpoint?height={height}")
        verified = self.helper.call("verify-finalized", **answer)
        return answer, verified

    def submit(self, record, op="sign-action", purpose="synthetic-oracle", transition=None, **values):
        if len(self.state["actions"]) >= MAX_ACTIONS:
            raise ValueError("action budget exhausted")
        signed = self.helper.call(op, Purpose=purpose, Record=record, **values)
        entry = dict(signed, op=op, kind=values.get("Kind", op), stage="signed_not_sent", signed_ns=time.time_ns(), transition=transition or {})
        self.state["pending_action"] = entry
        self.save()
        self.resume_action()

    def reconcile_recorded_action(self, item):
        # A cold restart may find this exact intent already certified while its
        # ingress nonce is now stale. Authenticate the selected certified record
        # before attempting to POST again; a duplicate rejection is not evidence
        # that the original business action failed.
        latest = min(s["Certified"] for s in self.statuses())
        matched = None
        for height in range(item["predicted_height"], min(latest,item["predicted_height"]+7)+1):
            record, actual = self.certified(height)
            if base64.b64decode(record["Actions"]).hex() != item["raw"][2:]:
                continue
            if height == item["predicted_height"]:
                if actual["root"].lower() != item["predicted_root"].lower():
                    raise ValueError("same action/parent produced unexpected root")
            else:
                parent, _ = self.certified(height-1)
                if record["Checkpoint"]["PreRoot"] != parent["Checkpoint"]["PostRoot"]:
                    raise ValueError("certified action parent chain differs")
                replay = self.helper.call("execute-signed",Record=parent,Data=item["raw"])
                if replay["height"] != height or replay["root"].lower() != actual["root"].lower():
                    raise ValueError("interleaved inbox action failed actual-parent reexecution")
            matched=(height,actual)
            break
        if matched:
            height,actual=matched
            item["stage"], item["certified_ns"], item["certified_height"] = "certified_not_finalized", time.time_ns(), height
            transition = item["transition"]
            if "open_height" in transition:
                transition["open_height"] = height
            self.state["actions"].append(item)
            self.state.update(transition)
            del self.state["pending_action"]
            self.save()
            self.event("dex_certified", id=item["id"], height=height, predicted_height=item["predicted_height"], root=actual["root"], kind=item["kind"])
            return True
        if latest >= item["predicted_height"]+7:
            raise ValueError("bounded action reconciliation exhausted; intent retained")
        return False

    def resume_action(self):
        item = self.state.get("pending_action")
        if not item:
            return
        if self.reconcile_recorded_action(item):
            return
        try:
            answer = web(f"http://127.0.0.1:{self.primary}/v1/actions", bytes.fromhex(item["raw"][2:]), "application/octet-stream")
        except Exception:
            # Certification may race the POST. Only the authenticated record,
            # never HTTP status or a local nonce guess, can complete the intent.
            if self.reconcile_recorded_action(item):
                return
            raise
        if answer.get("id") != item["id"] or answer.get("stage") == "rejected":
            if self.reconcile_recorded_action(item):
                return
            raise ValueError("DEX ingress rejected recorded action")
        item["ack_ns"] = time.time_ns()
        self.save()
        deadline = time.monotonic()+60
        while time.monotonic() < deadline:
            if self.reconcile_recorded_action(item):
                return
            stage = web(f"http://127.0.0.1:{self.primary}/v1/action-status?id="+item["id"])
            if stage.get("Stage") == "rejected" or stage.get("stage") == "rejected":
                if self.reconcile_recorded_action(item):
                    return
                raise ValueError("DEX economic rejection; no nonce/state adjustment")
            time.sleep(.2)
        raise ValueError("certification deadline; durable action retained")

    def collect(self, height, wait=True):
        record, _ = self.certified(height)
        deadline = time.monotonic()+45
        while True:
            selected = {}
            observed = {}
            for i in self.active:
                value = web(f"http://127.0.0.1:{19000+i}/v1/participation?height={height}")
                errors = self.state.setdefault("receipt_error_observations", {})
                if value["ReceiptErrors"] != errors.get(str(i), 0):
                    errors[str(i)] = value["ReceiptErrors"]
                    self.event("participation_transport_errors_observed", participant=i, cumulative=value["ReceiptErrors"])
                certs = self.helper.call("select-certificates", Record=record, Certificates=value["Certificates"] or [])
                observed[str(i)] = sorted(c["Duty"]["Participant"] for c in certs)
                for certificate in certs:
                    participant = certificate["Duty"]["Participant"]
                    # All are already bound to the same authenticated target.
                    # Different valid collector subsets can certify one duty;
                    # pick canonical bytes without awarding it twice.
                    old = selected.get(participant)
                    if old is None or canonical(certificate) < canonical(old):
                        selected[participant] = certificate
            if len(selected) >= 5 or not wait:
                self.event("participation_exact_target_observed", height=height, node_participants=observed, included=sorted(selected),
                           scope="union of all observed valid exact-target certificates; not universal delivery or seven votes in every view")
                return [selected[i] for i in sorted(selected)]
            if time.monotonic() >= deadline:
                break
            time.sleep(.2)
        raise ValueError("insufficient authenticated exact-target participation; durable state retained")

    def maintenance_step(self, record, parent, finalized, close_rewards=True):
        market, height = parent["market"], parent["height"]+1
        if market["Frozen"]:
            raise ValueError("FROZEN; no new loss allocation or refund")
        oracle = lambda: self.submit(record, Kind="oracle", Price=str(100*ATOM), FundingRate=100,
                                     FeedSequence=market["FeedSequence"]+1, ValidUntil=height+90)
        if market["FeedSequence"] == 0 or market["ValidUntil"] < height+20:
            oracle()
            return True
        if market["PendingFunding"] or height % 10 == 0:
            self.submit(record, Kind="funding")
            return True
        # Inbox/anchor actions and finality descendants can interleave with
        # the client. Commit the chosen real duty after h5, not only at h6.
        # The existing on-chain deadline and two-open-period bound are kept.
        closed = market["RewardPeriod"]
        held_period = None
        for period in range(closed+1, min(closed+2, (height-1)//10+1)+1):
            duty = (period-1)*10+5
            if duty >= height:
                continue
            certs = self.helper.call("committed-certificates", Record=record, Period=period)
            if height > period*10+4:
                if len(certs) < 5:
                    if not getattr(getattr(self, "args", None), "continue_with_held_rewards", False):
                        raise ValueError("uncommitted reward period past authenticated deadline; no late credit or period skip")
                    # This driver's five-participant coverage policy is stricter
                    # than the contract's per-certificate collector quorum.
                    # Hold this close without late commit, period skipping or
                    # deletion. Ordinary market actions still face all existing
                    # engine limits, including the unclosed fee-history cap.
                    holds = self.state.setdefault("held_reward_periods", {})
                    key = str(period)
                    if key not in holds and len(holds) >= 2:
                        raise ValueError("reward hold diagnostic capacity; rights retained")
                    note = {"period": period, "certificate_count": len(certs), "closed_through": closed}
                    if holds.get(key) != note:
                        holds[key] = note
                        self.save()
                        self.event("reward_close_held", **note, observed_height=height,
                                   scope="runner coverage policy; no late credit, skipped period or reservation")
                    held_period = period
                    break
                continue
            # Every scan includes known later arrivals before the original
            # deadline. Online membership is not proof of a vote in this view.
            observed = self.collect(duty, wait=len(certs) < 5)
            duties = {canonical(c["Duty"]) for c in certs}
            if any(canonical(c["Duty"]) not in duties for c in observed):
                self.submit(record, "commit-participation", Certificates=observed)
                return True
        period = closed+1
        if close_rewards and held_period != period and finalized >= period*10+4:
            blocks = []
            for h in list(range((period-1)*10+1, period*10+1))+[period*10+4]:
                proof, _ = self.finalized(h)
                blocks.append({"Checkpoint": proof["Checkpoint"], "Proof": proof["Proof"]})
            certs = self.helper.call("eligible-committed-certificates", Record=record, Close={"Period":period,"Blocks":blocks})
            self.submit(record, "reward-close", Close={"Period": period, "Certificates": certs, "Blocks": blocks})
            return True
        return False

    def economic_step(self, record, parent, finalized):
        if self.maintenance_step(record, parent, finalized):
            return
        market, height = parent["market"], parent["height"]+1
        if market["InboxCursor"] < 4 + self.state.get("extra_deposits", 0):
            self.submit(record, Kind="noop")
            return
        # A small fully collateralized position spans a real funding boundary.
        # Matching repeats at the same synthetic price; no new financial model.
        phase, cycle = self.state["phase"], self.state["cycle"]
        if phase == 2 and market["LastFunding"] <= self.state.get("open_height", 0):
            self.submit(record, Kind="noop")
            return
        if phase in (0, 1, 2, 3):
            purpose, side = [("trader-b", -1), ("trader-a", 1), ("trader-a", -1), ("trader-b", 1)][phase]
            transition = {"phase": phase+1}
            if phase == 1:
                transition["open_height"] = height
            self.submit(record, purpose=purpose, transition=transition, Kind="place", OrderID=cycle*2+(1 if phase < 2 else 2), Side=side, Quantity=1000000, Price=str(100*ATOM))
        elif phase == 4:
            self.submit(record, purpose="trader-a", transition={"phase": 0, "cycle": cycle+1}, Kind="withdraw", Amount=str(ATOM//100), Recipient=self.keys["trader-a"])
        self.save()

    def drive(self):
        if not self.state["funded"]:
            raise ValueError("run fund first; no implicit second funding")
        self.resume_action()
        active_start = time.monotonic()
        end = active_start+self.args.seconds
        next_input = time.monotonic()
        while time.monotonic() < end:
            self.guard()
            statuses = self.statuses()
            final = min(s["Finalized"] for s in statuses)
            storage = self.state.setdefault("storage_observations", {})
            for index, status in zip(self.active, statuses):
                current = status.get("Storage", {})
                old = storage.get(str(index), {})
                if current.get("generation", 0) > old.get("generation", 0):
                    self.event("storage_generation_observed", participant=index, storage=current, certified=status["Certified"], finalized=status["Finalized"])
                storage[str(index)] = current
                if current.get("blocked"):
                    raise ValueError("participant storage budget blocked; evidence retained")
            if min(s["Certified"] for s in statuses) == 0:
                self.control()
                time.sleep(.5)
                continue
            if time.monotonic() >= next_input:
                record, parent = self.certified()
                desired = min(4, parent["height"] // 64)
                if desired > self.state.get("extra_deposits", 0) and not parent["market"]["PendingFunding"]:
                    data = self.helper.call("native-call", Kind="deposit")["data"]
                    self.wait_tx(f"repeat-deposit-{desired}", "trader-a", CUSTODY, ATOM//10, data, 300000)
                    self.state["extra_deposits"] = desired
                    self.save()
                    record, parent = self.certified()
                self.economic_step(record, parent, final)
                next_input = time.monotonic() + self.args.interval
            self.control()
            if final and final > self.state.get("last_verified_finalized", {}).get("height", 0):
                _, verified = self.finalized(final)
                self.state["last_verified_finalized"] = {k: verified[k] for k in ("height", "checkpoint_hash", "root")}
            self.save()
            time.sleep(1)
        self.state["active_seconds"] += time.monotonic()-active_start
        self.state["phase_at_input_stop"] = self.state["phase"]
        self.save()
        self.drain()

    def drain(self):
        self.resume_action()
        # Finish only the already-started normal trading cycle. Do not begin
        # another position to make the measured input interval look active.
        # Existing oracle/funding/close/participation rules remain in force.
        for _ in range(32):
            if self.state["phase"] == 0:
                break
            record, parent = self.certified()
            self.economic_step(record, parent, min(s["Finalized"] for s in self.statuses()))
            self.control()
        if self.state["phase"] != 0:
            raise ValueError("finite open-cycle drain bound; position and pending action retained")
        # Existing finality requires descendants. Signed ordinary Noop only;
        # certified trailing descendants remain explicitly unsettled.
        record, parent = self.certified()
        if parent is None:
            raise ValueError("nothing certified to drain")
        # Persist the measured boundary before producing descendants. A retry
        # must not select the descendants it produced as a new drain target.
        target = self.state.get("settlement_target")
        if target is None:
            target = parent["height"]
            self.state["settlement_target"] = target
            self.save()
        self.validate_settlement_tail(target)
        for _ in range(8):
            if min(s["Finalized"] for s in self.statuses()) >= target:
                break
            record, parent = self.certified()
            if not self.maintenance_step(record, parent, min(s["Finalized"] for s in self.statuses()), close_rewards=False):
                self.submit(record, Kind="noop")
        self.validate_settlement_tail(target)
        self.wait_settlement(target)

    def validate_settlement_tail(self, target, finalized_root=None):
        """A fixed boundary cannot silently omit a recorded financial action."""
        authenticated = {}
        def selected(height):
            if height not in authenticated:
                authenticated[height] = self.certified(height)
            return authenticated[height]
        for item in self.state["actions"]:
            height = item.get("certified_height")
            if not isinstance(height, int) or height <= 0:
                raise ValueError("recorded action lacks authenticated certified height")
            if height <= target:
                continue
            if item.get("kind") != "noop":
                raise ValueError("settlement target would omit a recorded financial action")
            # Current engine.Action v1 is fixed 217 bytes plus 65-byte signature;
            # kind follows version and epoch. This shape check is additional to
            # the existing helper's cryptographic/QC and replay authentication.
            raw = bytes.fromhex(item["raw"][2:])
            if len(raw) != 282 or raw[:2] != b"\x00\x01" or raw[34] != 0:
                raise ValueError("trailing action is not a current signed Noop")
            if height-target > 8:
                raise ValueError("settlement trailing reconciliation bound")
            record, verified = selected(height)
            if verified["height"] != height or base64.b64decode(record["Actions"]) != raw:
                raise ValueError("trailing Noop differs from authenticated selected action")
            base, base_verified = selected(target)
            if finalized_root is not None and (base_verified["height"] != target or
                    "0x"+bytes(base["Checkpoint"]["PostRoot"]).hex() != finalized_root.lower()):
                raise ValueError("trailing Noop branch differs from finalized target root")
            previous = base
            for step in range(target+1, height+1):
                current, current_verified = selected(step)
                if current_verified["height"] != step or current["Checkpoint"]["PreRoot"] != previous["Checkpoint"]["PostRoot"]:
                    raise ValueError("trailing Noop selected parent differs")
                previous = current
            parent, _ = selected(height-1)
            replay = self.helper.call("execute-signed", Record=parent, Data=item["raw"])
            if replay["height"] != height or replay["root"].lower() != verified["root"].lower():
                raise ValueError("trailing Noop replay differs")

    def settle(self):
        # Recovery-only mode: no submit/resume_action/maintenance/funding call.
        # An explicit target is required for legacy journals without a target;
        # no target is inferred retroactively from their latest certified head.
        target = self.args.settlement_target
        if not isinstance(target, int) or isinstance(target, bool) or target <= 0:
            raise ValueError("settle requires an explicit positive settlement target")
        old = self.state.get("settlement_target")
        if old is not None and old != target:
            raise ValueError("settlement target differs from durable previous intent")
        pending = self.state.get("pending_action")
        if pending and not self.reconcile_recorded_action(pending):
            raise ValueError("pending action is not authenticated; settle never posts it")
        if self.state["phase"] != 0:
            raise ValueError("settle requires a completed trading cycle")
        # Authenticate actual finality, not status telemetry or a single QC.
        proof, verified = self.finalized(target)
        if proof["Checkpoint"]["Sequence"] != target or verified["height"] != target:
            raise ValueError("finalized proof differs from settlement target")
        self.validate_settlement_tail(target, verified["root"])
        checkpoint = {k: verified[k] for k in ("height", "checkpoint_hash", "root")}
        prior = self.state.get("settlement_checkpoint")
        if prior is not None and prior != checkpoint:
            raise ValueError("settlement finalized checkpoint differs from durable previous intent")
        if old is None or prior is None:
            self.state["settlement_target"] = target
            self.state["settlement_checkpoint"] = checkpoint
            self.save()
        self.event("settlement_only_start", target=target,
                   scope="existing finalized target; no DEX actions or maintenance generated")
        self.wait_settlement(target)

    def wait_settlement(self, target):
        # Normal CLX control transfers retain the existing nonce/gas caps. They
        # advance CLX finality only; no DEX descendant or financial input occurs.
        deadline = time.monotonic()+180
        while time.monotonic() < deadline:
            final = min(s["Finalized"] for s in self.statuses())
            observed = []
            for p in self.submission_status_paths:
                if not p.exists():
                    continue  # An inactive follower has no completion evidence.
                if p.is_symlink() or not p.is_file() or p.stat().st_size > 2*1024*1024:
                    raise ValueError("submission status type/bound")
                observed.append(json.loads(p.read_text()))
            account = None
            if self.observer:
                self.observer.advance()
                if self.observer.call("current")["Height"]:
                    account = authenticated_projection(self.helper,self.observer)
            if self.submission_mode == "leader":
                accepted = final >= target and any(submission_accepted(r,target,time.time()) for r in observed)
                if self.observer is None:
                    raise ValueError("integrated leader drain requires independent authenticated CLX observer")
            else:
                accepted = (final >= target and len(observed) == 2 and
                            all(relay_drained(r,target,time.time()) for r in observed))
            paid = account is not None and account["projection"]["status"]["Sequence"] >= target and all(int(account["projection"]["buckets"][k]) == 0 for k in ("W","R"))
            if accepted and (paid or self.observer is None):
                proof, state = self.finalized(target)
                atomic(self.path / "drained-finalized.json", {"target": target, "proof": proof, "verified": state})
                self.state["drained_target"] = target
                if account:
                    self.state["end"] = anchored_block(account["anchor"], http("eth_getBlockByNumber", [hex(account["anchor"]["Height"]), False]))
                else:
                    self.state["end"] = http("eth_getBlockByNumber", ["latest", False])
                self.state["status"] = "DRAIN_OBSERVED_AWAITING_INDEPENDENT_LEDGER_AND_LIVE_FAULT_REVIEW"
                self.state["native_paid_proof_verified"] = paid
                if account:
                    atomic(self.path/"drained-native-proof.json",account)
                self.save()
                self.event("drain_observed", target=target, certified=min(s["Certified"] for s in self.statuses()), finalized=final, submission_authenticated_observations=[r["Authenticated"] for r in observed], submission_pending_counts=[r.get("Counts", {}) for r in observed], local_queues_drained=all(relay_drained(r,target,time.time()) for r in observed), claims="authenticated_native_reserves_zero" if paid else "must_audit_native_nullifiers_and_reserves")
                return
            self.control()
            time.sleep(.5)
        raise ValueError("finite drain deadline; unfinished jobs and reservations preserved")

    def close(self):
        if self.observer:
            self.observer.close()
        self.helper.close()
        self.lock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "fund-wallets", "fund", "drive", "drain", "settle", "clx-progress"))
    parser.add_argument("--candidate", type=Path, default=REPO/"build/stage/live-generation-candidate")
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--observer", type=Path, help="read-only genesis-anchored CLX proof observer binary")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--settlement-target", type=int,
                        help="settle mode only: explicit already-finalized DEX target, fixed across retries")
    parser.add_argument("--seconds", type=int, default=3600)
    parser.add_argument("--interval", type=float, default=10)
    parser.add_argument("--min-memory-gib", type=int, default=4)
    parser.add_argument("--continue-with-held-rewards", action="store_true",
                        help="explicitly hold a reward close missing this runner's participant coverage after its deadline; continue only ordinary engine-permitted market actions")
    parser.add_argument("--active-indices", type=lambda s:[int(v) for v in s.split(",")], default=list(range(7)),
                        help="explicit live DEX participants for a planned stop test; never changes quorum")
    args = parser.parse_args()
    if (args.mode == "settle" and (args.settlement_target is None or args.settlement_target <= 0)) or (args.mode != "settle" and args.settlement_target is not None):
        raise SystemExit("--settlement-target is required only for settle and must be positive")
    if not 1 <= args.seconds <= 5400 or not 5 <= args.interval <= 60 or args.seconds/args.interval > 450:
        raise SystemExit("duration/rate budget")
    if not 5 <= len(args.active_indices) <= 7 or args.active_indices != sorted(set(args.active_indices)) or any(i<0 or i>6 for i in args.active_indices):
        raise SystemExit("declare 5..7 distinct registered active indices; quorum remains five")
    runner = Runner(args)
    try:
        if args.mode == "plan":
            report = {"status": "NOT_RUN", "identity": runner.identity, "funding": runner.plan,
                      "total_funding_atoms": str(sum(int(item["atoms"]) for item in runner.plan)), "initial_custody_atoms": str(225*ATOM),
                      "max_runner_tx": MAX_TX, "max_actions": MAX_ACTIONS,
                      "runner_gas_reservation_atoms": str(MAX_GAS_RESERVATION),
                      "scope": "offline plan; no LIVE RPC/TX/PM2/init", "synthetic_market": "BTC/CLX",
                      "live_gates": ["approved init/deployment and matching generation", "seven DEX Common participants with integrated leader submission started", "funding source unlocked through normal live_auth", "fault/recovery events and independent native ledger required for LIVE acceptance"]}
            atomic(args.output/"plan.json", report)
            print(json.dumps(report))
        else:
            if not args.execute:
                raise ValueError("ordinary finance mutations require explicit --execute after generation activation")
            runner.preflight()
            getattr(runner, args.mode.replace("-", "_"))()
    except Exception as error:
        runner.state["last_error"] = str(error)
        runner.state["status"] = "STOPPED_WITH_JOURNAL_PRESERVED"
        runner.save()
        raise
    finally:
        runner.close()


if __name__ == "__main__":
    main()
