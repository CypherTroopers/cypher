#!/usr/bin/env python3
"""Read-only native finance ledger. Reuses formal codecs and CLX issuance decoder.

Without --observer, canonical historical observations are not independent source
FHS proofs. Even with it, RPC receipt fields are consistency-checked; the auditor
does not independently reconstruct the receipt trie.
Unknown EVM calls stop accounting rather than silently treating them as transfers.
"""
import argparse
import json
import re
import time
from pathlib import Path
import subprocess

from live_clx_accounting import number
from live_finance import Helper, SourceObserver, CUSTODY, REPO, atomic, web, anchored_block, authenticated_projection
from live_observe import rpc

BUCKETS = "UTFSIW RZ".replace(" ", "")


def atoms(value):
    if isinstance(value, list):
        if len(value) != 32 or any(type(b) is not int or not 0 <= b <= 255 for b in value):
            raise ValueError("amount byte encoding")
        return int.from_bytes(bytes(value), "big")
    result = number(value)
    if result < 0 or result >= 1 << 128:
        raise ValueError("native amount range")
    return result


def address(value):
    if isinstance(value, list) and len(value) == 20:
        return "0x" + bytes(value).hex()
    if isinstance(value, str) and len(value) == 42 and value.startswith("0x"):
        return value.lower()
    raise ValueError("address encoding")


class Ledger:
    def __init__(self, start):
        if start["status"]["Sequence"] != 0 or any(int(n) for n in start["buckets"].values()):
            raise ValueError("this run auditor requires the recorded pre-finance baseline, not an arbitrary partial interval")
        self.buckets = {k: int(v) for k,v in start["buckets"].items()}
        self.surplus = int(start["surplus"])
        self.delta, self.accepted, self.claims, self.nonces, self.operations = {}, {}, {}, {}, {}
        self.gas = self.common = self.burn = self.issuance = 0
        self.maxima = {k: 0 for k in ("calldata_bytes", "dex_proof_bytes", "clx_evidence_bytes", "headers", "mpt_nodes", "mpt_bytes", "depth")}

    def add(self, who, value):
        who = address(who)
        self.delta[who] = self.delta.get(who, 0) + value

    def block(self, block):
        total = 0
        for reward in block["issuance_by_recipient"]:
            v = number(reward["atoms"])
            if v < 0:
                raise ValueError("negative issuance")
            self.add(reward["recipient"], v)
            total += v
        if total != number(block["issuance_total_atoms"]):
            raise ValueError("CLX issuance model inconsistency")
        self.issuance += total

    def transaction(self, tx, receipt, native=None):
        sender = address(tx["from"])
        if address(receipt["from"]) != sender or tx["hash"].lower() != receipt["transactionHash"].lower():
            raise ValueError("receipt sender/hash")
        nonce = number(tx["nonce"])
        if sender in self.nonces and nonce != self.nonces[sender]+1:
            raise ValueError("noncontiguous sender nonce in complete interval")
        self.nonces[sender] = nonce
        gas = number(receipt["gasUsed"])*number(tx["gasPrice"])
        common, burn = number(receipt["commonTxApproverReward"]), number(receipt["commonTxBurn"])
        if min(common, burn) < 0 or gas != common+burn or common != gas//5:
            raise ValueError("gas/Common/burn conservation")
        if number(receipt.get("effectiveGasPrice", tx["gasPrice"])) != number(tx["gasPrice"]):
            raise ValueError("effective gas price")
        self.add(sender, -gas)
        self.add(receipt["commonTxRewardRecipient"], common)
        self.gas += gas
        self.common += common
        self.burn += burn
        if number(receipt["status"]) == 0:
            if receipt["logs"]:
                raise ValueError("reverted transaction leaked logs")
            return self.count("reverted")
        if number(receipt["status"]) != 1 or tx.get("to") is None:
            raise ValueError("unexpected receipt status/contract creation")
        to, value = address(tx["to"]), number(tx["value"])
        self.add(sender, -value)
        self.add(to, value)
        if to != CUSTODY:
            if tx.get("input", "0x") != "0x":
                raise ValueError("unmodeled ordinary EVM call; separate EVM auditor required")
            return self.count("transfer")
        if native is None:
            raise ValueError("missing formal native decode")
        for key in self.maxima:
            self.maxima[key] = max(self.maxima[key], native.get(key, 0))
        kind = native["kind"]
        if kind in ("deposit", "support", "insurance"):
            self.buckets[{"deposit": "U", "support": "S", "insurance": "I"}[kind]] += value
        elif kind == "checkpoint":
            if value:
                raise ValueError("nonzero checkpoint value")
            cp, finance = native["checkpoint"], native["finance"]
            seq, digest = cp["Sequence"], native["checkpoint_hash"]
            if seq in self.accepted:
                if self.accepted[seq] != digest:
                    raise ValueError("conflicting accepted checkpoint")
                return self.count("checkpoint-replay")
            if seq != len(self.accepted)+1:
                raise ValueError("accepted checkpoint gap")
            self.accepted[seq] = digest
            for source, dest, field in [("U","T","DepositTotal"), ("I","T","InsuranceUsed"), ("T","F","CollectedFees"), ("T","Z","FundingDust"), ("T","W","WithdrawalTotal"), ("F","R","RewardFromFees"), ("S","R","RewardFromSupport")]:
                v = atoms(finance[field])
                self.buckets[source] -= v
                self.buckets[dest] += v
        elif kind == "claim":
            if value:
                raise ValueError("nonzero claim value")
            claim, digest = native["claim"], native["claim_hash"]
            if claim["Kind"] not in (1,2):
                raise ValueError("unknown native claim kind")
            events = [log for log in receipt["logs"] if address(log["address"]) == CUSTODY and log["topics"] == [native["event_topic"]]]
            if len(events) != 1:
                raise ValueError("missing/duplicate native claim event")
            raw = bytes.fromhex(events[0]["data"][2:])
            if len(raw) != 33 or "0x"+raw[:32].hex() != digest or raw[32] not in (0,1) or bool(raw[32]) != (digest in self.claims):
                raise ValueError("claim identity/replay bit mismatch")
            if digest in self.claims:
                return self.count("claim-replay")
            self.claims[digest] = native
            v = atoms(claim["Amount"])
            self.buckets["W" if claim["Kind"] == 1 else "R"] -= v
            self.add(CUSTODY, -v)
            self.add(claim["Recipient"], v)
        elif kind != "anchor":
            raise ValueError("unknown native operation")
        if min(self.buckets.values()) < 0:
            raise ValueError("unfunded reservation/payment")
        return self.count(kind)

    def count(self, kind):
        self.operations[kind] = self.operations.get(kind, 0)+1
        return kind

    def result(self, end):
        if self.buckets != {k: int(v) for k,v in end["buckets"].items()} or self.surplus != int(end["surplus"]):
            raise ValueError("native canonical buckets/surplus differ from independent ledger")
        if sum(self.buckets.values())+self.surplus != int(end["balance"]):
            raise ValueError("custody/bucket conservation")
        if end["status"]["Sequence"] != len(self.accepted):
            raise ValueError("canonical accepted sequence differs")
        if sum(self.delta.values()) != self.issuance-self.burn:
            raise ValueError("wallet/custody/issuance/burn conservation")
        return {"native_delta_atoms": {k: str(v) for k,v in self.delta.items()}, "buckets_atoms": {k: str(v) for k,v in self.buckets.items()}, "surplus_atoms": str(self.surplus), "custody_atoms": end["balance"], "gas_atoms": str(self.gas), "common_reward_atoms": str(self.common), "burn_atoms": str(self.burn), "existing_clx_issuance_atoms": str(self.issuance), "operations": self.operations, "maxima": self.maxima, "accepted_sequence": len(self.accepted), "paid_claims": len(self.claims)}


def projection(helper, ipc, height):
    request = helper.call("projection-keys")
    values = {k: rpc(ipc, "eth_getStorageAt", [CUSTODY, k, hex(height)]) for k in request["slots"]}
    balance = str(number(rpc(ipc, "eth_getBalance", [CUSTODY, hex(height)])))
    return helper.call("projection", Slots=values, Balance=balance)


def paid_nullifiers(claims):
    # Adapter.Claim stores the exact paid leaf hash, not a boolean marker.
    # This also rejects reuse of a claim ID with different authenticated fields.
    result = {}
    for claim in claims.values():
        slot, leaf = claim["nullifier_slot"], claim["claim_hash"]
        if any(not isinstance(v, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", v) for v in (slot, leaf)) or number(leaf) == 0:
            raise ValueError("paid nullifier slot/leaf encoding")
        slot, leaf = slot.lower(), leaf.lower()
        if slot in result and result[slot] != leaf:
            raise ValueError("one nullifier has conflicting paid leaves")
        result[slot] = leaf
    return result


def verify_paid_endpoint(helper, observer, journal, initial, final, ledger, output, require_paid=True):
    """Reauthenticate the ledger endpoints and paid rights, without RPC trust."""
    anchors = {}
    for label in ("start", "end"):
        block = journal[label]
        anchor = observer.call("anchor", Height=number(block["number"]), Hash=block["hash"])["anchor"]
        anchored_block(anchor, block)
        anchors[label] = anchor
    native = authenticated_projection(helper, observer, anchors["end"])
    if native["projection"] != final or require_paid and any(int(final["buckets"][key]) for key in ("W", "R")):
        raise ValueError("authenticated native endpoint has unobserved projection or unpaid claims")
    if authenticated_projection(helper, observer, anchors["start"])["projection"] != initial:
        raise ValueError("authenticated initial native projection differs")
    if require_paid and final["status"]["Sequence"] < journal["drained_target"]:
        raise ValueError("authenticated settlement endpoint precedes drained target")
    expected_nullifiers = paid_nullifiers(ledger.claims)
    nullifiers = sorted(expected_nullifiers)
    if len(nullifiers) > 4096 or len(ledger.delta) > 128:
        raise ValueError("auditor proof count bound")
    proof_records = [{"kind":"native-end", "evidence":native}]
    end = journal["end"]
    for first in range(0, len(nullifiers), 32):
        keys = nullifiers[first:first+32]
        evidence = observer.call("account", Height=number(end["number"]), Hash=end["hash"], Address=CUSTODY, Keys=keys)
        if evidence["anchor"] != anchors["end"] or set(evidence["values"]) != set(keys) or any(number(evidence["values"][key]) != number(expected_nullifiers[key]) for key in keys):
            raise ValueError("paid claim nullifier proof differs")
        proof_records.append({"kind":"nullifiers", "evidence":evidence})
    for who, delta in ledger.delta.items():
        balances = {}
        for label in ("start", "end"):
            block = journal[label]
            evidence = observer.call("account", Height=number(block["number"]), Hash=block["hash"], Address=who, Keys=[])
            if evidence["anchor"] != anchors[label] or evidence["address"].lower() != who.lower():
                raise ValueError("native wallet proof identity differs")
            balances[label] = int(evidence["balance"])
            proof_records.append({"kind":"wallet-"+label, "evidence":evidence})
        if balances["end"]-balances["start"] != delta:
            raise ValueError("authenticated wallet delta differs from full ledger")
    # Each row remains bounded; do not aggregate all historical MPTs into a
    # single unbounded JSON response or change protocol proof limits.
    with (output/"authenticated-accounts.jsonl").open("x") as stream:
        for record in proof_records:
            stream.write(json.dumps(record)+"\n")
    return {"start_anchor":anchors["start"],"end_anchor":anchors["end"],"paid_nullifiers":len(nullifiers),"wallets":len(ledger.delta),"scope":"genesis-linked CLX FHS and exact account/storage MPT proofs; committee trust model"}


def partial_interval(journal, anchor, block):
    copied = dict(journal)
    copied["end"] = anchored_block(anchor,block)
    copied.pop("drained_target",None)
    return copied


def audit(args):
    journal = json.loads((args.run/"journal.json").read_text())
    partial = getattr(args,"partial",False)
    inventory=json.loads((args.candidate/"public/inventory.json").read_text())
    helper = Helper(args.helper, args.candidate.resolve())
    observer = None
    ipc = REPO/"chaindbmine/cypher.ipc"
    name = getattr(args,"output_name","accounting")
    if not re.fullmatch(r"accounting(?:-[a-zA-Z0-9_-]{1,48})?", name):
        raise ValueError("dedicated accounting result name required")
    out = args.run/name
    out.mkdir(exist_ok=False)
    try:
        identity = helper.call("identity")
        if identity != journal["identity"] or rpc(ipc,"eth_getBlockByNumber", ["0x0",False])["hash"].lower() != identity["genesis"].lower():
            raise ValueError("auditor generation mismatch")
        if partial:
            if not args.observer:
                raise ValueError("partial audit requires source finality verifier")
            observer=SourceObserver(args.observer,Path(inventory["Participants"][0]["Manifest"]),args.run/"source-observer")
            requested=number(rpc(ipc,"eth_blockNumber",[]))
            deadline=time.monotonic()+180
            for _ in range(128):
                if observer.call("current")["Height"] >= requested:
                    break
                if time.monotonic() > deadline:
                    raise ValueError("partial authentication finite catch-up deadline")
                if observer.advance() is None:
                    break
            anchor=observer.call("current")
            block=rpc(ipc,"eth_getBlockByNumber",[hex(anchor["Height"]),False])
            journal=partial_interval(journal,anchor,block)
            # This is a private in-memory copy. No runner end, status, nonce,
            # business completion or signed bytes are edited by this auditor.
            atomic(out/"partial-endpoint.json",{"anchor":anchor,"block":block,"observed_requested_height":requested,"original_runner_status":journal.get("status"),"scope":"authenticated partial interval; not drained"})
        start, end = number(journal["start"]["number"]), number(journal["end"]["number"])
        if not 0 < end-start <= 4096:
            raise ValueError("bounded accounting interval required")
        initial = projection(helper, ipc, start)
        ledger = Ledger(initial)
        previous = journal["start"]["hash"].lower()
        with (out/"transactions.jsonl").open("x") as transactions:
            for first in range(start+1,end+1,64):
                blocks, inputs = [], []
                for h in range(first,min(end+1,first+64)):
                    block = rpc(ipc,"eth_getBlockByNumber",[hex(h),True])
                    if block["parentHash"].lower() != previous:
                        raise ValueError("canonical ancestry differs")
                    previous = block["hash"].lower()
                    inputs.append(json.dumps({"rlp": rpc(ipc,"debug_getBlockRlp",[h]), "expected_hash":block["hash"],"expected_number":h}))
                    blocks.append(block)
                decoded = subprocess.run([str(args.decoder.resolve())],input=("\n".join(inputs)+"\n").encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=60,check=True)
                values = [json.loads(s) for s in decoded.stdout.splitlines()]
                if len(values)!=len(blocks):
                    raise ValueError("issuance decoder record count")
                for block, parsed in zip(blocks,values):
                    ledger.block(parsed)
                    gas = 0
                    if parsed["transaction_hashes"] != [t["hash"] for t in block["transactions"]]:
                        raise ValueError("RLP transaction identity differs from RPC")
                    for tx in block["transactions"]:
                        receipt = rpc(ipc,"eth_getTransactionReceipt",[tx["hash"]])
                        if receipt["blockHash"].lower() != block["hash"].lower():
                            raise ValueError("receipt block binding")
                        native = helper.call("decode-native",Data=tx["input"]) if number(receipt["status"])==1 and (tx.get("to") or "").lower()==CUSTODY else None
                        kind = ledger.transaction(tx,receipt,native)
                        gas += number(receipt["gasUsed"])
                        transactions.write(json.dumps({"height":number(block["number"]),"tx":tx,"receipt":receipt,"native":native,"kind":kind})+"\n")
                    if gas != number(block["gasUsed"]):
                        raise ValueError("receipt/header gas mismatch")
                atomic(out/f"blocks-{first:08d}.json", {"raw_inputs":inputs,"decoded":values})
        if previous != journal["end"]["hash"].lower():
            raise ValueError("canonical end differs")
        final = projection(helper, ipc, end)
        result = ledger.result(final)
        actual = {}
        for who, delta in result["native_delta_atoms"].items():
            actual[who] = str(number(rpc(ipc,"eth_getBalance",[who,hex(end)]))-number(rpc(ipc,"eth_getBalance",[who,hex(start)])))
        if actual != result["native_delta_atoms"]:
            raise ValueError("all wallet balance changes differ from independent ledger")
        for slot, leaf in paid_nullifiers(ledger.claims).items():
            if number(rpc(ipc,"eth_getStorageAt",[CUSTODY,slot,hex(end)])) != number(leaf):
                raise ValueError("paid claim nullifier differs from exact paid leaf")
        if partial or journal.get("native_paid_proof_verified"):
            if not args.observer:
                raise ValueError("paid journal requires independent source observer revalidation")
            if observer is None:
                observer = SourceObserver(args.observer, Path(inventory["Participants"][0]["Manifest"]), args.run/"source-observer")
            result["clx_authentication"] = verify_paid_endpoint(helper, observer, journal, initial, final, ledger, out,require_paid=not partial)
        endpoints=[REPO/f"chaindb{i}/cypher.ipc" for i in range(7)]
        endpoints += [Path(p["CLXDataDir"])/"cypher.ipc" for p in inventory["Participants"]]
        expected_block=rpc(ipc,"eth_getBlockByNumber",[hex(end),False])
        node_results=[]
        for endpoint in endpoints:
            block=rpc(endpoint,"eth_getBlockByNumber",[hex(end),False])
            if not isinstance(block,dict) or any(block.get(k)!=expected_block.get(k) for k in ("hash","stateRoot","receiptsRoot","gasUsed")):
                raise ValueError("full-node canonical root/receipt/gas differs or unavailable")
            if projection(helper,endpoint,end)!=final:
                raise ValueError("full-node settlement projection differs")
            counters=rpc(endpoint,"debug_dexExecutionStats",[])
            if not isinstance(counters,dict) or any(counters.get(k)!=0 for k in ("Instances","Actions","InboxImports")):
                raise ValueError("CLX process heavy engine counters are not zero")
            node_results.append({"ipc":str(endpoint),"block_hash":block["hash"],"state_root":block["stateRoot"],"heavy_engine":counters})
        result["full_node_comparison"]=node_results
        if partial:
            dex=[]
            for participant in inventory["Participants"]:
                status=web("http://"+participant["API"]+"/v1/status")
                item={"participant":participant["Name"],"certified":status["Certified"],"finalized":status["Finalized"]}
                if status["Certified"]:
                    record=web("http://"+participant["API"]+f"/v1/certified?height={status['Certified']}")["Record"]
                    verified=helper.call("verify-certified",Record=record)
                    market=verified["market"]
                    item.update(certified_root=verified["root"],stage=verified["stage"],inbox_cursor=market["InboxCursor"],fee_atoms=market["Fees"],support_atoms=market["Support"],insurance_atoms=market["Insurance"],reward_period=market["RewardPeriod"],frozen=market["Frozen"])
                dex.append(item)
            result["dex_observations_not_finality"]=dex
            result["unsettled"]= {"native_deposit_uncredited_atoms":final["buckets"]["U"],"native_withdrawal_reserved_atoms":final["buckets"]["W"],"native_reward_reserved_atoms":final["buckets"]["R"],"runner_original_status":journal.get("status"),"runner_completion_unchanged":True}
        target=journal.get("drained_target")
        if target:
            roots=[]
            for participant in inventory["Participants"]:
                proof=web("http://"+participant["API"]+f"/v1/checkpoint?height={target}")
                verified=helper.call("verify-finalized",**proof)
                roots.append({"participant":participant["Name"],"height":verified["height"],"root":verified["root"],"checkpoint_hash":verified["checkpoint_hash"]})
            if len({(r["height"],r["root"],r["checkpoint_hash"]) for r in roots})!=1:
                raise ValueError("finalized DEX state differs across registered nodes")
            result["dex_finalized_comparison"]=roots
        if partial:
            scope = "CLX FHS/account proof authentication and partial native ledger; DEX certified observation only, no DEX finality"
        else:
            scope = "CLX FHS/account proof authentication, native ledger and DEX committee finality" if observer else "canonical accounting plus DEX committee finality; CLX finality not independently authenticated"
        scope += "; RPC receipt consistency checked, receipt trie not independently reconstructed"
        result.update(status="PASS_PARTIAL_AUTHENTICATED_ACCOUNTING" if partial else "PASS_AUTHENTICATED_LEDGER" if observer else "PASS_CANONICAL_LEDGER",start=start,end=end,scope=scope+"; not a complete Q4/Q5 verdict")
        atomic(out/("partial-accounting.json" if partial else "result.json"),result)
        return result
    finally:
        if observer:
            observer.close()
        helper.close()


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for field in ("run","candidate","helper","decoder"):
        parser.add_argument("--"+field,type=Path,required=True)
    parser.add_argument("--observer",type=Path,help="required to reauthenticate a proof-drained ledger")
    parser.add_argument("--output-name",default="accounting",help="fresh accounting[-label] directory; never overwrite prior audit")
    parser.add_argument("--partial",action="store_true",help="read-only authenticated interval audit; never mark runner drained/completed")
    print(json.dumps(audit(parser.parse_args())))
