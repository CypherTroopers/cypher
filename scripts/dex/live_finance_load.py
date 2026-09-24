#!/usr/bin/env python3
"""Same scheduled ordinary CLX arrival stream for separate A/B/C windows.

No PM2, init, network configuration or DEX financial inputs. The root operator
controls DEX/relay conditions. Every scheduled request remains in the denominator;
backpressure, send lateness, unresolved finality and reverts are reported.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import time

from live_finance import Runner, REPO, SOURCE, http, atomic
from live_clx_accounting import number
from live_observe import rpc, processes


def quantiles(samples):
    values=sorted(samples)
    if not values:return {k:None for k in ("p50","p95","p99")}
    return {label:values[max(0,math.ceil(p*len(values))-1)] for label,p in [("p50",.5),("p95",.95),("p99",.99)]}


def summary(records):
    complete=[r for r in records if r.get("stage")=="authenticated_finalized"]
    rejected=[r for r in records if r.get("stage") in ("not_issued_backpressure","not_issued_resource_stop","send_rejected")]
    return {"scheduled":len(records),"completed":len(complete),"rejected":len(rejected),
            "successful_completed":sum(number(r.get("receipt",{}).get("status",0))==1 for r in complete),
            "reverted_completed":sum(number(r.get("receipt",{}).get("status",0))==0 for r in complete),
            "unresolved":len(records)-len(complete)-len(rejected),
            "completion_rate":len(complete)/len(records) if records else 0,
            "rejection_rate":len(rejected)/len(records) if records else 0,
            "scheduled_to_authenticated_finality_seconds":quantiles([(r["finalized_ns"]-r["scheduled_ns"])/1e9 for r in complete]),
            "actual_submit_to_authenticated_finality_seconds":quantiles([(r["finalized_ns"]-r["submit_ns"])/1e9 for r in complete]),
            "send_lateness_seconds":quantiles([(r["submit_ns"]-r["scheduled_ns"])/1e9 for r in records if "submit_ns" in r]),
            "censoring":"unresolved and rejected requests retained; finite quantiles cover completed requests only"}


def transaction_cost(items):
    gas=common=burn=0
    missing=0
    for item in items:
        receipt=item.get("receipt")
        if receipt is None:
            missing+=1
            continue
        if receipt["transactionHash"].lower()!=item["hash"].lower() or receipt["from"].lower()!=item["sender"].lower():
            raise ValueError("measured receipt differs from signed intent")
        price=number(item["gas_price"])
        if number(receipt.get("effectiveGasPrice",price))!=price:
            raise ValueError("measurement effective gas price differs")
        fee=number(receipt["gasUsed"])*price
        reward=number(receipt["commonTxApproverReward"])
        burned=number(receipt["commonTxBurn"])
        if min(fee,reward,burned)<0 or fee!=reward+burned or reward!=fee//5:
            raise ValueError("measured gas/Common/burn conservation")
        gas+=fee;common+=reward;burn+=burned
    return {"gas_atoms":str(gas),"common_reward_atoms":str(common),"burn_atoms":str(burn),"receipt_missing":missing,
            "scope":"canonical receipt observations bound to signed intents; costs include reverted TX; finality measured separately"}


def resources():
    output=[]
    for pid,(_,ticks,stat) in processes().items():
        p=Path("/proc")/str(pid)
        try:
            cmd=(p/"cmdline").read_bytes()
            if str(REPO).encode() not in cmd:continue
            status={line.split(":",1)[0]:line.split(":",1)[1].strip() for line in (p/"status").read_text().splitlines() if line.startswith(("VmRSS:","VmHWM:","VmSwap:","Threads:"))}
            io={k:int(v) for k,v in (line.split(":",1) for line in (p/"io").read_text().splitlines()) if k in ("read_bytes","write_bytes")}
            output.append({"pid":pid,"start_ticks":ticks,"exe":os.readlink(p/"exe"),"cpu_user_ticks":int(stat[11]),"cpu_system_ticks":int(stat[12]),"memory":status,"io":io})
        except (OSError,ValueError,IndexError):continue
    return {"unix_ns":time.time_ns(),"processes":output,"mem_available_kib":int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))),"workspace_free_bytes":os.statvfs(REPO).f_bavail*os.statvfs(REPO).f_frsize,"clock_ticks":os.sysconf("SC_CLK_TCK")}


def observe_phase(runner,args):
    if runner.state.get("funded") or runner.state.get("wallets_funded") or runner.state["actions"]:
        raise ValueError("A/B/C requires its own journal, separate from the financial driver")
    root=runner.path/args.phase
    root.mkdir(exist_ok=False)
    # Authentication warmup is outside the timed arrival window, while its
    # wall time and source height remain recorded. No RPC latest is a trust root.
    warm=time.monotonic()
    target=number(http("eth_blockNumber",[]))
    while runner.observer.call("current")["Height"]<target:
        if time.monotonic()-warm>90:raise ValueError("bounded observer authentication warmup")
        if runner.observer.advance() is None:break
    warmup={"seconds":time.monotonic()-warm,"anchor":runner.observer.call("current")}
    previous_controls={k for k in runner.state["transactions"] if k.startswith("control-")}
    count=math.ceil(args.seconds/args.interval)
    start_ns=time.time_ns();start=time.monotonic()
    records=[{"business":f"benchmark-{args.phase}-{i:04d}","scheduled_ns":start_ns+int(i*args.interval*1e9),"offset":i*args.interval,"stage":"scheduled"} for i in range(count)]
    phase={"version":1,"phase":args.phase,"identity":runner.identity,"arrival_interval_seconds":args.interval,"duration_seconds":args.seconds,"warmup":warmup,"requests":records,"condition":"DEX/relay conditions controlled externally; compare actual observed inputs and cache/state differences","status":"RUNNING", "control_sender_purpose":runner.control_purpose,
           "injector":"fixed scheduled arrivals with one bounded synchronous sender/verifier; all sending lateness and rejected/censored arrivals retained"}
    atomic(root/"phase.json",phase)
    deadline=start+args.seconds+180
    next_resource=start
    cached_blocks={}
    stopped=False
    while time.monotonic()<deadline:
        now=time.monotonic()
        backlog=sum(r["stage"] in ("submitted","canonical_receipt") for r in records)
        for rec in records:
            if rec["stage"]!="scheduled" or rec["offset"]>now-start:continue
            if stopped:
                rec["stage"]="not_issued_resource_stop";continue
            try:runner.guard()
            except ValueError:
                stopped=True;rec["stage"]="not_issued_resource_stop";continue
            if backlog>=8:
                rec["stage"]="not_issued_backpressure";continue
            rec["submit_ns"]=time.time_ns()
            try:
                runner.tx(rec["business"],"synthetic-oracle",SOURCE,1)
                rec["hash"]=runner.state["transactions"][rec["business"]]["hash"]
                rec["stage"]="submitted";rec["ack_or_known_ns"]=time.time_ns();backlog+=1
            except ValueError as error:
                rec["stage"]="send_rejected";rec["error"]=str(error)
                # A signed intent survives even if submit failed; it must be
                # reconciled, not forgotten as an unsigned dropped arrival.
                if rec["business"] in runner.state["transactions"]:
                    rec["stage"]="submitted"
                    rec["hash"]=runner.state["transactions"][rec["business"]]["hash"]
        runner.observer.advance()
        anchor=runner.observer.call("current")
        for rec in records:
            if rec["stage"] not in ("submitted","canonical_receipt"):continue
            receipt=http("eth_getTransactionReceipt",[rec["hash"]])
            if not receipt:continue
            rec.setdefault("receipt_ns",time.time_ns());rec["receipt"]=receipt;rec["stage"]="canonical_receipt"
            item=runner.state["transactions"][rec["business"]]
            item["receipt"]=receipt;item["stage"]="canonical_receipt_not_independent_finality"
            height=number(receipt["blockNumber"])
            if height>anchor["Height"]:continue
            block_hash=receipt["blockHash"]
            proof=runner.observer.call("anchor",Height=height,Hash=block_hash)
            if block_hash not in cached_blocks:
                raw=rpc(REPO/"chaindbmine/cypher.ipc","debug_getBlockRlp",[height])
                request={"rlp":raw,"expected_hash":block_hash,"expected_number":height}
                result=subprocess.run([str(args.decoder.resolve())],input=(json.dumps(request)+"\n").encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,check=True)
                decoded=json.loads(result.stdout)
                atomic(root/f"block-{height:08d}.json",{"input":request,"decoded":decoded,"finality":proof})
                cached_blocks[block_hash]=decoded
            if rec["hash"].lower() not in [h.lower() for h in cached_blocks[block_hash]["transaction_hashes"]]:
                raise ValueError("TX absent from finalized header's authenticated body commitment")
            rec["stage"]="authenticated_finalized";rec["finalized_ns"]=time.time_ns()
        if now>=next_resource:
            with (root/"resources.jsonl").open("a") as stream:stream.write(json.dumps(resources())+"\n")
            next_resource=now+5
        runner.save()
        phase["current_anchor"]=anchor;phase["statistics"]=summary(records)
        atomic(root/"phase.json",phase)
        if now>=start+args.seconds and all(r["stage"] in ("authenticated_finalized","send_rejected","not_issued_backpressure","not_issued_resource_stop") for r in records):break
        if not stopped:runner.control()
        time.sleep(.1)
    for rec in records:
        if rec["stage"]=="scheduled":rec["stage"]="not_issued_resource_stop"
    phase["statistics"]=summary(records);phase["elapsed_seconds"]=time.monotonic()-start
    phase["status"]="MEASURED_PERFORMANCE_ACCEPTANCE_UNJUDGED"
    controls=[k for k in runner.state["transactions"] if k.startswith("control-") and k not in previous_controls]
    phase["tail_control_transactions"]=controls
    for k in controls:
        item=runner.state["transactions"][k]
        receipt=http("eth_getTransactionReceipt",[item["hash"]])
        if receipt:item["receipt"]=receipt
    scheduled=[runner.state["transactions"][r["business"]] for r in records if r["business"] in runner.state["transactions"]]
    phase["scheduled_cost"]=transaction_cost(scheduled)
    phase["control_cost"]=transaction_cost([runner.state["transactions"][k] for k in controls])
    runner.save()
    phase["limits"]={"max_pending":8,"max_requests":512,"normal_transfer_atoms":1,"observer":"bounded cryptographic verifier; observer CPU and request polling included in client-side completion latency","C_heap":"NOT_SEPARATELY_MEASURED","WAN":"NOT_RUN"}
    atomic(root/"phase.json",phase)
    return phase


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase",choices=("A","B","C"),required=True)
    p.add_argument("--candidate",type=Path,default=REPO/"build/stage/live-generation-candidate")
    for field in ("helper","observer","decoder","output"):p.add_argument("--"+field,type=Path,required=True)
    p.add_argument("--seconds",type=int,default=120);p.add_argument("--interval",type=float,default=10)
    p.add_argument("--execute",action="store_true");p.add_argument("--min-memory-gib",type=int,default=4)
    args=p.parse_args()
    if not 30<=args.seconds<=3600 or not 2<=args.interval<=60 or math.ceil(args.seconds/args.interval)>512:raise SystemExit("arrival/duration bound")
    args.active_indices=list(range(7));args.mode="workload" if args.execute else "plan"
    # The financial driver uses the committee funding source for controls.
    # This independent load journal owns every synthetic-oracle CLX TX nonce;
    # DEX action nonces are a separate authenticated domain.
    args.control_purpose="synthetic-oracle"
    runner=Runner(args)
    try:
        if not args.execute:
            print(json.dumps({"status":"NOT_RUN","identity":runner.identity,"phase":args.phase,"scheduled_count":math.ceil(args.seconds/args.interval),"interval_seconds":args.interval,"normal_transfer_atoms":1,"ordinary_load_budget_atoms":str(math.ceil(args.seconds/args.interval)*(100000*10**9+1)),"scope":"offline workload plan; no network or TX"}));return
        runner.preflight()
        print(json.dumps(observe_phase(runner,args)["statistics"]))
    finally:runner.close()

if __name__=="__main__":main()
