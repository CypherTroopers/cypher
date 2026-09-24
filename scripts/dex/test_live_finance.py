import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from live_finance import funding_plan, atomic, web, ATOM, CUSTODY
from live_finance_accounting import Ledger, atoms

A, B = "0x"+"11"*20, "0x"+"22"*20
R = "0x"+"33"*20

def initial():
    return {"status":{"Sequence":0},"buckets":{k:"0" for k in "UTFSIZWR"},"surplus":"0","balance":"0"}

class FinanceTest(unittest.TestCase):
    def test_funding_total_identity_and_checkpoint_budget(self):
        purposes = ["trader-a","trader-b","support-owner","insurance-owner","synthetic-oracle"]
        purposes += [f"relay-{i}-{lane}-gas" for i in range(2) for lane in ("anchor","checkpoint","claim")]
        inv = {"RelayConfigs":["relay-0", "relay-1"], "Keys":[{"Purpose":p,"Address":"0x"+f"{i+1:040x}"} for i,p in enumerate(purposes)]}
        plan = funding_plan(inv)
        self.assertEqual(sum(int(x["atoms"]) for x in plan),254*ATOM)
        self.assertEqual([int(x["atoms"]) for x in plan if "checkpoint" in x["purpose"]],[6*ATOM]*2)
        inv["Keys"][-1]["Address"] = inv["Keys"][0]["Address"]
        with self.assertRaises(ValueError): funding_plan(inv)

    def test_leader_submission_funds_seven_independent_gas_lane_owners(self):
        from live_finance import submission_mode
        purposes = ["trader-a","trader-b","support-owner","insurance-owner","synthetic-oracle"]
        purposes += [f"submission-{i}-{lane}-gas" for i in range(7) for lane in ("anchor","checkpoint","claim")]
        configs = [f"submission-{i}" for i in range(7)]
        inv = {"LeaderSubmissionConfigs": configs, "Participants": [{"SubmissionConfig": p} for p in configs],
               "Keys": [{"Purpose": p, "Address": "0x"+f"{i+1:040x}"} for i,p in enumerate(purposes)]}
        self.assertEqual(submission_mode(inv), ("leader", "submission", 7))
        plan = funding_plan(inv)
        self.assertEqual(sum(int(x["atoms"]) for x in plan), 294*ATOM)
        self.assertEqual(len(plan), 26)
        self.assertEqual([int(x["atoms"]) for x in plan if "checkpoint" in x["purpose"]], [6*ATOM]*7)
        with self.assertRaises(ValueError): funding_plan(dict(inv, RelayConfigs=["legacy0","legacy1"]))
        with self.assertRaises(ValueError): funding_plan(dict(inv, LeaderSubmissionConfigs=configs[:6]))
        changed = dict(inv, Participants=inv["Participants"][:6]+[{"SubmissionConfig":"wrong"}])
        with self.assertRaises(ValueError): funding_plan(changed)

    def test_no_remote_network_fallback(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("network called")):
            for endpoint in ("https://127.0.0.1:8999", "http://example.org", "http://user:pw@127.0.0.1"):
                with self.assertRaises(ValueError): web(endpoint)

    def test_journal_atomic_and_exclusive_next_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"journal.json"
            atomic(p,{"signed":"publicbytes", "nonce":9})
            self.assertEqual(json.loads(p.read_text())["nonce"],9)
            self.assertEqual(p.stat().st_mode & 0o777,0o600)
            (Path(d)/"journal.next").symlink_to(p)
            with self.assertRaises(OSError): atomic(p,{"nonce":10})
            self.assertEqual(json.loads(p.read_text())["nonce"],9)

    def test_independent_225_to_214_native_ledger_and_duplicate_claim(self):
        ledger=Ledger(initial())
        counter=0
        def tx(value,native,logs=None,status=1):
            nonlocal counter
            h="0x"+f"{counter:064x}"
            t={"from":A,"to":CUSTODY,"hash":h,"nonce":counter,"gasPrice":"1","value":str(value),"input":"0x"}
            r={"from":A,"transactionHash":h,"status":status,"gasUsed":"100","commonTxApproverReward":"20","commonTxBurn":"80","commonTxRewardRecipient":R,"logs":logs or []}
            counter+=1
            return ledger.transaction(t,r,native)
        tx(200*ATOM,{"kind":"deposit"});tx(20*ATOM,{"kind":"support"});tx(5*ATOM,{"kind":"insurance"})
        finance={k:0 for k in ("DepositTotal","InsuranceUsed","CollectedFees","FundingDust","WithdrawalTotal","RewardFromFees","RewardFromSupport")}
        finance.update(DepositTotal=200*ATOM,CollectedFees=84*10**15,WithdrawalTotal=10*ATOM,RewardFromFees=2*10**16,RewardFromSupport=98*10**16)
        checkpoint={"kind":"checkpoint","checkpoint":{"Sequence":1},"checkpoint_hash":"0x"+"aa"*32,"finance":finance}
        tx(0,checkpoint);self.assertEqual(tx(0,checkpoint),"checkpoint-replay")
        for index,kind,value in [(1,1,10*ATOM),(2,2,ATOM)]:
            digest="0x"+f"{index:064x}"
            decoded={"kind":"claim","claim_hash":digest,"claim":{"Kind":kind,"Amount":value,"Recipient":B},"event_topic":"0x"+"bb"*32}
            logs=[{"address":CUSTODY,"topics":[decoded["event_topic"]],"data":digest+"00"}]
            tx(0,decoded,logs)
            logs[0]["data"]=digest+"01"
            self.assertEqual(tx(0,decoded,logs),"claim-replay")
        final={"status":{"Sequence":1},"buckets":{k:str(v) for k,v in ledger.buckets.items()},"surplus":"0","balance":str(214*ATOM)}
        result=ledger.result(final)
        self.assertEqual(result["custody_atoms"],str(214*ATOM))
        self.assertEqual(result["buckets_atoms"]["T"],str(189916*10**15))
        self.assertEqual(result["buckets_atoms"]["F"],str(64*10**15))
        self.assertEqual(result["buckets_atoms"]["S"],str(1902*10**16))
        self.assertEqual(ledger.delta[B],11*ATOM)
        with self.assertRaises(ValueError): tx(0,dict(checkpoint,checkpoint_hash="0x"+"cc"*32))

    def test_amount_byte_width(self):
        self.assertEqual(atoms([0]*31+[1]),1)
        for value in ([0]*31,[0]*31+[256]):
            with self.assertRaises(ValueError): atoms(value)

if __name__ == "__main__": unittest.main()

class OutputOwnershipTest(unittest.TestCase):
    def test_dedicated_owner_marker_reuse_and_foreign_directory(self):
        from live_finance import prepare_output
        with tempfile.TemporaryDirectory(prefix="live-finance-") as d:
            path = Path(d)
            identity={"chain_id":10101919,"genesis":"fixture"}
            self.assertEqual(prepare_output(path,identity),path)
            self.assertEqual(prepare_output(path,identity),path)
            with self.assertRaises(ValueError): prepare_output(path,dict(identity,genesis="foreign"))
        with tempfile.TemporaryDirectory(prefix="live-finance-") as d:
            path=Path(d)
            (path/"unrelated").write_text("preserve")
            with self.assertRaises(ValueError): prepare_output(path,{})
            self.assertEqual((path/"unrelated").read_text(),"preserve")

class DurableIntentTest(unittest.TestCase):
    def test_clx_progress_retains_pending_dex_intent_and_requires_funded_run(self):
        from types import SimpleNamespace
        from live_finance import Runner
        r=object.__new__(Runner)
        r.args=SimpleNamespace(seconds=1)
        pending={"id":"signed-dex-intent","nonce":7,"raw":"public-signed-bytes"}
        r.state={"funded":False,"pending_action":pending}
        r.event=lambda *a,**k:None
        with self.assertRaises(ValueError):r.clx_progress()
        calls=[]
        r.guard=lambda:calls.append("guard")
        r.control=lambda:calls.append("ordinary-clx")
        r.save=lambda:calls.append("save")
        r.state["funded"]=True
        with patch("live_finance.time.monotonic",side_effect=[0,0,2]),patch("live_finance.time.sleep"):
            r.clx_progress()
        self.assertEqual(calls,["guard","ordinary-clx","save"])
        self.assertEqual(r.state["pending_action"],pending)

    def test_status_retry_records_unavailability_and_keeps_every_participant(self):
        import urllib.error
        from live_finance import Runner
        r=object.__new__(Runner)
        r.active=[1,2]
        events=[]
        r.event=lambda *a,**k:events.append((a,k))
        unavailable=urllib.error.HTTPError("http://127.0.0.1:19001/v1/status",503,"busy",{},None)
        with patch("live_finance.web",side_effect=[unavailable,{"Certified":6},{"Certified":5}]) as requests, patch("live_finance.time.sleep"):
            self.assertEqual(r.statuses(),[{"Certified":6},{"Certified":5}])
        self.assertEqual(requests.call_count,3)
        self.assertEqual([e[1]["http_status"] for e in events],[503])
        with patch("live_finance.web",side_effect=unavailable) as requests, patch("live_finance.time.sleep"):
            with self.assertRaises(urllib.error.HTTPError):r.statuses()
        self.assertEqual(requests.call_count,3)
        forbidden=urllib.error.HTTPError("http://127.0.0.1:19001/v1/status",403,"forbidden",{},None)
        with patch("live_finance.web",side_effect=forbidden) as requests:
            with self.assertRaises(urllib.error.HTTPError):r.statuses()
        self.assertEqual(requests.call_count,1)

    def test_known_mempool_transaction_is_not_resent_or_finalized(self):
        from live_finance import Runner
        r=object.__new__(Runner)
        item={"hash":"0x"+"aa"*32,"sender":A,"nonce":7,"raw":"signed-public","stage":"signed_not_sent"}
        r.state={"transactions":{"business":item}}
        r.save=lambda:None
        def call(method,params):
            if method=="eth_getTransactionReceipt":return None
            if method=="eth_getTransactionByHash":return {"hash":item["hash"],"from":A,"nonce":"0x7"}
            self.fail("unexpected resend or nonce mutation "+method)
        with patch("live_finance.http",side_effect=call):
            self.assertIsNone(r.tx("business","trader-a",B,1))
        self.assertEqual(item["stage"],"mempool_or_inclusion_observed_not_finality")
        self.assertNotIn("receipt",item)

    def test_interleaved_inbox_reconciles_exact_action_and_atomically_advances_phase(self):
        import base64
        from live_finance import Runner
        r=object.__new__(Runner)
        raw=b"already-signed-action"
        pending={"id":"aa"*32,"raw":"0x"+raw.hex(),"predicted_height":7,"predicted_root":"0xexpected-at-seven","transition":{"phase":2,"open_height":7},"kind":"place"}
        r.state={"pending_action":pending,"actions":[],"phase":1}
        r.primary=19000
        saved=[]
        r.save=lambda:saved.append(json.loads(json.dumps(r.state)))
        r.event=lambda *a,**k:None
        r.statuses=lambda:[{"Certified":8}]*7
        parent={"Actions":base64.b64encode(b"inbox").decode(),"Checkpoint":{"PostRoot":[1]*32}}
        actual={"Actions":base64.b64encode(raw).decode(),"Checkpoint":{"PreRoot":[1]*32}}
        r.certified=lambda height:(parent,{"root":"parent"}) if height==7 else (actual,{"root":"actual"})
        class H:
            def call(self,op,**kwargs):
                if op!="execute-signed" or kwargs["Record"]!=parent or kwargs["Data"]!=pending["raw"]:raise AssertionError("reexecution binding")
                return {"height":8,"root":"actual"}
        r.helper=H()
        with patch("live_finance.web",side_effect=[{"id":pending["id"],"stage":"ingress_admitted"},{"stage":"ingress_admitted"}]):
            r.resume_action()
        self.assertNotIn("pending_action",r.state)
        self.assertEqual(r.state["phase"],2)
        self.assertEqual(r.state["open_height"],8)
        self.assertEqual(r.state["actions"][0]["certified_height"],8)
        self.assertEqual(saved[-1]["phase"],2)
        self.assertNotIn("pending_action",saved[-1])

class FinalityDrainTest(unittest.TestCase):
    def test_relay_ack_stale_status_or_pending_claim_is_not_drained(self):
        from live_finance import relay_drained
        good={"Version":1,"Devnet":True,"ObservedAt":100,"Authenticated":{"CLXSequenceVerified":True,"CLXSequence":18,"DEXSequence":20},"Counts":{"complete":27},"TotalJobs":27}
        self.assertTrue(relay_drained(good,18,105))
        self.assertFalse(relay_drained(good,19,105))
        self.assertFalse(relay_drained(good,18,111))
        self.assertFalse(relay_drained(good,18,99))
        for change in ({"Counts":{"complete":26,"waiting":1}}, {"Counts":{"complete":28,"waiting":-1}}, {"Authenticated":{"CLXSequenceVerified":False,"CLXSequence":18,"DEXSequence":20}}):
            self.assertFalse(relay_drained(dict(good,**change),18,105))

    def test_ledger_end_uses_exact_authenticated_block(self):
        from live_finance import anchored_block
        anchor={"Height":1100,"BlockHash":[1]*32,"StateRoot":[2]*32}
        block={"number":hex(1100),"hash":"0x"+"01"*32,"stateRoot":"0x"+"02"*32}
        self.assertEqual(anchored_block(anchor,block),block)
        for change in ({"number":hex(1101)},{"hash":"0x"+"03"*32},{"stateRoot":"0x"+"04"*32}):
            with self.assertRaises(ValueError):anchored_block(anchor,dict(block,**change))

    def test_wallet_funding_entry_has_no_native_deposit(self):
        from live_finance import Runner
        runner=object.__new__(Runner)
        runner.plan=[{"purpose":"trader-a","recipient":A,"atoms":"105"}]
        runner.state={}; calls=[]
        runner.save=lambda:None
        runner.wait_tx=lambda *args:calls.append(args)
        runner.fund_wallets()
        self.assertEqual(calls,[("fund-trader-a","funding-source",A,105)])
        self.assertTrue(runner.state["wallets_funded"])
        self.assertNotIn("funded",runner.state)

    def test_paid_ledger_reauthenticates_nullifiers_and_wallet_deltas(self):
        from live_finance_accounting import verify_paid_endpoint
        zero="0x"+"00"*32; one="0x"+"00"*31+"01"; leaf="0x"+"a7"*32
        anchors={i:{"Height":i,"BlockHash":[i]*32,"StateRoot":[i+1]*32} for i in (1,2)}
        block=lambda i:{"number":hex(i),"hash":"0x"+bytes(anchors[i]["BlockHash"]).hex(),"stateRoot":"0x"+bytes(anchors[i]["StateRoot"]).hex()}
        start=initial();end=initial();end["status"]={"Sequence":1}
        journal={"start":block(1),"end":block(2),"drained_target":1}
        class H:
            def call(self,op,**kw):
                if op=="projection-keys":return {"slots":[zero]}
                return start if kw["Slots"][zero]==zero else end
        class O:
            bad_nullifier=False;bad_wallet=False;boolean_nullifier=False;wrong_leaf=False
            def call(self,op,**kw):
                i=kw["Height"]
                if kw["Hash"]!=block(i)["hash"]:raise ValueError("fork")
                if op=="anchor":return {"anchor":anchors[i]}
                slots=kw["Keys"]
                if slots==[zero]:values={zero:zero if i==1 else one}
                else:values={k:zero if self.bad_nullifier else one if self.boolean_nullifier else "0x"+"a8"*32 if self.wrong_leaf else leaf for k in slots}
                balance=10 if i==1 else 20
                if self.bad_wallet:balance=10
                return {"anchor":anchors[i],"address":kw["Address"],"values":values,"balance":str(balance if not slots else 0)}
        class L:
            claims={"paid":{"nullifier_slot":"0x"+"03"*32,"claim_hash":leaf}};delta={A:10}
        with tempfile.TemporaryDirectory() as d:
            result=verify_paid_endpoint(H(),O(),journal,start,end,L(),Path(d))
            self.assertEqual((result["paid_nullifiers"],result["wallets"]),(1,1))
        for bad in ("bad_nullifier","boolean_nullifier","wrong_leaf","bad_wallet"):
            observer=O();setattr(observer,bad,True)
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):verify_paid_endpoint(H(),observer,journal,start,end,L(),Path(d))

    def test_paid_nullifier_retains_exact_leaf_and_rejects_conflicting_claim_id(self):
        from live_finance_accounting import paid_nullifiers
        slot="0x"+"03"*32; first={"nullifier_slot":slot,"claim_hash":"0x"+"a7"*32}
        self.assertEqual(paid_nullifiers({"first":first,"exact":dict(first)}),{slot:first["claim_hash"]})
        for bad in (dict(first,claim_hash="0x"+"a8"*32),dict(first,claim_hash="0x"+"00"*32)):
            with self.assertRaises(ValueError):paid_nullifiers({"first":first,"other":bad})

    def test_drain_finishes_only_started_cycle_and_records_authenticated_end(self):
        import time
        from live_finance import Runner
        r=object.__new__(Runner)
        r.state={"phase":3,"actions":[]};r.save=lambda:None;r.control=lambda:None;r.event=lambda *a,**kw:None
        r.statuses=lambda:[{"Certified":6,"Finalized":6}]*7
        r.certified=lambda:({},{"height":6})
        r.finalized=lambda height:({"Checkpoint":{"Sequence":height}}, {"height":height})
        phases=[]
        def step(record,parent,finalized):
            phases.append(r.state["phase"])
            r.state["phase"]=4 if r.state["phase"]==3 else 0
        r.economic_step=step
        r.submit=lambda *a,**kw:self.fail("unexpected new action after completed cycle")
        anchor={"Height":1100,"BlockHash":[1]*32,"StateRoot":[2]*32}
        account={"anchor":anchor,"projection":{"status":{"Sequence":6},"buckets":{"W":"0","R":"0"}}}
        class O:
            def advance(self):return None
            def call(self,op):return anchor
        r.observer=O()
        with tempfile.TemporaryDirectory() as d:
            r.path=Path(d);r.candidate=Path(d)
            r.submission_mode="historical-standalone"
            r.submission_status_paths=[]
            for i in range(2):
                p=r.candidate/f"runtime/relay-{i}";p.mkdir(parents=True)
                r.submission_status_paths.append(p/"status.json")
                (p/"status.json").write_text(json.dumps({"Version":1,"Devnet":True,"ObservedAt":int(time.time()),"Authenticated":{"CLXSequenceVerified":True,"CLXSequence":6,"DEXSequence":6},"Counts":{"complete":2},"TotalJobs":2}))
            block={"number":hex(1100),"hash":"0x"+"01"*32,"stateRoot":"0x"+"02"*32}
            def read(method,params):
                self.assertEqual((method,params),("eth_getBlockByNumber",[hex(1100),False]))
                return block
            r.helper=None
            with patch("live_finance.authenticated_projection",return_value=account),patch("live_finance.http",side_effect=read):r.drain()
            self.assertEqual(phases,[3,4])
            self.assertEqual(r.state["end"],block)
            self.assertTrue(r.state["native_paid_proof_verified"])

    def test_action_kind_is_logged_without_shadowing_event_name(self):
        from live_finance import Runner
        r=object.__new__(Runner)
        with tempfile.TemporaryDirectory() as d:
            r.path=Path(d)
            r.event('dex_certified',kind='oracle',height=2)
            event=json.loads((r.path/'events.jsonl').read_text())
            self.assertEqual((event['event'],event['kind'],event['height']),('dex_certified','oracle',2))

    def test_participation_interleaved_slot_can_commit_before_original_deadline(self):
        from live_finance import Runner
        r=object.__new__(Runner);r.active=list(range(7));r.state={}
        calls=[];r.submit=lambda *a,**kw:calls.append((a,kw))
        r.collect=lambda height,**kw: self.assertEqual(height,5) or [{"Duty":{"Participant":i,"Height":5,"View":1}} for i in range(5)]
        class H:
            def call(self,op,**kw):return []
        r.helper=H()
        market={"Frozen":False,"FeedSequence":1,"ValidUntil":100,"PendingFunding":0,"RewardPeriod":0}
        # h6 was consumed by an ordinary concurrent inbox action. h7 is still
        # inside the formal h14 cutoff, and finality drain must not skip it.
        self.assertTrue(r.maintenance_step({}, {"height":6,"market":market},4,close_rewards=False))
        self.assertEqual(calls[0][0][1],'commit-participation')
        calls.clear()
        with self.assertRaisesRegex(ValueError,'past authenticated deadline'):
            r.maintenance_step({}, {"height":14,"market":market},12)
        self.assertEqual(calls,[])

    def test_collection_unions_all_observed_exact_target_voters_not_all_online(self):
        from live_finance import Runner
        r=object.__new__(Runner);r.active=list(range(7));r.state={};r.event=lambda *a,**kw:None
        record={'authenticated':'target'};r.certified=lambda height:(record,{})
        responses=[]
        for i in range(7):
            voters=range(6) if i==6 else range(5)
            responses.append({'ReceiptErrors':0,'Certificates':[{'Duty':{'Participant':v,'Height':15,'View':148}} for v in voters]})
        class H:
            def call(self,op,**kw):
                if op!='select-certificates' or kw['Record']!=record:raise AssertionError('formal target verifier bypass')
                return kw['Certificates']
        r.helper=H()
        with patch('live_finance.web',side_effect=responses) as get:
            selected=r.collect(15)
        self.assertEqual(get.call_count,7)
        self.assertEqual([c['Duty']['Participant'] for c in selected],list(range(6)))

    def test_explicit_reward_hold_preserves_period_and_allows_normal_market_action(self):
        from live_finance import Runner
        from types import SimpleNamespace
        r=object.__new__(Runner);r.args=SimpleNamespace(continue_with_held_rewards=True)
        r.state={'phase':0,'cycle':0};r.keys={'trader-a':A};r.save=lambda:None
        events=[];r.event=lambda *a,**kw:events.append((a,kw))
        calls=[];r.submit=lambda *a,**kw:calls.append((a,kw))
        class H:
            def call(self,op,**kw):
                if op!='committed-certificates':raise AssertionError('reward close or late commit attempted')
                return []
        r.helper=H();r.collect=lambda *a,**kw: self.fail('late certificate collection')
        market={'Frozen':False,'FeedSequence':1,'ValidUntil':100,'PendingFunding':0,
                'RewardPeriod':0,'InboxCursor':4,'LastFunding':10}
        before=dict(market)
        r.economic_step({}, {'height':14,'market':market},14)
        self.assertEqual(market,before)
        self.assertEqual(calls[0][1]['Kind'],'place')
        self.assertEqual(r.state['held_reward_periods']['1']['certificate_count'],0)
        self.assertEqual(events[0][0],('reward_close_held',))
        calls.clear();market['Frozen']=True
        with self.assertRaisesRegex(ValueError,'FROZEN'):
            r.economic_step({}, {'height':15,'market':market},15)
        self.assertEqual(calls,[])

    def test_later_held_period_does_not_suppress_prior_provable_close(self):
        from live_finance import Runner
        from types import SimpleNamespace
        r=object.__new__(Runner);r.args=SimpleNamespace(continue_with_held_rewards=True)
        r.state={};r.save=lambda:None;r.event=lambda *a,**kw:None
        calls=[];r.submit=lambda *a,**kw:calls.append((a,kw))
        r.finalized=lambda h:({'Checkpoint':{'Sequence':h},'Proof':'unit'},None)
        class H:
            def call(self,op,**kw):
                if op=='committed-certificates':return list(range(5)) if kw['Period']==1 else []
                if op=='eligible-committed-certificates':return list(range(5))
                raise AssertionError(op)
        r.helper=H()
        market={'Frozen':False,'FeedSequence':1,'ValidUntil':100,'PendingFunding':0,'RewardPeriod':0}
        self.assertTrue(r.maintenance_step({}, {'height':24,'market':market},24))
        self.assertEqual(calls[0][0][1],'reward-close')
        self.assertEqual(calls[0][1]['Close']['Period'],1)
        self.assertIn('2',r.state['held_reward_periods'])

    def test_later_valid_participant_is_committed_before_original_deadline(self):
        from live_finance import Runner
        r=object.__new__(Runner);r.active=list(range(7));r.state={}
        calls=[];r.submit=lambda *a,**kw:calls.append((a,kw))
        cert=lambda h,p:{'Duty':{'Height':h,'View':1,'Participant':p}}
        class H:
            def call(self,op,**kw):return [cert(5 if kw['Period']==1 else 15,i) for i in range(5)]
        r.helper=H();r.collect=lambda h,**kw:[cert(h,i) for i in range(6)]
        market={'Frozen':False,'FeedSequence':1,'ValidUntil':100,'PendingFunding':0,'RewardPeriod':0}
        self.assertTrue(r.maintenance_step({}, {'height':16,'market':market},0))
        self.assertEqual(calls[0][0][1],'commit-participation')
        self.assertEqual(len(calls[0][1]['Certificates']),6)

    def test_partial_interval_does_not_mark_original_run_drained(self):
        from live_finance_accounting import partial_interval
        original={'status':'STOPPED_WITH_JOURNAL_PRESERVED','start':{'number':'0x400'},'transactions':{},'actions':[]}
        before=json.dumps(original,sort_keys=True)
        anchor={'Height':1100,'BlockHash':[1]*32,'StateRoot':[2]*32}
        block={'number':hex(1100),'hash':'0x'+'01'*32,'stateRoot':'0x'+'02'*32}
        observed=partial_interval(original,anchor,block)
        self.assertEqual(json.dumps(original,sort_keys=True),before)
        self.assertNotIn('end',original)
        self.assertNotIn('drained_target',observed)
        self.assertEqual(observed['status'],'STOPPED_WITH_JOURNAL_PRESERVED')
        self.assertEqual(observed['end'],block)

    def test_observer_cli_relative_run_is_absolute_without_resolving_links(self):
        from live_finance import SourceObserver
        class P:
            pass
        with patch('live_finance.subprocess.Popen',return_value=P()) as spawn:
            SourceObserver(Path('/tmp/helper'),Path('manifest.json'),Path('build/stage/live-finance-fixture/source-observer'))
        command=spawn.call_args[0][0]
        self.assertTrue(Path(command[2]).is_absolute())
        self.assertTrue(Path(command[4]).is_absolute())
        self.assertEqual(command[4],str(Path('build/stage/live-finance-fixture/source-observer').absolute()))

class LeaderSubmissionLayoutTest(unittest.TestCase):
    def test_member_submission_directories_are_distinct_and_bound(self):
        from live_finance import submission_paths
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); configs=[]; participants=[]
            for i in range(7):
                path=root/f"member-{i}.json"
                data=root/f"member-{i}/dex"
                member={"DEXDataDir":str(data),"API":f"127.0.0.1:{19000+i}","SubmissionConfig":str(path)}
                path.write_text(json.dumps({"DataDir":str(data/"submission"),"DEXURL":"http://"+member["API"]}))
                configs.append(str(path));participants.append(member)
            inv={"LeaderSubmissionConfigs":configs,"Participants":participants}
            mode, paths=submission_paths(inv,root)
            self.assertEqual(mode,"leader");self.assertEqual(len(set(paths)),7)
            bad=json.loads(Path(configs[6]).read_text());bad["DataDir"]=str(paths[0].parent)
            Path(configs[6]).write_text(json.dumps(bad))
            with self.assertRaises(ValueError):submission_paths(inv,root)

    def test_business_settled_is_distinct_from_old_sender_nonce_queue(self):
        from live_finance import submission_accepted, relay_drained
        status={"Version":1,"Devnet":True,"ObservedAt":100,"LeaderIntegrated":True,
                "Authenticated":{"CLXSequenceVerified":True,"CLXSequence":19,"DEXSequence":20},
                "Counts":{"complete":1,"signed":1},"TotalJobs":2}
        self.assertTrue(submission_accepted(status,19,105))
        self.assertFalse(relay_drained(status,19,105))
        for change in ({"ObservedAt":90},{"Authenticated":{"CLXSequenceVerified":False,"CLXSequence":19,"DEXSequence":20}},
                       {"Authenticated":{"CLXSequenceVerified":True,"CLXSequence":18,"DEXSequence":20}}):
            self.assertFalse(submission_accepted(dict(status,**change),19,105))

    def test_integrated_drain_uses_native_proof_despite_old_sender_queue(self):
        import time
        from live_finance import Runner
        r=object.__new__(Runner)
        r.state={"phase":0,"actions":[]};r.save=lambda:None;r.control=lambda:None
        events=[];r.event=lambda *a,**kw:events.append((a,kw))
        r.statuses=lambda:[{"Certified":6,"Finalized":6}]*7
        r.certified=lambda:({},{"height":6})
        r.finalized=lambda height:({"Checkpoint":{"Sequence":height}}, {"height":height})
        r.submission_mode="leader"
        anchor={"Height":1100,"BlockHash":[1]*32,"StateRoot":[2]*32}
        account={"anchor":anchor,"projection":{"status":{"Sequence":6},"buckets":{"W":"0","R":"0"}}}
        class O:
            def advance(self):return None
            def call(self,op):return anchor
        r.observer=O();r.helper=None
        with tempfile.TemporaryDirectory() as d:
            r.path=Path(d);r.candidate=Path(d)
            r.submission_status_paths=[Path(d)/f"status-{i}.json" for i in range(7)]
            for i in (0,1):
                r.submission_status_paths[i].write_text(json.dumps({"Version":1,"Devnet":True,"ObservedAt":int(time.time()),
                    "Authenticated":{"CLXSequenceVerified":True,"CLXSequence":6,"DEXSequence":6},
                    "Counts":{"complete":1,"signed":1},"TotalJobs":2}))
            block={"number":hex(1100),"hash":"0x"+"01"*32,"stateRoot":"0x"+"02"*32}
            with patch("live_finance.authenticated_projection",return_value=account),patch("live_finance.http",return_value=block):
                r.drain()
            self.assertTrue(r.state["native_paid_proof_verified"])
            self.assertEqual(r.state["drained_target"],6)
            self.assertFalse(events[-1][1]["local_queues_drained"])
            self.assertEqual(events[-1][1]["submission_pending_counts"],[{"complete":1,"signed":1}]*2)
            r.observer=None
            with self.assertRaisesRegex(ValueError,"independent authenticated CLX observer"):
                r.drain()

class PlanCommandTest(unittest.TestCase):
    def test_plan_report_total_matches_seven_member_payer_plan(self):
        import contextlib
        import io
        from live_finance import main
        purposes = ["trader-a","trader-b","support-owner","insurance-owner","synthetic-oracle"]
        purposes += [f"submission-{i}-{lane}-gas" for i in range(7) for lane in ("anchor","checkpoint","claim")]
        configs=[f"submission-{i}" for i in range(7)]
        inventory={"LeaderSubmissionConfigs":configs,"Participants":[{"SubmissionConfig":p} for p in configs],
                   "Keys":[{"Purpose":p,"Address":"0x"+f"{i+1:040x}"} for i,p in enumerate(purposes)]}
        class OfflineRunner:
            identity={"chain_id":10101919}
            plan=funding_plan(inventory)
            def close(self): pass
        with tempfile.TemporaryDirectory() as d:
            args=["live_finance.py","plan","--helper","/not-opened","--output",d]
            output=io.StringIO()
            with patch("sys.argv",args),patch("live_finance.Runner",return_value=OfflineRunner()),contextlib.redirect_stdout(output):
                main()
            report=json.loads((Path(d)/"plan.json").read_text())
            self.assertEqual(report,json.loads(output.getvalue()))
            self.assertEqual(report["status"],"NOT_RUN")
            self.assertEqual(int(report["total_funding_atoms"]),sum(int(item["atoms"]) for item in report["funding"]))
            self.assertEqual(report["total_funding_atoms"],str(294*ATOM))
            self.assertEqual(report["initial_custody_atoms"],str(225*ATOM))
            self.assertFalse((Path(d)/"journal.json").exists())

class ColdRecordedActionTest(unittest.TestCase):
    def runner(self):
        import base64
        from live_finance import Runner
        r=object.__new__(Runner)
        item={"id":"aa"*32,"raw":"0x"+b"already-certified-noop".hex(),"kind":"noop","nonce":11,
              "predicted_height":12,"predicted_root":"0xexpected","transition":{},"stage":"signed_not_sent"}
        r.state={"actions":[],"pending_action":item};r.primary=19000
        r.saved=[];r.save=lambda:r.saved.append(json.loads(json.dumps(r.state)))
        r.event=lambda *a,**kw:None
        r.statuses=lambda:[{"Certified":13}]*7
        record={"Actions":base64.b64encode(bytes.fromhex(item["raw"][2:])).decode()}
        r.certified=lambda h:(record,{"root":"0xexpected"}) if h==12 else self.fail("unexpected height")
        return r,item

    def test_cold_already_certified_action_is_authenticated_before_stale_nonce_post(self):
        from urllib.error import HTTPError
        r,item=self.runner()
        with patch("live_finance.web",side_effect=HTTPError("local",400,"nonce already consumed",{},None)) as post:
            r.resume_action()
        post.assert_not_called()
        self.assertNotIn("pending_action",r.state)
        self.assertEqual(len(r.state["actions"]),1)
        self.assertEqual(r.state["actions"][0]["nonce"],11)
        self.assertEqual(r.saved[-1]["actions"][0]["certified_height"],12)
        self.assertEqual(r.saved[-1]["actions"][0]["stage"],"certified_not_finalized")
        self.assertNotIn("ack_ns",r.saved[-1]["actions"][0])
        r.resume_action()
        self.assertEqual(len(r.state["actions"]),1)

    def test_certification_racing_post400_requires_exact_authenticated_record(self):
        from urllib.error import HTTPError
        r,item=self.runner();calls=iter((11,12))
        r.statuses=lambda:[{"Certified":next(calls)}]
        with patch("live_finance.web",side_effect=HTTPError("local",400,"nonce already consumed",{},None)) as post:
            r.resume_action()
        self.assertEqual(post.call_count,1)
        self.assertNotIn("pending_action",r.state)
        self.assertEqual(r.state["actions"][0]["raw"],item["raw"])

    def test_bad_authenticated_root_never_completes_or_rewrites_pending_intent(self):
        r,item=self.runner();before=json.loads(json.dumps(item))
        record,actual=r.certified(12)
        r.certified=lambda h:(record,{"root":"0xwrong"})
        with patch("live_finance.web",side_effect=AssertionError("must not post")):
            with self.assertRaisesRegex(ValueError,"unexpected root"):r.resume_action()
        self.assertEqual(r.state["pending_action"],before)
        self.assertEqual(r.state["actions"],[])
        self.assertEqual(r.saved,[])


class SettlementOnlyRecoveryTest(unittest.TestCase):
    def runner(self):
        import base64
        from types import SimpleNamespace
        from live_finance import Runner
        r=object.__new__(Runner)
        r.args=SimpleNamespace(settlement_target=15)
        r.state={"phase":0,"actions":[{"kind":"withdraw","certified_height":14}]}
        r.saved=[];r.save=lambda:r.saved.append(json.loads(json.dumps(r.state)))
        r.event=lambda *a,**kw:None
        r.waited=[];r.wait_settlement=lambda target:r.waited.append(target)
        r.statuses=lambda:[{"Certified":16,"Finalized":15}]*7
        raw=b"\x00\x01"+b"x"*32+b"\x00"+b"x"*(282-35)
        item={"kind":"noop","id":"fixture-id","raw":"0x"+raw.hex(),"predicted_height":16,
              "predicted_root":"0x16","transition":{},"stage":"certified_not_finalized","certified_height":16}
        records={15:({"Checkpoint":{"Sequence":15,"PostRoot":[15]*32}},{"height":15,"root":"0x15"}),
                 16:({"Actions":base64.b64encode(raw).decode(),"Checkpoint":{"Sequence":16,"PreRoot":[15]*32,"PostRoot":[16]*32}},
                     {"height":16,"root":"0x16"})}
        r.certified=lambda height=None:records[height or 16]
        r.finalized=lambda height:({"Checkpoint":{"Sequence":height}}, {"height":height,"checkpoint_hash":"0x"+"15"*32,"root":"0x"+"0f"*32})
        class H:
            def call(self,op,**kw):
                assert op=="execute-signed"
                return {"height":16,"root":"0x16"}
        r.helper=H()
        forbidden=lambda *a,**kw:self.fail("settle must not submit, resume, maintain, trade or fund")
        r.submit=r.resume_action=r.maintenance_step=r.economic_step=r.fund=forbidden
        return r,item

    def test_settle_authenticates_existing_noop_and_never_posts(self):
        r,item=self.runner();r.state["pending_action"]=item
        with patch("live_finance.web",side_effect=AssertionError("no POST")):
            r.settle()
        self.assertNotIn("pending_action",r.state)
        self.assertEqual(r.state["actions"][-1]["certified_height"],16)
        self.assertEqual(r.state["settlement_target"],15)
        self.assertEqual(r.waited,[15])

    def test_settle_unmatched_pending_retains_intent_without_post(self):
        r,item=self.runner();r.state["pending_action"]=item
        r.reconcile_recorded_action=lambda item:False
        with patch("live_finance.web",side_effect=AssertionError("no POST")):
            with self.assertRaisesRegex(ValueError,"never posts"):
                r.settle()
        self.assertIs(r.state["pending_action"],item)
        self.assertNotIn("settlement_target",r.state)
        self.assertEqual(r.waited,[])

    def test_settle_refuses_open_cycle_and_unfinalized_target(self):
        r,_=self.runner();r.state["phase"]=2
        with self.assertRaisesRegex(ValueError,"completed trading cycle"):r.settle()
        r.state["phase"]=0
        def reject(height):raise ValueError("FHS finality unavailable")
        r.finalized=reject
        with self.assertRaisesRegex(ValueError,"FHS finality unavailable"):r.settle()
        self.assertNotIn("settlement_target",r.state)
        self.assertEqual(r.waited,[])

    def test_settle_rejects_wrong_finalized_height_and_skipped_financial_action(self):
        r,_=self.runner()
        r.finalized=lambda height:({"Checkpoint":{"Sequence":14}},{"height":14})
        with self.assertRaisesRegex(ValueError,"proof differs"):r.settle()
        r,_=self.runner();r.state["actions"].append({"kind":"funding","certified_height":16})
        with self.assertRaisesRegex(ValueError,"omit a recorded financial action"):r.settle()
        self.assertNotIn("settlement_target",r.state)
        self.assertEqual(r.waited,[])

    def test_settle_noop_label_cannot_hide_another_signed_action(self):
        r,item=self.runner();raw=bytearray.fromhex(item["raw"][2:]);raw[34]=3
        item["raw"]="0x"+raw.hex();r.state["actions"].append(item)
        with self.assertRaisesRegex(ValueError,"not a current signed Noop"):r.settle()
        self.assertEqual(r.waited,[])

    def test_settle_authenticates_tail_exact_bytes_parent_and_reexecution(self):
        for failure in ("bytes","parent","replay"):
            with self.subTest(failure=failure):
                r,item=self.runner();r.state["actions"].append(item)
                record,verified=r.certified(16)
                if failure=="bytes":record["Actions"]="AA=="
                elif failure=="parent":record["Checkpoint"]["PreRoot"]=[99]*32
                else:r.helper.call=lambda *a,**kw:{"height":16,"root":"0xbad"}
                with self.assertRaises(ValueError):r.settle()
                self.assertNotIn("settlement_target",r.state)
                self.assertEqual(r.waited,[])

    def test_settle_target_is_explicit_and_durable_across_retry(self):
        r,_=self.runner();r.args.settlement_target=None
        with self.assertRaisesRegex(ValueError,"explicit positive"):r.settle()
        r.args.settlement_target=15
        def timeout(target):raise ValueError("finite drain deadline")
        r.wait_settlement=timeout
        with self.assertRaisesRegex(ValueError,"finite drain"):r.settle()
        self.assertEqual(r.saved[-1]["settlement_target"],15)
        r.args.settlement_target=16
        with self.assertRaisesRegex(ValueError,"durable previous intent"):r.settle()
        r.args.settlement_target=15;r.wait_settlement=lambda target:r.waited.append(target)
        r.settle();self.assertEqual(r.waited,[15])

    def test_drain_persists_target_before_descendant_and_reuses_after_crash(self):
        from live_finance import Runner
        r,_=self.runner();r.resume_action=lambda:None;r.control=lambda:None
        r.statuses=lambda:[{"Certified":15,"Finalized":14}]*7
        r.certified=lambda height=None:({}, {"height":15})
        r.maintenance_step=lambda *a,**kw:False
        def crash(*a,**kw):
            self.assertEqual(r.saved[-1]["settlement_target"],15)
            raise ValueError("selected descendant observation unavailable")
        r.submit=crash
        with self.assertRaisesRegex(ValueError,"descendant observation unavailable"):Runner.drain(r)
        r.statuses=lambda:[{"Certified":18,"Finalized":15}]*7
        r.certified=lambda height=None:({}, {"height":18})
        Runner.drain(r)
        self.assertEqual(r.waited,[15])
        self.assertEqual(r.state["settlement_target"],15)

    def test_shared_settlement_wait_is_finite_without_dex_input(self):
        from live_finance import Runner
        r,_=self.runner();r.submission_status_paths=[];r.observer=None
        r.submission_mode="historical-standalone";controls=[];r.control=lambda:controls.append(1)
        with patch("live_finance.time.monotonic",side_effect=[0,1,181]),patch("live_finance.time.sleep"):
            with self.assertRaisesRegex(ValueError,"finite drain deadline"):
                Runner.wait_settlement(r,15)
        self.assertEqual(controls,[1]);self.assertNotIn("drained_target",r.state)

    def test_settle_tail_must_descend_from_exact_finalized_target_root(self):
        r,item=self.runner();r.state["actions"].append(item)
        r.finalized=lambda height:({"Checkpoint":{"Sequence":height}}, {"height":height,"root":"0x"+"ff"*32})
        with self.assertRaisesRegex(ValueError,"differs from finalized target root"):r.settle()
        self.assertNotIn("settlement_target",r.state)
        self.assertEqual(r.waited,[])

    def test_settle_gap_chain_cannot_hide_a_disconnected_intermediate_parent(self):
        import base64
        r,item=self.runner();item["certified_height"]=18;r.state["actions"].append(item)
        records={height:r.certified(height) for height in (15,16)}
        records[17]=({"Checkpoint":{"Sequence":17,"PreRoot":[99]*32,"PostRoot":[17]*32}},
                     {"height":17,"root":"0x17"})
        records[18]=({"Actions":base64.b64encode(bytes.fromhex(item["raw"][2:])).decode(),
                      "Checkpoint":{"Sequence":18,"PreRoot":[17]*32,"PostRoot":[18]*32}},
                     {"height":18,"root":"0x18"})
        r.certified=lambda height:records[height]
        r.helper.call=lambda *a,**kw:{"height":18,"root":"0x18"}
        with self.assertRaisesRegex(ValueError,"selected parent differs"):r.settle()
        self.assertNotIn("settlement_target",r.state)
        self.assertEqual(r.waited,[])

    def test_settle_retry_cannot_replace_finalized_checkpoint_at_same_height(self):
        r,_=self.runner();r.settle()
        before=json.loads(json.dumps(r.state["settlement_checkpoint"]))
        r.finalized=lambda height:({"Checkpoint":{"Sequence":height}},
                                  {"height":height,"checkpoint_hash":"0x"+"16"*32,"root":"0x"+"ee"*32})
        with self.assertRaisesRegex(ValueError,"checkpoint differs from durable previous intent"):r.settle()
        self.assertEqual(r.state["settlement_checkpoint"],before)
        self.assertEqual(r.waited,[15])
