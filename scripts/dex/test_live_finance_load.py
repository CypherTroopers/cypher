import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from live_finance import Runner, SOURCE, ATOM
from live_finance_load import summary, transaction_cost, observe_phase

ORACLE="0x"+"11"*20
HASH="0x"+"22"*32

class LiveLoadTest(unittest.TestCase):
    def test_censored_rejected_and_slow_arrivals_stay_in_denominator(self):
        records=[{"stage":"authenticated_finalized","scheduled_ns":0,"submit_ns":0,"finalized_ns":10**9,"receipt":{"status":"0x1"}},
                 {"stage":"authenticated_finalized","scheduled_ns":0,"submit_ns":2*10**9,"finalized_ns":100*10**9,"receipt":{"status":"0x0"}},
                 {"stage":"submitted","scheduled_ns":0,"submit_ns":10**9},
                 {"stage":"not_issued_backpressure","scheduled_ns":0}]
        result=summary(records)
        self.assertEqual((result["scheduled"],result["completed"],result["rejected"],result["unresolved"]),(4,2,1,1))
        self.assertEqual(result["completion_rate"],.5)
        self.assertEqual(result["scheduled_to_authenticated_finality_seconds"]["p99"],100)
        self.assertEqual((result["successful_completed"],result["reverted_completed"]),(1,1))

    def test_gas_cost_includes_failed_tx_and_rejects_wrong_receipt(self):
        receipt={"transactionHash":HASH,"from":ORACLE,"status":"0x0","gasUsed":"100","commonTxApproverReward":"20","commonTxBurn":"80"}
        item={"hash":HASH,"sender":ORACLE,"gas_price":"1","receipt":receipt}
        cost=transaction_cost([item,{"hash":"pending"}])
        self.assertEqual((cost["gas_atoms"],cost["common_reward_atoms"],cost["burn_atoms"],cost["receipt_missing"]),("100","20","80",1))
        for change in ({"transactionHash":"other"},{"commonTxBurn":"0"},{"effectiveGasPrice":"2"}):
            with self.assertRaises(ValueError):transaction_cost([dict(item,receipt=dict(receipt,**change))])

    def test_load_control_does_not_use_financial_funding_source_nonce(self):
        r=object.__new__(Runner)
        r.control_purpose="synthetic-oracle";r.keys={"synthetic-oracle":ORACLE};r.state={"transactions":{}}
        r.last_head="head";r.last_head_progress=time.monotonic()-10;r.last_control=0
        calls=[];r.tx=lambda *a:calls.append(a)
        with patch("live_finance.http",return_value={"hash":"head"}):r.control()
        self.assertEqual(calls,[("control-0000","synthetic-oracle",SOURCE,1)])

    def test_load_nonce_intent_is_fsynced_before_send_and_stays_owned(self):
        r=object.__new__(Runner);r.keys={"synthetic-oracle":ORACLE};r.state={"transactions":{}}
        r.guard=lambda:None;r.event=lambda *a,**kw:None
        saved=[];r.save=lambda:saved.append(bool(r.state["transactions"]))
        class H:
            def call(self,op,**kw):
                if op=="sign-tx":return {"raw":"owned-public-tx"}
                if op=="verify-tx":return {"sender":ORACLE,"to":SOURCE,"value":"1","nonce":5,"gas":100000,"gas_price":"1000000000","data":"0x","hash":HASH}
                raise AssertionError(op)
        r.helper=H();queries=[]
        def rpc(method,params):
            queries.append((method,params))
            if method=="eth_getTransactionCount":
                self.assertEqual(params[0],ORACLE);return "0x5"
            if method=="eth_getBalance":
                self.assertEqual(params[0],ORACLE);return hex(ATOM)
            if method in ("eth_getTransactionReceipt","eth_getTransactionByHash"):return None
            if method=="eth_sendRawTransaction":
                self.assertEqual(saved,[True]);self.assertEqual(params,["owned-public-tx"]);return HASH
            raise AssertionError(method)
        with patch("live_finance.http",side_effect=rpc):r.tx("benchmark-A-0000","synthetic-oracle",SOURCE,1)
        self.assertEqual(r.state["transactions"]["benchmark-A-0000"]["nonce"],5)
        self.assertEqual(r.state["transactions"]["benchmark-A-0000"]["stage"],"rpc_ack_not_finality")

    def test_financial_journal_reuse_is_rejected_before_network(self):
        r=object.__new__(Runner);r.state={"funded":True,"actions":[]}
        with patch("live_finance_load.http",side_effect=AssertionError("network before ownership")):
            with self.assertRaisesRegex(ValueError,"own journal"):observe_phase(r,None)

if __name__=="__main__":unittest.main()
