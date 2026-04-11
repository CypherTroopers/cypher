function nowTs() {
  return (new Date()).toISOString();
}

function spamNativeSingle(from, password, to, rounds, valueWei, gas, gasPriceWei, unlockSeconds, printEvery) {
  from = from || "0x864bacd8a9a7289b60a1e3de5a69cde87ad32e81";
  to = to || "0x380Ae1a000eb03930bb2F64d4A75dfE54b3e7e18";
  rounds = rounds || 100;
  valueWei = valueWei || "1";
  gas = gas || 21000;
  gasPriceWei = gasPriceWei || "1000000000";
  unlockSeconds = unlockSeconds || 3600;
  printEvery = printEvery || 20;

  var ok = personal.unlockAccount(from, password, unlockSeconds);
  if (!ok) throw "unlock failed";

  var balance = eth.getBalance(from);
  console.log("[" + nowTs() + "] from      =", from);
  console.log("[" + nowTs() + "] to        =", to);
  console.log("[" + nowTs() + "] balance   =", balance.toString(10));
  console.log("[" + nowTs() + "] rounds    =", rounds);

  var startBlock = eth.blockNumber;
  var sent = 0;
  var failed = 0;
  var hashes = [];

  console.log("[" + nowTs() + "] startBlock =", startBlock);

  for (var i = 0; i < rounds; i++) {
    try {
      var h = eth.sendTransaction({
        from: from,
        to: to,
        value: valueWei,
        gas: gas,
        gasPrice: gasPriceWei
      });
      hashes.push(h);
      sent++;

      if (sent % printEvery === 0) {
        console.log("[" + nowTs() + "] sent =", sent, " lastHash =", h);
      }
    } catch (e) {
      failed++;
      console.log("[" + nowTs() + "] ERROR i=" + i + " err=" + String(e));
    }
  }

  var endBlock = eth.blockNumber;

  console.log("[" + nowTs() + "] endBlock =", endBlock);
  console.log("[" + nowTs() + "] sent     =", sent);
  console.log("[" + nowTs() + "] failed   =", failed);

  return {
    startBlock: startBlock,
    endBlock: endBlock,
    sent: sent,
    failed: failed,
    hashes: hashes
  };
}
