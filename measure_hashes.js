function measureMinedTPS(hashes) {
  if (!hashes || !hashes.length) throw "hashes[] required";

  var mined = [];
  var pending = 0;
  var failed = 0;

  for (var i = 0; i < hashes.length; i++) {
    try {
      var tx = eth.getTransaction(hashes[i]);
      if (!tx) {
        failed++;
        continue;
      }
      if (tx.blockNumber === null || tx.blockNumber === undefined) {
        pending++;
        continue;
      }
      mined.push(tx.blockNumber);
    } catch (e) {
      failed++;
    }
  }

  if (!mined.length) {
    console.log("no mined tx found");
    return {
      mined: 0,
      pending: pending,
      failed: failed
    };
  }

  mined.sort(function(a, b) { return a - b; });

  var startBlockNum = mined[0];
  var endBlockNum = mined[mined.length - 1];

  var startBlock = eth.getBlock(startBlockNum);
  var endBlock = eth.getBlock(endBlockNum);

  var seconds = endBlock.timestamp - startBlock.timestamp;
  if (seconds <= 0) seconds = 1;

  var tps = mined.length / seconds;

  console.log("====================================");
  console.log("minedTx        =", mined.length);
  console.log("pendingTx      =", pending);
  console.log("failedLookup   =", failed);
  console.log("startBlock     =", startBlockNum);
  console.log("endBlock       =", endBlockNum);
  console.log("seconds        =", seconds);
  console.log("TPS            =", tps);
  console.log("====================================");

  return {
    mined: mined.length,
    pending: pending,
    failed: failed,
    startBlock: startBlockNum,
    endBlock: endBlockNum,
    seconds: seconds,
    tps: tps
  };
}
