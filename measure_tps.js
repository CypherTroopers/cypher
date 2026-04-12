function measureTPS(start, end, nonEmptyOnly) {
  if (start === undefined || end === undefined) {
    throw "start and end are required";
  }
  if (end <= start) {
    throw "end must be greater than start";
  }

  var totalTx = 0;
  var countedBlocks = 0;
  var emptyBlocks = 0;
  var missingBlocks = 0;

  var firstBlock = eth.getBlock(start);
  var lastBlock = eth.getBlock(end);

  if (!firstBlock) throw "start block not found";
  if (!lastBlock) throw "end block not found";

  for (var i = start; i <= end; i++) {
    var b = eth.getBlock(i);
    if (!b) {
      missingBlocks++;
      continue;
    }

    var txCount = b.transactions ? b.transactions.length : 0;

    if (txCount === 0) {
      emptyBlocks++;
      if (!nonEmptyOnly) countedBlocks++;
      continue;
    }

    totalTx += txCount;
    countedBlocks++;
  }

  var seconds = lastBlock.timestamp - firstBlock.timestamp;
  if (seconds <= 0) throw "invalid time range";

  var tps = totalTx / seconds;

  console.log("====================================");
  console.log("startBlock     =", start);
  console.log("endBlock       =", end);
  console.log("seconds        =", seconds);
  console.log("totalTx        =", totalTx);
  console.log("countedBlocks  =", countedBlocks);
  console.log("emptyBlocks    =", emptyBlocks);
  console.log("missingBlocks  =", missingBlocks);
  console.log("TPS            =", tps);
  console.log("nonEmptyOnly   =", !!nonEmptyOnly);
  console.log("====================================");

  return {
    startBlock: start,
    endBlock: end,
    seconds: seconds,
    totalTx: totalTx,
    countedBlocks: countedBlocks,
    emptyBlocks: emptyBlocks,
    missingBlocks: missingBlocks,
    tps: tps,
    nonEmptyOnly: !!nonEmptyOnly
  };
}
