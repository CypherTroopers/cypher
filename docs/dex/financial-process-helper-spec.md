# Financial process fixture protocol (devnet only)

This specification is fixed before the helper implementation. `dex/devnet/testnet`
is an explicitly invoked test utility. It is not a public operator bootstrap API.
Each child creates its own persisted BLS secret and Ed25519 TLS key in a new marked
directory, returns only its registered public identity, and then receives trusted
genesis/committee configuration through its parent's private stdin pipe. The
CLX verifier authenticates that configuration against the CLX genesis commitment.
No trader secrets or operational keys are sent to a child.

The native CLX network fixture generates its key genesis with the same
`core.GenesisKey` JSON decoding, `ToBlock` body construction and committee-hash
assignment as ordinary CLI `init`. Its seven child processes explicitly opt into
that fixture path through the private test command's `NormalKeyGenesis` field;
older reward/recovery fixtures retain their previous synthetic key genesis.
The native fixture checks each child's key hash against the parent's normal key
genesis. A matching transaction genesis alone is insufficient for ordinary Common
ETH synchronization when the key genesis/body differs. The trusted native proof
epoch and the DEX-OFF sync helper use this same canonical fixture key. No production
genesis codec, operational genesis or committee rule is changed by this fixture.

New node i fixtures allocate both listener and HTTP endpoint on the dedicated
loopback IP 127.0.0.(i+2), with random ports persisted in the existing identity.
The normal transport uses that registered listener IP for outgoing sockets with
ephemeral source ports. TLS registration remains the identity authority. Existing
marked fixtures retain their original addresses; restart does not rewrite them.
The normal-CLI test wrapper can therefore impose real packet drops between these
addresses inside its newly created network namespace, while parent HTTP and CLX
traffic on 127.0.0.1 remain independent. This requires no public fault endpoint.

All financial execution, receipt issuance, FHS signing, TLS extension validation
and certified-data import run on the same service actor. Control input is bounded
JSON (2 MiB per line); output uses `DEXCTL ` plus one bounded JSON object. Control
operations are init, action, status, checkpoint, partition, repair and shutdown.
Partition changes only the receive filter; the transport still uses real TLS
sockets. The parent may kill/restart only children it owns. Restart restores the
same identity, action queue, collector, FHS watermark and transport outbox.

The fixture action queue commits exact height/payload pairs before ACK, rejects
conflicting replacement, and is bounded to128 entries/1 MiB raw bytes. Admission
authenticates signatures/domain or actual CLX evidence; proposal execution again
checks the correct parent, nonce and accounting. Missing actions pause proposals
at that height. They do not stop the CLX domain. Reward-close actions are optional;
missing reward evidence cannot make ordinary signed market actions unavailable.
The child publishes a separate numeric-loopback HTTP API address in its identity.
`POST /v1/actions` uses height:u64 big endian followed by the authenticated action;
the fixture's control `action` command itself sends that HTTP request. A newly
durable action is propagated over TLS kind2, with exact duplicate suppression.
No parent-pipe action directly inserts into an actor queue as a claimed network test.

TLS extension payloads have canonical bytes: `CDXEXT01`:8, kind:u8, body. Kinds:
1=observed prepare vote: ref length:u16, ref:1..2048, RLP vote length:u32,
vote:1..8192; 2=receipt:226 bytes; 3=certificate:bounded existing codec (5..7
collectors); 4=data request:after height:u64; 5=certified record:canonical existing
JSON, 1..131063 bytes. Limits apply before RLP/JSON/cryptographic processing.
Transport binds sender/domain/epoch/registry. Vote extensions additionally require
the prepare vote identity/public key to equal their TLS sender. Receipt/certificate
signatures are independently checked against the registered committee.

The independent Python fixture covers extension framing and data-request endianness;
real signed vote/receipt/certificate validity remains a Go integration test.
Collectors issue receipts only after their own validated-vote hook and before their
next-child vote; collector WAL is fsynced first. The scenario holds action6 until
all seven action5 participation certificates have5/7 receipts and are retained by
the honest collectors. This explicit fixture delivery schedule is not a claim of
unconditional censorship resistance or WAN liveness.

Certified-data repair requests one record at a time and calls the ordinary
authenticated import/re-execution path. It never copies another voter's safety
watermark. Missing parent is retryable; over-budget data is explicitly unavailable.
The parent uses checkpoint+proof+state output for separate CLX settlement calls;
an ingress ACK never implies CLX settlement.
