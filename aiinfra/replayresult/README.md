# Durable replay results

`replayresult` freezes the adapter-neutral digest and size boundary for a CCSE
durable result. The raw replay key remains the authoritative lookup key; the
result digest binds the exact visible-ASCII content type and payload bytes.

This package proves content integrity only. A semantic kernel must additionally
use a closed catalog of successful content types and validate the canonical
payload for its operation. An arbitrary non-zero result digest is never proof
that the source mutation succeeded.
