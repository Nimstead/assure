# What an evidence signature proves

An evidence pack lets a reviewer check exported records without contacting the Assure server. Its signature protects the exact pack bytes. Ledger hashes and signed checkpoints expose inconsistent or shortened history.

## The key must be trusted separately

A public key inside a pack is not, by itself, a trust anchor. Someone who can replace both the pack and its key can create a different valid signature. The reviewer needs the expected fingerprint through a separate trusted channel.

## Integrity and completeness are different

A valid signature establishes integrity under the accepted key. It does not establish that every host reported, every check ran, or every control was satisfied. Coverage and time period remain part of the review.

Restoring an old database can remove later ledger entries. Checkpoints outside that database can reveal the shortening. The warning may describe a legitimate recovery, but the missing period must still be explained.

See [export evidence](../how-to/export-evidence.md), [verify a pack](../how-to/verify-evidence.md), and [restore a backup](../how-to/restore.md).
