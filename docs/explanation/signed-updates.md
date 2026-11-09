# Why agent updates are signed

The server distributes agents, but an enrolled agent accepts an update only when a pinned Nimstead release key signed it. The signed manifest binds the code and release channel.

## The first installation is different

The initial installer and agent arrive from the operator's server. A compromised server could alter that first copy. An already enrolled agent checks later updates against its pinned keys.

Independent verification closes that initial trust gap. The operator can compare the release signature and hashes before installation. The [verification guide](../how-to/verify-agent-release.md) gives the steps.

## An update must also run

After verification, the agent tests the new code's inventory on the host before switching. If that test fails, it keeps the old version. The previous file remains available beside the installed agent.

Release channels constrain which signed releases a host accepts. A stable host should not accept a less-proven preview merely because a server offers it.

The signature does not protect an already compromised host from a local administrator. Host permissions, trusted verification tools, and key custody remain necessary.
