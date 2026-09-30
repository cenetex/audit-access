# audit-access

Requests for reviewer access to RATi audits.

A RATi audit report is sealed for a short list of Solana wallets. If you want to review one,
you ask by opening a pull request here. The request is public and comes from your GitHub
account, so a maintainer can see who is asking and can comment on the pull request.

## How to ask

1. Open the audit's locked page and connect the wallet you want to review with.
2. If it is not a recipient yet, press **Request access**. Your wallet signs two short
   messages (nothing on chain, no funds), and the page opens GitHub with your request filled in.
3. Press **Propose new file**, then **Create pull request**. Add a comment saying who you are
   and why you want to review it.

The file is `requests/<your wallet address>.json`. It holds your wallet address, the public
key you will open the report with, and your signature proving the wallet is yours. It is all
public data. **Use a fresh wallet if you do not want your main wallet tied to your GitHub
account**: any wallet works, and nothing in it depends on your holdings.

## What happens next

A request is only acted on when the audit's reviewer list, which lives with the audit, already
includes your wallet. Anything else is left alone, with no reply. A maintainer merges a request
they accept; merging is the approval. The auditor then records it and seals the report for you,
after which you can open the locked page with the same wallet.

## The check

Every pull request runs `scripts/check.mjs`, taken from the main branch. It confirms the file
is named for its wallet and that the wallet signed it. It is advisory: a green check means
the request is well formed, not that it will be accepted.
