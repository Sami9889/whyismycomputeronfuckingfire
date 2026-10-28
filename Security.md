# Security Policy

Thanks for looking after whyismycomputeronfuckingfire.com.au. It is a small hobby project made by [Sami9889](https://github.com/Sami9889) ([sami-s.dev](https://sami-s.dev)), but I take security reports seriously.

## Reporting a vulnerability

**Please do not open a public issue or post in the guestbook.** Guestbook entries are public GitHub issues.

Report privately in one of these ways:

1. **GitHub private vulnerability reporting** (preferred): go to the *Security* tab of this repository and choose *Report a vulnerability*, or use
   <https://github.com/Sami9889/whyismycomputeronfuckingfire/security/advisories/new>.
2. **Email me** at <hello@sami-s.dev>. Please put "Security" in the subject line. If you want to send sensitive details, ask first and I will arrange a private channel.

Please include:

- what you found and where (URL, endpoint or file),
- steps to reproduce it,
- what you think the impact is.

## What to expect

This is a one-person project, so these are goals, not guarantees:

- I will try to acknowledge your report within **7 days**.
- I will try to confirm and fix real issues within **30 days**, and tell you when it is fixed.
- I am happy to credit you in the fix if you want that.

There is no bug bounty.

## Scope

In scope:

- `server.js` (the guestbook, fund bar, visitor counter and anti-spam checks)
- `index.html`
- Anything that exposes the GitHub tokens the server uses, or lets someone write to the repository's issues without passing the checks

Out of scope:

- Spam or silly entries in the guestbook (tell me and I will close the issue)
- Denial-of-service through sheer traffic volume
- Social engineering, physical attacks, or attacks on GitHub, your host or other third parties
- Missing security headers or best-practice suggestions with no demonstrated impact
- The site's jokes about computers being on fire

## Good-faith research

If you act in good faith, avoid harming other people's data, do not access more than you need to prove the issue, and give me reasonable time to fix it before sharing details, I will not pursue action against you.

## Supported versions

Only the latest version on the default branch is supported.
