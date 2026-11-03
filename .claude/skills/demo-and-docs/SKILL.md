---
name: demo-and-docs
description: Use when writing the README, judge instructions, mock mode, hosting, demo scripts or the video plan for Tollgate.
---
# Demo and docs

- README: what it is in two sentences, how to run in mock mode with one command, how to run against the Braintree sandbox, how to run the tests, honest limits, license.
- Judge instructions: how to open the hosted demo, sample sandbox steps, no real money, no login needed for mock mode.
- Mock mode must work with no keys so anyone can try it.
- docs/ARCHITECTURE.md: diagram of agent -> Gate -> executor -> Braintree, plus Sentinel beside it.
- docs/THREAT_MODEL.md: what attacks Tollgate addresses, what it does not.
- Video (under 3:00): story first, live attack with the gate OFF then ON, Sentinel catching a weakened rule, honest limits, results from the real benchmark only.
- Never overclaim. Say what the tests measured and no more.
