# Celestiq Lattice

> Open infrastructure for a network where every entity, person, home, organisation, device, agent, is a sovereign node, and any two can coordinate directly.

**Status:** Early. Architecture v1 specified. Local proof of concept working. Federation layer is the next milestone.

---

## What this is

Celestiq Lattice is a protocol and runtime for sovereign federated coordination. Each Lattice node runs on hardware owned by its operator (a home, an organisation, a research lab, eventually an individual) and hosts a typed message bus that devices, applications, and AI agents connect to. Nodes federate with each other directly, by mutual consent, with no platform in the data path.

The thesis is straightforward. Today's digital infrastructure routes through a small number of platforms that decide what devices can talk to each other, where data flows, and what an individual is allowed to orchestrate. The infrastructure for the opposite arrangement, where every entity owns its own node and federates by consent, does not yet exist as a coherent protocol. Lattice is an attempt at that protocol.

---

## Three commitments

These shape every design decision in the spec.

**Sovereignty is an architecture, not a policy.** Platforms that promise privacy do so by policy. Promises are revocable, monetisable, and silently changeable. Lattice removes the possibility of inspection rather than promising restraint: data flows directly between consenting parties, never touching a platform's systems.

**Typed messages, not opaque bytes.** A message bus that moves bytes is a transport. A bus that moves typed, schema-validated messages is a language. Lattice's schema system is what makes federation meaningful: two independent operators can exchange data because both interpret it under the same shared contract.

**Federation requires consent, in both directions.** Each node decides what it sends and what it accepts, independently. Either side can pause or revoke without the other's cooperation. Federation cannot be made to happen against any participant's will.

---

## Architecture at a glance

A Lattice deployment has three components.

- **The Lattice node.** A long-running server per location. Hosts the message bus, schema registry, device registry, permission rules, object store, and federation manager. Runs on commodity hardware.
- **Client SDKs.** Two tiers. Tier 1 is a minimal C library for constrained microcontrollers. Tier 2 is a full-featured client with bindings for desktop, mobile, browser, and command-line environments.
- **Coordination service.** A lightweight introduction service that helps two nodes locate each other when first federating. It sees connection metadata only, never data, and is self-hostable. The decentralised path based on libp2p is on the roadmap.

The full architecture, including the wire protocol, schema language, identity model, encryption profiles, and federation protocol, is documented in the v1 architecture specification under `/docs`.

---

## What works today

- Typed pub/sub messaging over the bus, end to end between processes on a single node
- A local AI runtime integrated as a participant on the bus, subscribing to typed messages and publishing structured responses
- A hardware client running on a constrained-device microcontroller, driving a physical actuator in response to commands sent from a phone, all routed through the local node with no cloud in the loop

What this proves: the single-node value proposition holds. A sovereign node with local AI and hardware on the bus works end to end on commodity hardware.

## What is coming next

- Federation between two nodes (the central thesis of the protocol)
- The schema definition language and compiler
- Mutual-auth TLS handshake with the identity model
- Permission rules and the local administrative API
- A demonstrable two-node federated teleoperation flow

---

## Repository layout

The repository is in early scaffolding. The intended structure:

```
/spec       protocol specification and design documents
/server     reference node runtime
/sdk-tier1  constrained-device client SDK
/sdk-tier2  full-featured client SDK and language bindings
/examples   minimal working examples
/docs       developer and operator documentation
```

---

## Documents

- `/docs/architecture-v1.pdf` — the v1 architecture specification
- `/docs/decisions-v1.pdf` — companion document covering the reasoning, tradeoffs, and forward considerations behind every decision in the spec

---

## Getting involved

This is an early project. The architecture is more developed than the code, and the right way to engage right now is at the design level.

- If you have read the spec and have feedback, open an issue.
- If you work on a project Lattice should learn from (NATS, libp2p, ActivityPub, AT Protocol, Matter, Home Assistant, the local-first software community), reach out.
- If you want to follow the longer-form thinking behind the project, the [Substack](https://aayushessence.substack.com/) is the best place.

A contribution guide will follow when the code base is past its initial scaffolding phase.

---

## License

The protocol specification and reference implementations will be released under permissive open-source licences. The intended choice is Apache 2.0 for code and CC BY 4.0 for the specification, confirmed before the first tagged release.

---

## Contact

Aayush Sharma · aayush7official@gmail.com
