# Keys used by these vectors

Derived from fixed seeds so anyone can rebuild them.

| role | seed | public key |
|---|---|---|
| adversary, signs and is embedded | `00..ff` | `5699a9cef870e2ff0c022b67689cc76fe05e90915c5f0143f9356ca72f4aff99` |
| bystander, valid but did not sign | `00..02` | `7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674` |
| conformance, unused here | `00..01` | `4cb5abf6...` |

The adversary key is deliberately not the conformance key. A verifier that happens to have the fixture key loaded must still refuse these, and sharing the key would let it pass for a reason that has nothing to do with section 9.5.
