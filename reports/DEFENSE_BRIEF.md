# Defence brief: threshold-signed Kubernetes service account tokens

**The original bug.** The prototype claimed FROST threshold signing. In fact, one coordinator-held ECDSA key
(`ecdsa-signing.pem`) signed every token, and the FROST result was computed and thrown away
(`legacy/frost/cmd/grpc-proxy/main.go:198, 205, 228`). That key and all five FROST shares were committed to the
public repository. I found it by checking each paper claim against the code line by line, after a reviewer said
that "converting a Schnorr signature to P1363" is meaningless. No such conversion existed; the P1363 encoding was
applied to a separate ECDSA signature.

**Why FROST cannot work with Kubernetes today.** kube-apiserver's external-signer plugin accepts only RS256,
ES256, ES384 and ES512 (`plugin.go:180`, v1.36.5). FROST produces Schnorr signatures, which no allowed algorithm
verifies. Threshold FROST tokens would need an upstream allow-list change, so I used threshold RSA, which yields
a standard RS256 signature with no change to Kubernetes.

**Shoup threshold RSA in five sentences.** A trusted dealer builds an RSA modulus N from two safe primes, fixes
e = 65537 and the private exponent d, and splits d with a random degree-2 polynomial so that each of the 5
signers gets one share; in the library used, each share is also multiplied by Δ⁻¹ with Δ = 5!. To sign, each
signer hashes and pads the token (PKCS#1 v1.5, SHA-256) itself, raises the result to twice its share, and attaches
a zero-knowledge proof that it used the same share as its public verification key. The coordinator combines any 3
valid shares with Lagrange coefficients scaled by Δ, which avoids division modulo the secret group order. This gives
w with wᵉ = x⁴, and because gcd(4, e) = 1, the extended Euclidean algorithm turns w into y with yᵉ = x. That y is an
ordinary RS256 signature: byte-identical whichever 3 signers took part, and identical to single-key `crypto/rsa`
output (both re-verified in this audit).

**What it protects against, and what it does not.** It protects against:
- theft of up to 2 shares (no signature on anything);
- theft of a coordinator, which holds only public data, so taking one gives no offline forging;
- policy-violating tokens, because every signer checks the claims itself;
- a misbehaving signer, which is excluded and named.

It does *not* protect against:
- **an online oracle.** Whoever controls a coordinator or the apiserver can get tokens for any claims the policy allows while they hold it. With the shipped policy that includes powerful kube-system service accounts.
- **a dishonest dealer,** who sees the whole key once;
- **co-located signers.** In every tested deployment the signers share one operator, one cloud account, one software build and one dealer, so this is not real organisational independence;
- **3 colluding signers,** which is the threshold itself.

**N14 in three sentences.** Go's standard JSON decoder matches field names case-insensitively and lets the last
duplicate win, while the apiserver's go-jose v2 is case-sensitive. A malicious coordinator could therefore send
`{"iss":"good","ISS":"evil"}` (or duplicate keys), so that the signer's policy approved one value while the apiserver
believed another. The policy now reads exact keys and rejects any duplicate or case-variant key at every level it
inspects; an audit mutation that reverts the fix is caught by the tests.

**Quorum waste and the two overload-control attempts.** In a deliberately CPU-starved stress test, each signer
dropped load on its own, so many requests got only 1–2 shares (computed, then wasted): goodput fell to 0.50–0.76 of
peak with 32–44 % of shares wasted, meeting a rule fixed before the run. Version 1 copied DAGOR (all signers drop
the *same* requests, using a keyed priority) plus an early abort; it failed its pre-registered rules, because a
250 ms window held only 2–5 requests and the controller oscillated, which doubled token requests per issued token
in a 300-pod storm (9.0 against 3.8). Version 2, pre-registered in commit 293a919 before any v2 code or data, used
1-second, 40-request windows, a shed-fraction overload signal and damping: it stopped the collapse (0.72 against 0.40 of
peak at c = 200, waste 11 % against 47 %) but never reached 0.8 of peak and hurt retry storms (worst wait 260 s
against 32 s, 8.1 against 4.4 requests per token). Neither was adopted, and the default stays simple deadline-aware
admission. By v2's own pre-registered rule the early abort is now off by default: priority ordering prevents
collapse under sustained overload but starves late clients in bursts, the wrong trade for kubelet token storms.

## The 8 hardest questions

1. **"Isn't the coordinator still a single point of compromise?"** For *online* use, yes. While held, it can mint
   any policy-allowed token, including kube-system ones. What the threshold adds is that no key ever sits on the
   coordinator: losing control ends the attack, nothing can be forged offline, and malformed or over-long tokens
   are refused.
2. **"What independence do your signers really have?"** At best, 5 AWS regions but one provider, account,
   operator, build and dealer. Whoever compromises the account can snapshot every disk. That removes the
   single-host problem, not the shared-organisation problem.
3. **"Why trust a dealer? Why not distributed key generation?"** Shoup RSA needs a modulus with secret safe-prime
   factors. Distributed RSA key generation exists but has no maintained Go implementation. The dealer runs once
   and holds the key only in memory. A dishonest dealer is stated as an assumption, not mitigated.
4. **"tcrsa is unaudited; how do you know it is right?"** Correctness: every combined signature is checked with
   the standard library before it is released, and the audit showed Join's output equals `crypto/rsa`'s. Secrecy
   and side channels are **not** verified: big-integer exponentiation is not constant time, and nobody has
   reviewed it.
5. **"What about replay?"** Shares are deterministic, so a replay inside the ±60 s clock window gets the same
   token that was already issued. Outside the window every signer refuses. There is no nonce cache.
6. **"Why RSA and not threshold ECDSA (ES256)?"** No maintained Go threshold ECDSA supports P-256, and RSA needs
   no interactive rounds. The costs are a trusted dealer and larger tokens.
7. **"What does it cost?"** On AWS (7C) at one request: default Kubernetes 2.5 ms, a single-key external signer
   3.3 ms, threshold 23 ms with signers in the same region and 151 ms with signers across 5 regions. Throughput
   tops out near 70 tokens/s, limited by the small signers' CPU. Pod start-up at 200 pods is unchanged (≈ 16 s),
   because each pod needs one token.
8. **"How do you know your tests test the security?"** In an independent audit, 16 of the 17 targeted
   mutations were caught, and so was every extra mutation on the policy, the TLS identities and the fail-closed
   paths. The one survivor (the binary's abort default) and the redundant checks that no test reaches are listed
   as findings. On top of that: 110 minutes of fuzzing, including a differential against the apiserver's JSON
   parser, found nothing, and the full end-to-end suite passes on a fresh machine against a real v1.36.5 apiserver.
