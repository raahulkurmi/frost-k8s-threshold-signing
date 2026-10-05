Source: SCORED '26 review, pasted by the author on 2026-10-05; verbatim.

This paper presents frost-k8s, a prototype that aims to integrate FROST threshold signing with Kubernetes' KEP-740 ExternalJWTSigner interface for service account tokens. The system uses a 3-of-5 signer configuration and reports an end-to-end Minikube implementation, two KEP-740 integration issues, and measurements of signing latency and fault tolerance. Overall, I find the problem relevant and the systems direction interesting. My main concern is that the signing path described in the paper is difficult to reconcile with ES256 verification and with the released artifact. This makes it hard to assess the paper's central threshold-security claim with confidence.

Strengths

The paper addresses a practical Kubernetes security problem and uses KEP-740 as a natural integration point.
The implementation is described in useful engineering detail and accompanied by a public artifact.
The authors are relatively candid about important prototype limitations, including signer co-location, trusted-dealer key generation, and the single-node benchmark setup.
The KEP-740 integration lessons could be useful to practitioners if their scope and applicable specification versions are clarified.
Weaknesses

The central relationship between FROST/Schnorr, ES256/ECDSA, and the actual implementation is currently unclear.
The performance baseline changes both the signing algorithm and parts of the deployment architecture, which makes the comparison difficult to interpret.
Some security claims are stronger than what the reported experiments directly establish.
A few reported results and security arguments need clarification for internal consistency.
Comments for authors
Thank you for the submission. The paper presents frost-k8s, a prototype integrating FROST threshold signing with Kubernetes' KEP-740 ExternalJWTSigner interface, and it tackles a problem I consider both practical and timely: the service account signing key as a single point of compromise. The choice of KEP-740 as the integration point is natural, the implementation and deployment are described in enough detail to follow, the limitations sections are unusually candid, and the public artifact made it possible for me to examine the system directly, which is exactly the kind of practice this community should encourage. It is precisely because the artifact is available, however, that I was able to check the signing path in detail, and this is where my main concern arises: I was unable to reconcile the threshold-signing construction described in the paper with ES256 verification on the one hand, and with the released implementation on the other. Since this affects the paper's central security claim, I describe it first and in detail below; my remaining comments are more standard and should be straightforward to address.

My main concern is the relationship between FROST/Schnorr and ES256/ECDSA. Section 3.2 describes the FROST signature shares as being aggregated into a Schnorr signature, which is then converted to IEEE P1363 format and returned as an ES256 JWT signature. I do not understand how this step works cryptographically: P1363 specifies an encoding of signature values, but changing the encoding does not by itself turn a Schnorr signature into an ECDSA signature. Since an ES256 verifier expects ECDSA over P-256, this part of the design needs a clearer explanation.

The released artifact also seems to implement a different signing path. In makeSignFn(), the proxy first calls collectCommitmentsParallel(), then calls collectSharesParallel(). However, the returned signature shares are discarded (_, err = collectSharesParallel(...)). The file separately defines aggregateSignature(), which invokes Config.AggregateSignatures(), but this helper does not appear to be called from the JWT issuance path. Instead, immediately after the share collection succeeds, the proxy calls ecKey.SignES256(signingInput). The same ecKey is loaded by the coordinator at startup using NewECDSAKey(). If I am reading the artifact correctly, the successful FROST interaction therefore acts as a gate before signing, while the actual JWT signature is produced by a conventional ECDSA private key held by the coordinator.

There is a related key-management question. Section 5.4 describes data/ecdsa-signing.pem as containing the PKIX-encoded FROST group public key for use by FetchKeys. In the artifact, however, NewECDSAKey() tries to parse this file as an EC private key; if that parsing does not succeed, it generates and stores a new P-256 private key. PublicKeyPKIX() then derives the public key from that same private key, while SignES256() uses it to produce the JWT signature. Thus, as the current code reads, both the verification key supplied to the gRPC server and the JWT signature appear to originate from the coordinator-side ECDSA key rather than directly from the FROST group key. This also seems difficult to reconcile with the paper's statement that the coordinator holds no signing key material.

Could the authors please clarify the exact signing path?

A few additional issues should also be addressed:

For KEP-740 Finding 1, the current upstream KEP/proto describes claims as the already base64url-encoded JWT payload, while the paper quotes different wording. Please provide the exact Kubernetes version or upstream commit corresponding to the quoted text. If this was an ambiguity in an earlier version that has since been clarified, the paper should state that explicitly.
Stopping signer containers primarily tests availability rather than compromise. For example, stopping three signers demonstrates that the system refuses to sign when fewer than three are available, but it does not experimentally demonstrate the behavior of an attacker controlling three signing shares. I suggest separating the fault-tolerance experiments from the security argument more clearly.
Table 3/Figure 3 report about 70 ms with two signers killed, while Section 6.4 reports about 36 ms for what appears to be the same 3-of-5-active configuration. Could you clarify whether these measurements correspond to different conditions, such as failure detection/recovery versus steady-state warm signing.
"The paper gives the threshold forgery probability as C(5,3) * p^3 = 10p^3. If the baseline probability is p, the improvement factor is 1/(10p^2), not a fixed 40x. Could you state the assumed value of p if 40x is intended as a concrete example, or present the improvement as a function of p.
Threshold RSA seems particularly relevant because it could preserve a standard RS256 verification path, and the paper should discuss why FROST is preferable despite the compatibility issue above. PASTA and ROAST also seem worth mentioning as related work.
Section 9 contains two limitations labeled "L2".
