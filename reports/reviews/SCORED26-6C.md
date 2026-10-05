Source: SCORED '26 review, pasted by the author on 2026-10-05; verbatim.

Review #6C
Overall merit
2. Weak reject

Reviewer expertise
2. Some familiarity

Paper Review
The paper tackles an important problem which is the compromise of the Kubernetes service-account signing key allows cluster-wide attacks. Integrating an external threshold-signing service through KEP-740, without modifying Kubernetes core or its clients, is an attractive architectural direction. The paper provides a detailed description of the prototype, token-issuance flow, deployment architecture, and implementation challenges.

However, I have the following concerns:

The security evaluation simulates signer compromise by stopping signer containers. This seems to be testing availability after a crash and, not adversarial compromise or resistance to token forgery. A compromised signer remains operational and may return malformed shares, reuse nonces, leak state, or collude with other signers. The paper could benefit from better explaining how this evaluation leads to an adversarial compromise.

The current prototype does not seem to provide the independence required to achieve the security goal of decentralization of the key. All five signers, Vault, coordinators, and nginx run on one Docker host, and the trusted-dealer key-generation process temporarily holds every share. A single host compromise can obtain all shares and reduce the effective threshold to one.

The evaluation uses only a single-node Minikube installation on macOS with Docker Desktop and a socat bridge. This environment is insufficient for estimating the latency and reliability of a production deployment with geographically or administratively independent signers.

The paper calls two issues "previously undocumented KEP-740 defects," but one is an ambiguous comment and the other is the established JWA requirement that ES256 signatures use fixed-width r || s encoding. The paper should provide evidence that these are defects in KEP-740 rather than implementation mistakes.

Minor:

The limitations are numbered inconsistently: two different items are labeled L2.
