Source: SCORED '26 review, pasted by the author on 2026-10-05; verbatim.
[Note by the author: this text starts at the review's "Paper Review" section; its merit/expertise header was not included in what was pasted.]

Paper Review
Kubernetes signs all its access tokens with one single private key. If that key is stolen, an attacker can forge any token. This paper builds a prototype that splits the key into 5 parts: at least 3 of the 5 signers must work together to sign a token, so stealing one part is not enough. The system connects to Kubernetes through a new official interface (KEP-740), without changing Kubernetes itself. During the work the authors found two implementation problems that make tokens fail silently, and they present these as the main contribution. The performance cost is small (about 6%) in their test setup. However, everything runs on a single machine, so the real security benefit is only shown in theory.

Strengths: The topic is timely, the prototype works end to end, and the code is public. I liked that the authors are honest about the limits: they say clearly that running all signers on one machine does not give real security, and they repeat this warning in the right places. The two implementation problems they found seem useful for anyone who will build on the same interface.

Weaknesses:

The performance comparison is not clean: the baseline uses a different signature algorithm (RS256) than the new system (ES256), so the numbers mix two changes at once.
The abstract only reports the good numbers (6% and 18%), but Table 2 also shows much higher overhead in some cases (+44%, +42%), which is not mentioned.
The security claims rely on two "companion" papers by the same authors that are only preprints, not reviewed.
The paper needs editing: two limitations are both called "L2", the abstract says six limitations but the paper lists seven, Sections 5.3 and 5.4 repeat almost the same text, and the conclusion repeats the same findings twice.
Comments for authors
Thank you for the submission. The prototype works, the code is public, and I appreciated your honesty about the limits of the test setup.

-The baseline uses a different signature algorithm (RS256) than your system (ES256). This makes the comparison hard to read. Why not compare against a single-key ES256 setup?

The abstract reports only the best numbers (6% and 18% overhead), but Table 2 also shows +44% and +42% in some tests. Please mention these too, or explain them.

Have you reported the two problems you found to the Kubernetes project? If yes, please say so it would make the paper stronger.
