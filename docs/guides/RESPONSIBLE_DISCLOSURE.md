# Responsible Disclosure For Scanner Findings

The Execution Gap Scanner is local and private by default. Actenon does not run a hosted leaderboard, public grading service, or ecosystem ranking from OSS scanner output.

Scanner findings should be described as candidate agent-controlled consequential action paths that require maintainer review. They are a map of authority, not a vulnerability accusation.

## Default Handling

- Keep reports inside the developer workspace or CI system.
- Do not publish grades for third-party projects without consent.
- Treat findings as advisory until the affected maintainers can review context.
- Prefer private pull requests, security reports, or maintainer channels for consequential-action gaps.
- Do not publish target grades or private field-test reports without maintainer consent.

## Future Public Grades

Any future public registry, badge, or ecosystem grade should be opt-in, transparent about methodology, and correctable by the affected project. Compatibility and verification claims should not require buying Actenon Cloud.

## What To Share

When reporting a finding, include:

- scanner mode and version,
- capability registry version,
- affected file and line,
- finding summary,
- surface id, primitive, agent-control context, consequence class, confidence, source context, and gating status,
- remediation suggestion,
- whether the finding is static-only or reproduced at a protected endpoint.

Avoid sharing secrets, production identifiers, customer data, or private scanner reports.

## Non-Claims

A scanner finding does not prove exploitability, business-policy failure, downstream finality, harm, production reachability, or non-compliance. It means static analysis found a candidate consequential action path and did not find one or more visible execution-boundary controls.

Critical-impact candidate means the action surface could have critical consequences if reachable, agent-controlled and ungated. It does not mean a critical vulnerability has been proven. Headline counts and headline consequence class are based on runtime-source candidates by default; test, fixture, example, docs, generated and migration findings should be reported separately and downgraded by context.

Use phrases such as "candidate consequential action path", "static advisory finding", and "requires maintainer review". Avoid definitive claims about the target project's safety, production deployment, or real-world impact.

Do not describe a static scanner result as a proven vulnerability, confirmed exploit, breach, or production incident unless separate maintainer-validated runtime evidence supports that claim.
