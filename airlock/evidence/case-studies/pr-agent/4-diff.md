### Airlock / Authority Review

**This change adds powers that are not approved:**

| | Power | Resource | Code |
|---|---|---|---|
| ➕ | `github.repo.delete` | `github.com/Actenon/actenon-kernel` | `pr_agent/git_providers/github_provider.py:819 in GithubProvider.publish_comment  (PyGithub Repository.delete)` |

**Runtime production authority: BLOCKED UNTIL APPROVED** (`airlock approve`, then commit `airlock.json`).


