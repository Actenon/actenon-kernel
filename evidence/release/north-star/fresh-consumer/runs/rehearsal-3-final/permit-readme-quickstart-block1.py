from actenon_permit import Actenon, GitHubAdapter

client = Actenon.local(agent_id="my-agent", scopes=["github.issue.create"])
client.register_credential("GITHUB_TOKEN", "ghp_YOUR_TOKEN")
client.register_adapter_tool("github_issue",
    action_type="github.issue.create",
    adapter=GitHubAdapter(test_mode=True),
    credential_ref="GITHUB_TOKEN", target="github")

intent = client.authorised_execution_intents.create(
    action="github.issue.create", target="github",
    parameters={"owner": "Actenon", "repo": "example", "title": "Hello"})
result = intent.execute()
print(f"{result.state}  {result.finality}")   # succeeded  final
