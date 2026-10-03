"""Credentials: held by Airlock, released only into authorised requests.

`airlock run` removes every managed credential from the agent's environment and gives the agent a
placeholder of the same name instead. Agent code and SDKs keep working unchanged (they read the variable
and put the placeholder wherever they normally put the key). The edge replaces the placeholder with the
real secret only after the request was authorised, and only for requests to the hosts that credential
belongs to. A denied request is never forwarded, so a denied operation never receives a credential.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# Well-known credential variables and the hosts they authenticate to.
KNOWN_CREDENTIALS: dict[str, tuple[str, ...]] = {
    "OPENAI_API_KEY": ("api.openai.com",),
    "ANTHROPIC_API_KEY": ("api.anthropic.com",),
    "GITHUB_TOKEN": ("api.github.com", "uploads.github.com"),
    "GH_TOKEN": ("api.github.com", "uploads.github.com"),
    "GITHUB_PAT": ("api.github.com", "uploads.github.com"),
    "GITHUB_PERSONAL_ACCESS_TOKEN": ("api.github.com", "uploads.github.com"),
    "GITHUB_ACCESS_TOKEN": ("api.github.com", "uploads.github.com"),
    "SLACK_BOT_TOKEN": ("slack.com",),
    "SLACK_TOKEN": ("slack.com",),
    "STRIPE_API_KEY": ("api.stripe.com",),
    "STRIPE_SECRET_KEY": ("api.stripe.com",),
    "LINEAR_API_KEY": ("api.linear.app",),
    "NOTION_TOKEN": ("api.notion.com",),
    "NOTION_API_KEY": ("api.notion.com",),
    "HF_TOKEN": ("huggingface.co",),
    "HUGGINGFACEHUB_API_TOKEN": ("huggingface.co",),
    "GROQ_API_KEY": ("api.groq.com",),
    "MISTRAL_API_KEY": ("api.mistral.ai",),
    "TAVILY_API_KEY": ("api.tavily.com",),
    "SERPAPI_API_KEY": ("serpapi.com",),
    "GOOGLE_API_KEY": ("generativelanguage.googleapis.com",),
    "GEMINI_API_KEY": ("generativelanguage.googleapis.com",),
    "TOGETHER_API_KEY": ("api.together.xyz",),
    "DEEPSEEK_API_KEY": ("api.deepseek.com",),
    "OPENROUTER_API_KEY": ("openrouter.ai",),
    "COHERE_API_KEY": ("api.cohere.com",),
}

# Base-URL variables that move a provider to another host; the credential follows the configured host.
BASE_URL_OVERRIDES: dict[str, str] = {
    "OPENAI_API_KEY": "OPENAI_BASE_URL",
    "ANTHROPIC_API_KEY": "ANTHROPIC_BASE_URL",
}

SECRET_HINTS = ("TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "PRIVATE_KEY", "CREDENTIAL")

# Provider names inside a credential variable's name (e.g. pr-agent's ``GITHUB.USER_TOKEN``, ``OPENAI.KEY``).
PROVIDER_HINTS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("GITHUB", "GH_"), ("api.github.com", "uploads.github.com")),
    (("OPENAI",), ("api.openai.com",)),
    (("ANTHROPIC", "CLAUDE"), ("api.anthropic.com",)),
    (("SLACK",), ("slack.com",)),
    (("STRIPE",), ("api.stripe.com",)),
    (("LINEAR",), ("api.linear.app",)),
    (("NOTION",), ("api.notion.com",)),
    (("GROQ",), ("api.groq.com",)),
    (("MISTRAL",), ("api.mistral.ai",)),
    (("DEEPSEEK",), ("api.deepseek.com",)),
    (("OPENROUTER",), ("openrouter.ai",)),
    (("GEMINI",), ("generativelanguage.googleapis.com",)),
)

# Model-provider chat endpoints, used when the code picks the provider through configuration (e.g. LiteLLM
# with the model in a settings file): the endpoints of the providers whose credential is configured.
LLM_ENDPOINTS: dict[str, tuple[str, ...]] = {
    "api.openai.com": ("api.openai.com/v1/chat/completions",),
    "api.anthropic.com": ("api.anthropic.com/v1/messages",),
    "api.groq.com": ("api.groq.com/openai/v1/chat/completions",),
    "api.mistral.ai": ("api.mistral.ai/v1/chat/completions",),
    "api.deepseek.com": ("api.deepseek.com/chat/completions",),
    "openrouter.ai": ("openrouter.ai/api/v1/chat/completions",),
    "generativelanguage.googleapis.com": ("generativelanguage.googleapis.com/v1beta/models/{}:generateContent",),
}


def looks_secret(name: str) -> bool:
    n = name.upper()
    if n.endswith(("_FILE", "_DIR", "_PATH", "_URL", "_URI", "_HOME")):
        return False  # these hold locations, not secrets
    return any(h in n for h in SECRET_HINTS) or n.endswith((".KEY", "_KEY")) and len(n) > 4


def infer_hosts(name: str) -> tuple[str, ...]:
    """Hosts a secret-looking variable most plausibly authenticates to, from a provider name inside it."""
    if name in KNOWN_CREDENTIALS:
        return KNOWN_CREDENTIALS[name]
    if not looks_secret(name):
        return ()
    n = name.upper()
    if "AZURE" in n or "BEDROCK" in n or "VERTEX" in n:
        return ()  # cloud-hosted variants of a provider live on other hosts
    for hints, hosts in PROVIDER_HINTS:
        if any(n.startswith(h) or f"_{h}" in n or f".{h}" in n for h in hints):
            return hosts
    return ()


def hosts_for(name: str, env: dict[str, str]) -> tuple[str, ...]:
    hosts = list(KNOWN_CREDENTIALS.get(name, ()) or infer_hosts(name))
    override = BASE_URL_OVERRIDES.get(name)
    if override and env.get(override):
        host = (urlsplit(env[override]).hostname or "").lower()
        if host:
            hosts = [host]
    return tuple(hosts)


@dataclass
class Vault:
    """Real credential values, in the Airlock process only."""

    bindings: dict[str, tuple[str, ...]] = field(default_factory=dict)  # name -> hosts
    _real: dict[str, str] = field(default_factory=dict, repr=False)
    placeholders: dict[str, str] = field(default_factory=dict)  # name -> placeholder

    @classmethod
    def from_environment(cls, names: dict[str, tuple[str, ...]], env: dict[str, str]) -> "Vault":
        v = cls()
        for name, hosts in names.items():
            value = env.get(name)
            if not value:
                continue
            v.bindings[name] = tuple(h.lower() for h in hosts)
            v._real[name] = value
            v.placeholders[name] = f"airlock-{name.lower().replace('_', '-')}-{secrets.token_hex(12)}"
        return v

    def agent_environment(self, env: dict[str, str]) -> dict[str, str]:
        out = dict(env)
        for name, ph in self.placeholders.items():
            out[name] = ph
        return out

    def secrets(self) -> list[str]:
        return [v for v in self._real.values() if v]

    def placeholders_in(self, *texts: str) -> list[str]:
        """Names of the credentials whose placeholder appears in any of ``texts``."""
        found = []
        for name, ph in self.placeholders.items():
            if any(ph in t for t in texts if t):
                found.append(name)
        return found

    def allowed_for(self, name: str, host: str) -> bool:
        return host.lower() in self.bindings.get(name, ())

    def inject(self, text: str, names: list[str]) -> str:
        for n in names:
            text = text.replace(self.placeholders[n], self._real[n])
        return text

    def redact(self, text: str) -> str:
        for real in self._real.values():
            if real:
                text = text.replace(real, "[credential]")
        return text


def environment_secrets(env: dict[str, str]) -> list[str]:
    return sorted(k for k in env if looks_secret(k))


def default_env() -> dict[str, str]:
    return dict(os.environ)
