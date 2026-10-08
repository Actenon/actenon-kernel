"""Synthetic browser-submit fixture for the advisory execution-gap scanner.

The page object below is local-only: it records no data and contacts no service.
"""


class SyntheticPage:
    """Minimal stand-in exposing browser-style methods to static analysis."""

    async def fill(self, selector: str, value: str) -> None:
        pass

    async def click(self, selector: str) -> None:
        pass


async def browser_agent_submit_profile(page: SyntheticPage, email: str) -> None:
    """Model a consequential form submission without performing a real action."""
    await page.fill("#email", email)
    await page.click("button[type=submit]")
