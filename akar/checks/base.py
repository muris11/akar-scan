from __future__ import annotations

from ..models import Page


class Check:
    """Base class for scanner modules.

    `on_page` runs against each sampled crawled page, `run` executes once per scan
    for host-wide checks.
    """

    id = "base"
    name = "Base check"
    description = ""

    async def run(self, ctx) -> None:
        return None

    async def on_page(self, ctx, page: Page) -> None:
        return None
