"""交互式 API 文档默认不对公网开放。"""

import httpx
import pytest

from app.config import Settings
from app.main import app


def test_api_docs_disabled_by_default():
    assert Settings(_env_file=None).api_docs_enabled is False


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"])
async def test_api_docs_routes_are_absent_by_default(path):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(path)

    assert response.status_code == 404
