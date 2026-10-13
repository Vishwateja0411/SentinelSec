import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_full_intake_workflow(client: AsyncClient):
    """
    Test the complete intake lifecycle:
    1. Query targets list initially (empty)
    2. Register a new target with affirmative attestation
    3. Retrieve the target directly by ID
    4. Confirm target appears in list
    """
    # 1. Initial list
    init_res = await client.get("/api/targets")
    assert init_res.status_code == 200
    assert init_res.json()["total"] == 0

    # 2. Intake valid target
    create_res = await client.post(
        "/api/targets",
        json={
            "target": "https://api.sentinel-security.internal/v1",
            "type": "url",
            "authorization_attestation": True,
        },
    )
    assert create_res.status_code == 201
    created = create_res.json()
    target_id = created["id"]
    assert created["authorization_attestation"] is True

    # 3. Retrieve by ID
    get_res = await client.get(f"/api/targets/{target_id}")
    assert get_res.status_code == 200
    assert get_res.json()["target"] == "https://api.sentinel-security.internal/v1"

    # 4. List now contains target
    list_res = await client.get("/api/targets")
    assert list_res.status_code == 200
    assert list_res.json()["total"] == 1
    assert list_res.json()["items"][0]["id"] == target_id
