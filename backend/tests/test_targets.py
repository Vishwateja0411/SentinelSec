import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_target_valid_url(client: AsyncClient):
    payload = {
        "target": "https://secure-app.internal.example.org:8443/dashboard",
        "type": "url",
        "authorization_attestation": True,
    }
    response = await client.post("/api/targets", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["target"] == "https://secure-app.internal.example.org:8443/dashboard"
    assert data["type"] == "url"
    assert data["authorization_attestation"] is True
    assert "id" in data
    assert "attestation_timestamp" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_create_target_valid_ipv4(client: AsyncClient):
    payload = {
        "target": "192.168.1.100",
        "type": "ip",
        "authorization_attestation": True,
    }
    response = await client.post("/api/targets", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["target"] == "192.168.1.100"
    assert data["type"] == "ip"
    assert data["authorization_attestation"] is True


@pytest.mark.asyncio
async def test_create_target_valid_ipv6(client: AsyncClient):
    payload = {
        "target": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "type": "ip",
        "authorization_attestation": True,
    }
    response = await client.post("/api/targets", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["type"] == "ip"


@pytest.mark.asyncio
async def test_reject_false_authorization_attestation(client: AsyncClient):
    payload = {
        "target": "https://example.com",
        "type": "url",
        "authorization_attestation": False,
    }
    response = await client.post("/api/targets", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert "errors" in data or "detail" in data
    error_text = str(data)
    assert "Explicit affirmative authorization attestation is strictly required" in error_text


@pytest.mark.asyncio
async def test_reject_missing_authorization_attestation(client: AsyncClient):
    payload = {
        "target": "https://example.com",
        "type": "url",
    }
    response = await client.post("/api/targets", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_reject_invalid_ip_format(client: AsyncClient):
    invalid_ips = [
        "example.com",  # domain name submitted as IP
        "999.999.999.999",  # out of range
        "192.168.1.1.1",  # too many octets
        "not-an-ip",
    ]
    for ip in invalid_ips:
        payload = {
            "target": ip,
            "type": "ip",
            "authorization_attestation": True,
        }
        response = await client.post("/api/targets", json=payload)
        assert response.status_code == 422, f"Expected 422 for invalid IP: {ip}"


@pytest.mark.asyncio
async def test_reject_unsupported_url_schemes(client: AsyncClient):
    unsupported_schemes = [
        "ftp://ftp.example.com/files",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "gopher://gopher.floodgap.com",
        "ssh://user@10.0.0.1",
    ]
    for url in unsupported_schemes:
        payload = {
            "target": url,
            "type": "url",
            "authorization_attestation": True,
        }
        response = await client.post("/api/targets", json=payload)
        assert response.status_code == 422, f"Expected 422 for scheme: {url}"


@pytest.mark.asyncio
async def test_reject_embedded_url_credentials(client: AsyncClient):
    payload = {
        "target": "https://admin:SuperSecretPassword@app.example.com",
        "type": "url",
        "authorization_attestation": True,
    }
    response = await client.post("/api/targets", json=payload)
    assert response.status_code == 422
    assert "Embedded credentials" in str(response.json())


@pytest.mark.asyncio
async def test_reject_malformed_url(client: AsyncClient):
    payload = {
        "target": "http://",
        "type": "url",
        "authorization_attestation": True,
    }
    response = await client.post("/api/targets", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_target_by_id_and_not_found(client: AsyncClient):
    # Create target first
    create_payload = {
        "target": "https://test.example.com",
        "type": "url",
        "authorization_attestation": True,
    }
    create_resp = await client.post("/api/targets", json=create_payload)
    target_id = create_resp.json()["id"]

    # Retrieve created target
    get_resp = await client.get(f"/api/targets/{target_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == target_id
    assert get_resp.json()["target"] == "https://test.example.com"

    # Nonexistent target
    not_found_resp = await client.get("/api/targets/00000000-0000-0000-0000-000000000000")
    assert not_found_resp.status_code == 404


@pytest.mark.asyncio
async def test_target_pagination(client: AsyncClient):
    # Insert 5 targets
    for i in range(5):
        await client.post(
            "/api/targets",
            json={
                "target": f"10.0.0.{i + 1}",
                "type": "ip",
                "authorization_attestation": True,
            },
        )

    # First page: limit 2, skip 0
    page1 = await client.get("/api/targets?skip=0&limit=2")
    assert page1.status_code == 200
    data1 = page1.json()
    assert data1["total"] == 5
    assert len(data1["items"]) == 2
    assert data1["skip"] == 0
    assert data1["limit"] == 2

    # Second page: limit 2, skip 2
    page2 = await client.get("/api/targets?skip=2&limit=2")
    assert page2.status_code == 200
    data2 = page2.json()
    assert data2["total"] == 5
    assert len(data2["items"]) == 2
    assert data2["items"][0]["id"] != data1["items"][0]["id"]
