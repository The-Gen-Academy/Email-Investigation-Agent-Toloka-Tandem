"""Shared Nebius request path; bounded retries for transient provider errors only."""

import time

import httpx


def completion(
    api_key: str, base_url: str, body: dict, client: httpx.Client | None = None
) -> dict:
    owns_client = client is None
    client = client or httpx.Client(timeout=60)
    try:
        for attempt in range(3):
            response = client.post(
                base_url.rstrip("/") + "/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json=body,
            )
            if response.status_code in (429, 502, 503, 504, 529) and attempt < 2:
                time.sleep(3 * (attempt + 1))
                continue
            response.raise_for_status()
            data = response.json()
            choice = data["choices"][0]
            if choice.get("finish_reason") == "length":
                raise ValueError(
                    "Model response exceeded its token limit; incomplete output was rejected"
                )
            return choice["message"]
        raise RuntimeError("Nebius is temporarily unavailable")
    finally:
        if owns_client:
            client.close()
