# Optional AI reference

Assure uses Anthropic for finding explanations and natural-language search filters. These features require credentials. The model does not execute searches or remediation.

## Configuration

The enablement check requires a nonempty `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`. Exactly `NIMSTEAD_AI=0` disables provider calls.

`NIMSTEAD_AI_MODEL` defaults to `claude-opus-5-5`. The API reads this value at module import. The SDK client is cached in the process. Restart the API after credential or model changes.

An enabled status reports configuration presence. It does not prove that the credential or provider is available.

## HTTP operations

| Operation | Input | Successful response |
| --- | --- | --- |
| `GET /api/ai/status` | No body | `enabled`: boolean |
| `POST /api/ai/explain/{finding_id}` | An owned finding ID, no body | `text`: explanation string. `model`: configured model name |
| `POST /api/ai/search` | JSON object with `text`: string, 2–500 characters | The five filter fields below |

GET accepts a user session or an eligible read-only organisation token. POST requires a user session. Read-only API tokens cannot use POST.

Enabled POST requests pass through limits of 30 per user and 200 per organisation per hour. The quota check precedes explanation-cache lookup. It records attempts rather than actual provider calls. User refusal short-circuits the organisation counter. The status operation does not call the provider.

| HTTP status | Condition |
| --- | --- |
| `401` or `403` | Authentication or access refusal, according to the authentication path |
| `404` | The requested finding is unavailable to this user |
| `422` | Invalid search request body |
| `429` | The AI usage limit is reached |
| `503` | AI is disabled, a provider call fails, or its answer is unusable |

Provider connection, rate-limit, and API-status failures map to `503`. Refusal and empty text also map to `503`. Other SDK configuration or unexpected internal errors can propagate as server errors.

## Explanation data

The explanation request selects these finding fields:

| Finding field | Provider input |
| --- | --- |
| `vuln_id` | Vulnerability identifier |
| `package` | Package name |
| `installed_version` | Installed version |
| `fixed_version` | Fixed version, or `no fix available yet` when falsey |
| `kev` | Known-exploitation flag |
| `epss` | EPSS probability |
| `cvss` | CVSS score |
| `priority` | Assure priority |
| `reasons` | Risk reason values |
| `summary` | First 1500 characters, or empty text when absent or falsey |

The hostname field is not selected. The API does not redact hostnames or other sensitive text inside the selected values.

The process caches up to 2048 combinations of selected facts and truncated summary. Identical combinations can reuse an answer across findings. Restart clears the cache. A cached answer can return without a provider call, including after AI enablement changes in the process environment.

The prompt requests three short paragraphs under 140 words. The API does not enforce that length or verify generated facts. The returned `model` names the configured model. Provider fallback is enabled, so this field does not identify the actual fallback model.

## Search filter fields

The provider receives the search text. The Python helper truncates it to 500 characters. The HTTP endpoint rejects longer input instead.

| Field | Accepted values | Default |
| --- | --- | --- |
| `q` | String of at most 100 characters, or `null`. Matches package, CVE ID, or hostname text | `null` |
| `priority` | List with values `fix-now`, `next`, `planned`, or `low`. An empty list selects all priorities | `[]` |
| `status` | `open`, `resolved`, or `accepted` | `open` |
| `fixable` | Boolean, or `null` for either value | `null` |
| `kev` | Boolean, or `null` for either value | `null` |

The provider receives a schema that requires all five fields and forbids extra properties. Local validation uses the Pydantic model instead. It supplies omitted defaults, ignores extra keys, and applies default type coercion.

Invalid JSON, invalid enum values, and invalid field lengths produce `503`. A successful response contains filters only. The caller applies them to the findings view.

## Related

- [Configuration](../configuration.md)
- [HTTP endpoint catalog](api-endpoints.md)
- Source: [`ai.py`](../../api/src/nimstead/ai.py) and the AI handlers in [`app.py`](../../api/src/nimstead/app.py)
