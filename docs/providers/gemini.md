---
summary: "Use Google Gemini models in OpenClaw"
read_when:
  - You want to use Gemini models in OpenClaw
  - You need Gemini API key or Vertex/Gemini CLI setup
---
# Google Gemini

Google provides the **Gemini** model family through several authentication methods:
API key, Google Vertex (gcloud ADC), Antigravity OAuth, and Gemini CLI OAuth.

## Option A: Gemini API key (recommended)

**Best for:** direct API access with usage-based billing.
Create your API key in [Google AI Studio](https://aistudio.google.com/apikey).

### CLI setup

```bash
openclaw onboard --auth-choice gemini-api-key
# or non-interactive
openclaw onboard --gemini-api-key "$GEMINI_API_KEY"
```

### Config snippet

```json5
{
  env: { GEMINI_API_KEY: "AI..." },
  agents: { defaults: { model: { primary: "google/gemini-3-pro-preview" } } }
}
```

## Option B: Google Vertex AI

**Best for:** enterprise GCP workloads with gcloud Application Default Credentials.

### CLI setup

```bash
gcloud auth application-default login
openclaw models set google-vertex/gemini-3-pro-preview
```

### Config snippet

```json5
{
  agents: { defaults: { model: { primary: "google-vertex/gemini-3-pro-preview" } } }
}
```

## Option C: Antigravity OAuth

**Best for:** using Google Antigravity subscription access.

```bash
openclaw plugins enable google-antigravity-auth
openclaw models auth login --provider google-antigravity --set-default
```

## Option D: Gemini CLI OAuth

**Best for:** using Gemini CLI subscription access.

```bash
openclaw plugins enable google-gemini-cli-auth
openclaw models auth login --provider google-gemini-cli --set-default
```

Note: you do **not** paste a client id or secret into `openclaw.json`. The CLI
login flow stores tokens in auth profiles on the gateway host.

## Available models

| Model ID | Name | Context | Features |
|----------|------|---------|----------|
| `gemini-3-pro-preview` | Gemini 3 Pro | 202k | Reasoning, vision, code |
| `gemini-3-flash-preview` | Gemini 3 Flash | 262k | Fast, reasoning, vision |
| `gemini-2.5-pro-preview-06-05` | Gemini 2.5 Pro | 1M | Reasoning, vision, code |
| `gemini-2.5-flash-preview-05-20` | Gemini 2.5 Flash | 1M | Fast, reasoning |
| `gemini-2.0-flash` | Gemini 2.0 Flash | 1M | Fast, vision |

## Provider mapping

| Auth method | Provider prefix | Example |
|-------------|----------------|---------|
| API key | `google/` | `google/gemini-3-pro-preview` |
| Vertex AI | `google-vertex/` | `google-vertex/gemini-3-pro-preview` |
| Antigravity | `google-antigravity/` | `google-antigravity/gemini-3-pro-preview` |
| Gemini CLI | `google-gemini-cli/` | `google-gemini-cli/gemini-3-pro-preview` |

## Gemini embeddings

Gemini can also be used for memory search embeddings:

```json5
{
  agents: {
    defaults: {
      memorySearch: {
        provider: "gemini",
        model: "gemini-embedding-001",
        remote: {
          apiKey: "YOUR_GEMINI_API_KEY"
        }
      }
    }
  }
}
```

See [/concepts/memory](/concepts/memory) for details.

## Notes

- Model refs are `google/<model>` for API key access.
- Vertex uses `google-vertex/<model>`, Antigravity uses `google-antigravity/<model>`.
- Gemini is a built-in provider: no `models.providers` config needed, just set auth + model.
- See [/concepts/model-providers](/concepts/model-providers) for provider rules.
