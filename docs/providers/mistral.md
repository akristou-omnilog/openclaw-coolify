---
summary: "Use Mistral AI models in OpenClaw"
read_when:
  - You want to use Mistral models in OpenClaw
  - You need Mistral API key setup
---
# Mistral AI

Mistral AI builds open and commercial LLMs optimized for efficiency and multilingual
tasks. OpenClaw supports Mistral as a **built-in provider** — set your API key and
pick a model.

## CLI setup

```bash
openclaw onboard --auth-choice apiKey --token-provider mistral --token "$MISTRAL_API_KEY"
# or set the environment variable
export MISTRAL_API_KEY="sk-..."
```

## Config snippet

```json5
{
  env: { MISTRAL_API_KEY: "sk-..." },
  agents: { defaults: { model: { primary: "mistral/mistral-large-latest" } } }
}
```

## Available models

| Model ID | Name | Context | Features |
|----------|------|---------|----------|
| `mistral-large-latest` | Mistral Large | 128k | Reasoning, multilingual, code |
| `mistral-medium-latest` | Mistral Medium | 128k | Balanced performance |
| `mistral-small-latest` | Mistral Small | 128k | Fast, cost-efficient |
| `codestral-latest` | Codestral | 256k | Code-optimized, fill-in-the-middle |
| `open-mistral-nemo` | Mistral Nemo | 128k | Open-weight, efficient |
| `ministral-8b-latest` | Ministral 8B | 128k | Lightweight, fast |

## Custom provider setup

If you need to override the base URL or define explicit models, use
`models.providers`:

```json5
{
  env: { MISTRAL_API_KEY: "sk-..." },
  agents: { defaults: { model: { primary: "mistral/mistral-large-latest" } } },
  models: {
    mode: "merge",
    providers: {
      mistral: {
        baseUrl: "https://api.mistral.ai/v1",
        apiKey: "${MISTRAL_API_KEY}",
        api: "openai-completions",
        models: [
          {
            id: "mistral-large-latest",
            name: "Mistral Large",
            reasoning: false,
            input: ["text"],
            cost: { input: 2, output: 6, cacheRead: 0, cacheWrite: 0 },
            contextWindow: 128000,
            maxTokens: 8192
          }
        ]
      }
    }
  }
}
```

## Notes

- Model refs are `mistral/<model>`.
- Mistral is a built-in provider: no `models.providers` config needed for basic usage.
- Get your API key from [console.mistral.ai](https://console.mistral.ai/).
- Mistral uses an OpenAI-compatible API.
- See [/concepts/model-providers](/concepts/model-providers) for provider rules.
