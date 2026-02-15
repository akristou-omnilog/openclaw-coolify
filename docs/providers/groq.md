---
summary: "Use Groq LPU inference in OpenClaw"
read_when:
  - You want to use Groq models in OpenClaw
  - You need fast inference with Groq LPU
---
# Groq

Groq provides ultra-fast inference powered by their custom **LPU** (Language
Processing Unit) hardware. OpenClaw supports Groq as a **built-in provider** —
set your API key and pick a model.

## CLI setup

```bash
openclaw onboard --auth-choice apiKey --token-provider groq --token "$GROQ_API_KEY"
# or set the environment variable
export GROQ_API_KEY="gsk_..."
```

## Config snippet

```json5
{
  env: { GROQ_API_KEY: "gsk_..." },
  agents: { defaults: { model: { primary: "groq/llama-3.3-70b-versatile" } } }
}
```

## Available models

| Model ID | Name | Context | Features |
|----------|------|---------|----------|
| `llama-3.3-70b-versatile` | Llama 3.3 70B | 128k | General, fast |
| `llama-3.1-8b-instant` | Llama 3.1 8B | 128k | Ultra-fast, lightweight |
| `llama-3.2-90b-vision-preview` | Llama 3.2 90B Vision | 128k | Vision |
| `mixtral-8x7b-32768` | Mixtral 8x7B | 32k | MoE, multilingual |
| `gemma2-9b-it` | Gemma 2 9B | 8k | Lightweight |
| `deepseek-r1-distill-llama-70b` | DeepSeek R1 Distill 70B | 128k | Reasoning |
| `qwen-qwq-32b` | Qwen QwQ 32B | 128k | Reasoning |

## Custom provider setup

If you need to override the base URL or define explicit models, use
`models.providers`:

```json5
{
  env: { GROQ_API_KEY: "gsk_..." },
  agents: { defaults: { model: { primary: "groq/llama-3.3-70b-versatile" } } },
  models: {
    mode: "merge",
    providers: {
      groq: {
        baseUrl: "https://api.groq.com/openai/v1",
        apiKey: "${GROQ_API_KEY}",
        api: "openai-completions",
        models: [
          {
            id: "llama-3.3-70b-versatile",
            name: "Llama 3.3 70B Versatile",
            reasoning: false,
            input: ["text"],
            cost: { input: 0.59, output: 0.79, cacheRead: 0, cacheWrite: 0 },
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

- Model refs are `groq/<model>`.
- Groq is a built-in provider: no `models.providers` config needed for basic usage.
- Get your API key from [console.groq.com](https://console.groq.com/).
- Groq uses an OpenAI-compatible API.
- Groq excels at **speed** — ideal as a fast fallback or for lightweight tasks.
- See [/concepts/model-providers](/concepts/model-providers) for provider rules.
