---
summary: "Use NVIDIA NIM models in OpenClaw"
read_when:
  - You want to use NVIDIA models in OpenClaw
  - You need NVIDIA NIM API setup
---
# NVIDIA NIM

NVIDIA provides AI model inference through **NIM** (NVIDIA Inference Microservices).
NIM exposes an OpenAI-compatible API, so it integrates with OpenClaw as a custom
provider via `models.providers`.

## Get an API key

1. Sign up at [build.nvidia.com](https://build.nvidia.com/)
2. Go to your profile and generate an API key
3. The key format is `nvapi-...`

## Config snippet

```json5
{
  env: { NVIDIA_API_KEY: "nvapi-..." },
  agents: { defaults: { model: { primary: "nvidia/meta/llama-3.3-70b-instruct" } } },
  models: {
    mode: "merge",
    providers: {
      nvidia: {
        baseUrl: "https://integrate.api.nvidia.com/v1",
        apiKey: "${NVIDIA_API_KEY}",
        api: "openai-completions",
        models: [
          {
            id: "meta/llama-3.3-70b-instruct",
            name: "Llama 3.3 70B Instruct",
            reasoning: false,
            input: ["text"],
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
            contextWindow: 131072,
            maxTokens: 8192
          },
          {
            id: "meta/llama-3.1-405b-instruct",
            name: "Llama 3.1 405B Instruct",
            reasoning: false,
            input: ["text"],
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
            contextWindow: 131072,
            maxTokens: 8192
          },
          {
            id: "nvidia/llama-3.1-nemotron-70b-instruct",
            name: "Nemotron 70B Instruct",
            reasoning: false,
            input: ["text"],
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
            contextWindow: 131072,
            maxTokens: 8192
          },
          {
            id: "mistralai/mistral-large-2-instruct",
            name: "Mistral Large 2",
            reasoning: false,
            input: ["text"],
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
            contextWindow: 128000,
            maxTokens: 8192
          },
          {
            id: "deepseek-ai/deepseek-r1",
            name: "DeepSeek R1",
            reasoning: true,
            input: ["text"],
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
            contextWindow: 163840,
            maxTokens: 8192
          }
        ]
      }
    }
  }
}
```

## Available models (selection)

NVIDIA NIM hosts many models. Some popular ones:

| Model ID | Name | Context | Features |
|----------|------|---------|----------|
| `meta/llama-3.3-70b-instruct` | Llama 3.3 70B | 131k | General, code |
| `meta/llama-3.1-405b-instruct` | Llama 3.1 405B | 131k | Complex tasks |
| `nvidia/llama-3.1-nemotron-70b-instruct` | Nemotron 70B | 131k | NVIDIA-tuned |
| `mistralai/mistral-large-2-instruct` | Mistral Large 2 | 128k | Multilingual |
| `deepseek-ai/deepseek-r1` | DeepSeek R1 | 164k | Reasoning |
| `qwen/qwen2.5-coder-32b-instruct` | Qwen 2.5 Coder 32B | 131k | Code |

Browse the full catalog at [build.nvidia.com](https://build.nvidia.com/).

## Self-hosted NIM

If you run NIM containers on your own infrastructure, point `baseUrl` to your
local endpoint:

```json5
{
  models: {
    mode: "merge",
    providers: {
      nvidia: {
        baseUrl: "http://your-nim-host:8000/v1",
        apiKey: "local",
        api: "openai-completions",
        models: [
          { id: "meta/llama-3.3-70b-instruct", name: "Llama 3.3 70B" }
        ]
      }
    }
  }
}
```

## Notes

- Model refs are `nvidia/<model>` (e.g. `nvidia/meta/llama-3.3-70b-instruct`).
- NVIDIA NIM is **not** a built-in provider; it requires a `models.providers` entry.
- NIM uses an OpenAI-compatible API (`openai-completions`).
- Cost values depend on your NIM plan; update them to match your billing.
- See [/concepts/model-providers](/concepts/model-providers) for provider rules.
