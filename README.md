# zkPrompt

Proof of Prompt enables AI agents to commit to prompts privately while generating verifiable outputs using zero-knowledge proofs. It ensures secure, trustless interactions between AI agents and decentralized applications, allowing on-chain verification without exposing sensitive input data.

[more information](https://wiki.zypher.network/zypher-ai-agent/zypher-ai-agent/zkprompt)

**Under development, do not use in production environments**

## Testing

### `test_client_request`

Requires a DashScope API key in `.env` (`QWEN_API_KEY=sk-xxx`). Copy [`.env_tmplate`](.env_tmplate) to `.env` and fill in the key.

```bash
# Terminal 1
cargo run -p proxy -- --forward dashscope.aliyuncs.com --port 9100

# Terminal 2
cargo test --package client --lib -- client_tmp::test::test_client_request
```

The proxy `--forward` host must match the API endpoint (`dashscope.aliyuncs.com`). Using `www.rust-lang.org` here will return 404.

## License

This project is licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html).
