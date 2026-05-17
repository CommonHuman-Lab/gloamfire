# Custom Chain

```yaml
# scenarios/chains/my_chain.yaml
name: my_chain
description: Custom attack sequence
on_fail: stop   # stop | continue (default: continue)
scenarios:
  - suspicious_curl
  - reverse_shell
  - fake_ransomware
```

Then run it:

```bash
gloamfire simulate chain my_chain
gloamfire simulate chain ./scenarios/chains/my_chain.yaml --export ./output
```