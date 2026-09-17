# Plugin Development

A plugin implements two operations:

1. `generate_attacks()` creates `AttackCase` objects for a phase.
2. `execute()` runs those cases and returns a normalized `RunResult`.

The included Promptfoo, Garak and PyRIT adapters inherit from `SafeSubprocessPlugin`. Public configuration supplies the exact argv list used for an authorized environment.

```python
from redteam_harness.core.models import AttackPhase
from redteam_harness.core.subprocess_plugin import SafeSubprocessPlugin

class ExamplePlugin(SafeSubprocessPlugin):
    name = "example"
    executable = "example-tool"
    supported_phases = {AttackPhase.INITIAL_ACCESS}
```

Do not add `shell=True`. Do not accept arbitrary executable paths from campaign YAML. Keep authentication out of the config file and inject it from environment variables or the deployment secret store.
