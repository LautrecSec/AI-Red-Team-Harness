# External Tools

The core harness is intentionally independent of any one red-team engine. External engines are optional adapters.

## Promptfoo

Use for structured evaluations, repeatable regression suites, policy assertions and CI gates. Install Promptfoo separately, then configure an argv command in the campaign.

## Garak

Use for broad vulnerability/probe coverage and model-level scanning. Garak target configuration varies by provider, so this public repository does not hard-code an internal provider or credential model.

## PyRIT

Use for multi-turn and orchestrated adversarial testing. PyRIT integrations are environment-specific, so this adapter is opt-in and requires an explicit argv command.

## Why wrappers instead of bundling everything?

Keeping scanners optional reduces image size and attack surface, allows independent scanner upgrades, and makes the harness useful in environments where only one approved scanner is permitted.
