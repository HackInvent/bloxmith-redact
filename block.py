"""Configured text/JSON minimization with wallet-owned pseudonym keys."""

import json
from bloxsmith_app.block_api import APPLICATION_JSON, TEXT_PLAIN, BlockDefinition, BlockRuntimeOutput, BlockRuntimeResult
from . import logic, ui


# FB1 - Apply explicit JSON-field, literal and bounded email rules without interpreting content as instructions.
# FB2 - Distinguish fixed masking, structural field removal and keyed deterministic pseudonyms.
# FB3 - Enforce input, shape and replacement limits and never report original values or resolved keys.
# FB4 - Use public runtime inputs and wallet resolution in both runtimes and package origins.
# FB5 - Provide translated responsive configuration, conditional controls and preserved UI drafts.
class RedactBlock(BlockDefinition):
    """Configured minimization is not universal anonymization or binary/PDF redaction."""

    kind = "redact"

    def ui_assets(self, surface="modal"):
        return list(self.model.get("ui_assets", {}).get(surface, []))

    def execute_runtime(self, context):
        try:
            if not context.has_input_value("content", "1"):
                return BlockRuntimeResult(status="skipped", outputs=[])
            if len(context.input_events) > 1:
                raise logic.RedactError("Send one document per activation.")
            values = logic.process(context.input_value("content", "1"), context.config,
                                   context.resolve_secret, context.services.get("cancel_requested", lambda: False))
            mime = APPLICATION_JSON if values["report"]["format"] == "json" else TEXT_PLAIN
            outputs = [BlockRuntimeOutput(port_id=int(port.id), port_name=port.name,
                value=values[port.name] if port.name == "redacted" else json.dumps(values[port.name]),
                content_type=mime if port.name == "redacted" else APPLICATION_JSON)
                for port in context.output_ports if port.name in values]
            return BlockRuntimeResult(status="success", outputs=outputs, content_type=mime,
                metadata={self.kind: {"replacements": values["report"]["total"]}},
                logs=["[redact] Configured minimization completed."])
        except (ValueError, TypeError, RuntimeError, OSError, RecursionError) as exc:
            detail = str(exc) if isinstance(exc, logic.RedactError) else "Content could not be safely minimized."
            message = self.translate("block.redact.error", {"detail": detail}, fallback="Redaction failed: {detail}")
            return BlockRuntimeResult(status="failed", outputs=[], error=message, exit_code=1,
                                      logs=["[redact-error] " + detail])

    def handle_ui_action(self, *, node, action, values, payload=None):
        if action in {"save_settings", "modal_update_fields", "inspector_update_fields"}:
            patch = (values or {}).get("node_patch") or {}
            if "config" in patch:
                try:
                    logic.configuration({**self.default_config(), **(node.get("config") or {}), **patch["config"]})
                except (ValueError, TypeError):
                    return {"error": self.translate("block.redact.error", {"detail": "Invalid redaction settings."},
                                                   fallback="Redaction failed: {detail}")}
        result = super().handle_ui_action(node=node, action="modal_update_fields" if action == "save_settings" else action,
                                         values=values, payload=payload)
        return ui.replace_config(result, node)

    def render_modal(self, *, node, payload=None):
        return ui.modal(self, node, payload)

    def render_inspector_panel(self, *, node, payload=None):
        return ui.inspector(self, node, payload)

    def render_node_card(self, *, node, payload=None):
        config = node.get("config") or {}
        return ui.card(self, node, str(config.get("input_format", "text")) + " · " + str(config.get("action", "mask")))
