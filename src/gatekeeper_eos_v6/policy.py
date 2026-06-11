"""Gatekeeper v0.1: Binary whitelist policy - SHIPPED"""


class GatekeeperPolicy:
    """Binary whitelist policy: Explicit allow, everything else block.
    
    Property:
    - Unknown tool → BLOCK
    - Missing tool → BLOCK
    - Only explicitly allowed tools → ALLOW
    """
    
    ALLOWED_TOOLS = {"read_file"}
    
    def evaluate_action(self, payload: dict) -> dict:
        tool = payload.get("tool")
        
        # Default deny: No tool specified → BLOCK
        if tool is None:
            return {"status": "BLOCK"}
        
        # Explicit allow: Only allowed tools → ALLOW
        if tool in self.ALLOWED_TOOLS:
            return {"status": "ALLOW"}
        
        # Default deny: Unknown tool → BLOCK
        return {"status": "BLOCK"}
