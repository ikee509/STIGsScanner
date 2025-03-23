from fastapi import HTTPException
import hmac
import json
from pathlib import Path

async def verify_api_key(api_key: str) -> bool:
    """Verify API key from agent"""
    try:
        config_path = Path("/etc/stig-central/config.json")
        with open(config_path) as f:
            config = json.load(f)
            
        valid_keys = config.get("api_keys", {})
        
        if api_key not in valid_keys:
            raise HTTPException(
                status_code=403,
                detail="Invalid API key"
            )
            
        return True
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error verifying API key: {str(e)}"
        ) 