from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from routes.auth import decodeJWT

class jwtBearer(HTTPBearer):
    def __init__(self, auto_Error: bool = True):
        super(jwtBearer, self).__init__(auto_error=auto_Error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(jwtBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid or Expired Token")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid or Expired Token")

    def verify_jwt(self, jwtoken: str):
        isTokenValid: bool = False
        try:
            payload = decodeJWT(jwtoken)
            # Check if the payload contains the required fields (email and session_id)
            if "email" in payload and "session_id" in payload:
                # Here you can perform additional checks if needed
                isTokenValid = True
        except:
            payload = None
        return isTokenValid
