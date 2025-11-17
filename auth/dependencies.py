# ============================================================
# auth/dependencies.py
# Dependencias de autenticación para rutas protegidas
# ============================================================

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from core.database import get_db
from models.user_model import User
from auth.auth_handler import verificar_token

# ============================================================
# Configuración de seguridad HTTP Bearer
# ============================================================

# HTTPBearer: esquema de autenticación que espera:
# Header: "Authorization: Bearer <token>"
# Extrae automáticamente el token del header
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Obtiene el usuario actual autenticado desde el token JWT.
    
    Esta función actúa como middleware de autenticación para rutas protegidas.
    Se usa como dependencia en @app.get(), @app.post(), etc.
    
    Args:
        credentials: Token extraído del header Authorization
        db: Sesión de base de datos
    
    Returns:
        User: Objeto usuario de la base de datos
    
    Raises:
        HTTPException 401: Si token inválido, expirado o usuario no existe
    
    Flujo de validación:
        1. Extraer token del header (HTTPBearer lo hace automáticamente)
        2. Verificar firma y expiración del token
        3. Extraer username del payload
        4. Consultar usuario en base de datos
        5. Retornar usuario o lanzar excepción
    
    Ejemplo de uso en una ruta:
        @app.get("/me")
        async def get_profile(current_user: User = Depends(get_current_user)):
            return current_user
    """
    # Extraer el token JWT del header Authorization
    token = credentials.credentials
    
    # Verificar token: decodificar, validar firma y expiración
    payload = verificar_token(token)
    
    # Si token inválido, expirado o con firma incorrecta
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Extraer el 'sub' (subject) del payload
    # Por convención, 'sub' contiene el identificador del usuario (username)
    username = payload.get("sub")
    
    # Si falta información de usuario en el token
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido: falta información de usuario",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Consultar usuario en base de datos
    user = db.query(User).filter(User.username == username).first()
    
    # Si usuario no existe en BD (por ejemplo, fue eliminado después de login)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Si usuario está desactivado
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuario desactivado",
        )
    
    # Retornar objeto usuario para usar en la ruta
    return user 

        

