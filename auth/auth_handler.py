# ============================================================
# auth/auth_handler.py
# Gestión de JSON Web Tokens (JWT) para autenticación
# ============================================================

from datetime import datetime, timezone, timedelta
from jose import jwt, JWTError  # PyJWT para crear/verificar tokens
import os
import secrets
from dotenv import load_dotenv

# Cargar variables de entorno desde archivo .env
load_dotenv()

# ============================================================
# Configuración de JWT
# ============================================================

# SECRET_KEY: Clave privada para firmar tokens (debe ser segura en producción)
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    # Si no existe en .env, generar una clave aleatoria (solo para desarrollo)
    SECRET_KEY = secrets.token_urlsafe(32)

# ALGORITHM: Algoritmo de encriptación (HS256 = HMAC con SHA-256)
# Opciones: HS256 (simétrico), RS256 (asimétrico), etc.
ALGORITHM = os.getenv("ALGORITHM", "HS256")

# Tiempo de expiración del token en minutos
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))


def crear_token(data: dict, expiration: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    """
    Crea un token JWT firmado con la información del usuario.
    
    Args:
        data (dict): Datos a incluir en el payload (ejemplo: {"sub": "usuario123"})
        expiration (int): Tiempo de expiración en minutos
    
    Returns:
        str: Token JWT codificado
    
    Flujo JWT:
        1. Se crea un payload con datos del usuario
        2. Se agrega la fecha de expiración (exp)
        3. Se firma el payload con SECRET_KEY usando el algoritmo especificado
        4. Se retorna el token en formato: header.payload.signature
    
    Ejemplo de payload:
        {
            "sub": "juan_perez",           # Subject (identificador del usuario)
            "exp": 1700000000,             # Expiration time (timestamp Unix)
            "iat": 1699998000              # Issued at (timestamp Unix)
        }
    """
    # Hacer copia del diccionario para no modificar el original
    to_encode = data.copy()
    
    # Calcular la fecha de expiración (ahora + tiempo especificado)
    expire = datetime.now(timezone.utc) + timedelta(minutes=expiration)
    
    # Agregar el claim 'exp' (expiration) al payload
    to_encode.update({"exp": expire})
    
    # Codificar el token con la clave secreta y algoritmo
    # Resultado: string con formato base64.base64.base64
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt


def verificar_token(token: str) -> dict | None:
    """
    Verifica y decodifica un token JWT.
    
    Args:
        token (str): Token JWT a verificar
    
    Returns:
        dict | None: Payload del token si es válido, None si es inválido/expirado
    
    Validaciones:
        - Verifica la firma (solo el servidor con SECRET_KEY puede verificar)
        - Verifica la expiración (si exp < ahora, token expirado)
        - Verifica el algoritmo coincida con el configurado
    """
    try:
        # Decodificar el token verificando firma y expiración
        # Lanza JWTError si token es inválido, expirado o con firma incorrecta
        payload = jwt.decode(
            token, 
            SECRET_KEY, 
            algorithms=[ALGORITHM]
        )
        return payload
    
    except JWTError as e:
        # Token expirado, inválido o firmado con otra clave
        # Retornamos None para indicar que el token no es válido
        print(f"Error al verificar token: {str(e)}")
        return None 
    
    