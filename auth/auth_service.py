# ============================================================
# auth/auth_service.py
# Servicios de encriptación de contraseñas con Passlib
# ============================================================

from passlib.context import CryptContext

# ============================================================
# Configuración de Passlib
# ============================================================

# HASH_SCHEMA: Algoritmo de hash usado para encriptar contraseñas
# "argon2" es uno de los más seguros (resistente a ataques GPU/GPU)
# Otras opciones: "bcrypt", "scrypt"
HASH_SCHEMA = "argon2"

# Crear contexto de cifrado con argon2 como principal
# deprecated="auto" indica que acepte hashes antiguos pero cree nuevos con argon2
pwd_context = CryptContext(
    schemes=[HASH_SCHEMA],
    deprecated="auto"
)


def hashear_password(password: str) -> str:
    """
    Encripta una contraseña en texto plano usando Passlib con Argon2.
    
    Args:
        password (str): Contraseña en texto plano
    
    Returns:
        str: Contraseña hasheada (irreversible)
    
    ¿Qué es el hashing?
        - Es una función unidireccional que convierte texto en un hash único
        - Imposible revertir: de hash no se puede obtener la contraseña original
        - Mismo input = mismo output (determinístico)
        - Un pequeño cambio en input = hash completamente diferente
    
    ¿Por qué Argon2?
        - Resistente a ataques de fuerza bruta
        - Usa memoria intensiva (previene GPU cracking)
        - Estándar recomendado por OWASP 2023
        - Más seguro que bcrypt o MD5
    
    Ejemplo de salida:
        "$argon2id$v=19$m=65540,t=3,p=4$salt123$hash_muy_largo_aqui"
    """
    return pwd_context.hash(password)


def verificar_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica si una contraseña en texto plano coincide con su hash.
    
    Args:
        plain_password (str): Contraseña en texto plano (de login)
        hashed_password (str): Contraseña hasheada (de base de datos)
    
    Returns:
        bool: True si coinciden, False si no
    
    Flujo:
        1. Usuario ingresa contraseña en login
        2. Se hashea la contraseña ingresada
        3. Se compara con el hash almacenado en BD
        4. Si hashes coinciden, contraseña es correcta
    
    Nota de seguridad:
        - Passlib usa "timing-safe comparison" para prevenir timing attacks
        - Timing attack: medir cuánto tarda la comparación para adivinar contraseña
        - La función resiste estos ataques automáticamente
    """
    return pwd_context.verify(plain_password, hashed_password)

