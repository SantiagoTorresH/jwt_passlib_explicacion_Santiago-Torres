# Sistema de Autenticación Segura con JWT y Passlib

> **Explicando Seguridad en Acción: Autenticación JWT y Encriptación con Passlib**

## 📋 Descripción del Problema

En aplicaciones modernas, es crítico proteger la información del usuario y autenticar solicitudes de forma segura. Este proyecto implementa un sistema completo de autenticación que resuelve dos problemas fundamentales:

1. **Almacenamiento seguro de contraseñas**: Las contraseñas NO deben guardarse en texto plano. Usamos **Passlib con Argon2** para aplicar hashing irreversible.

2. **Autenticación sin sesiones**: En APIs REST, usamos **JWT (JSON Web Tokens)** para crear tokens firmados que verifican la identidad sin depender de sesiones del servidor.

### ¿Por qué es importante?

- 🔐 **Passlib + Argon2**: Resistente a ataques de fuerza bruta y GPU cracking
- 🎫 **JWT**: Tokens sin estado (stateless), escalables y seguros
- ✅ **Validación en múltiples niveles**: registro, login, verificación de token, autorización por roles

---

## 🔄 Flujo de Autenticación Completo

```
┌─────────────────────────────────────────────────────────────┐
│                   REGISTRO (POST /register)                 │
├─────────────────────────────────────────────────────────────┤
│ 1. Usuario envía: {"username": "juan", "password": "abc123"} │
│ 2. Sistema valida longitud (min 3-6 caracteres)            │
│ 3. Hashea contraseña con Passlib+Argon2                    │
│ 4. Guarda en BD: {username, hashed_password, role, etc}    │
│ 5. Retorna: {"id": 1, "username": "juan", "role": "user"}  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    LOGIN (POST /login)                      │
├─────────────────────────────────────────────────────────────┤
│ 1. Usuario envía: {"username": "juan", "password": "abc123"}│
│ 2. Sistema busca usuario en BD por username                 │
│ 3. Usa verificar_password() para comparar hashes            │
│ 4. Si válido, crea JWT con: {"sub": "juan", "exp": ...}    │
│ 5. Retorna: {"access_token": "eyJ...", "token_type": "bearer", "user": {...}} │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│             RUTAS PROTEGIDAS (GET /me, GET /admin)          │
├─────────────────────────────────────────────────────────────┤
│ 1. Cliente envía: Header "Authorization: Bearer eyJ..."     │
│ 2. FastAPI extrae token con HTTPBearer()                   │
│ 3. Verifica firma y expiración del JWT                     │
│ 4. Busca usuario en BD usando 'sub' del token              │
│ 5. Valida rol (admin/user) si es necesario                 │
│ 6. Si todo OK, retorna datos. Si falla, 401 Unauthorized   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔐 Passlib: Hashing Seguro de Contraseñas

### ¿Qué es Passlib?

Librería Python que maneja encriptación de contraseñas con buenos defaults. **Nunca guardes contraseñas en texto plano.**

### Algoritmo: Argon2

```python
# Contraseña en texto plano
password = "miPassword123"

# Después de hashear con Argon2
hashed = "$argon2id$v=19$m=65540,t=3,p=4$salt_aleatorio$hash_muy_largo"
```

**Características de Argon2:**
- ✅ Resistente a GPU/ASIC cracking (usa mucha memoria)
- ✅ Recomendado por OWASP 2023
- ✅ Incluye salt aleatorio automáticamente
- ✅ Irreversible (no se puede obtener la contraseña del hash)

### Flujo Práctico:

**1. Registro:**
```python
from auth.auth_service import hashear_password

password_usuario = "abc123"
hashed = hashear_password(password_usuario)
# Guardar en BD: hashed (nunca password_usuario)
```

**2. Login:**
```python
from auth.auth_service import verificar_password

password_ingresado = "abc123"
hashed_en_bd = usuario.hashed_password

es_correcto = verificar_password(password_ingresado, hashed_en_bd)
# True si coinciden, False si no
```

---

## 🎫 JWT: JSON Web Tokens

### ¿Qué es JWT?

Token firmado en tres partes: `header.payload.signature`

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiJqdWFuIiwiZXhwIjoxNzAwMDAwMDAwfQ.
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

### Partes del JWT:

#### Header (Parte 1)
```json
{
  "alg": "HS256",   // Algoritmo de firma
  "typ": "JWT"      // Tipo de token
}
```

#### Payload (Parte 2)
```json
{
  "sub": "juan",                    // Subject (ID del usuario)
  "exp": 1700000000,                // Expiration (fecha Unix)
  "iat": 1699998000,                // Issued at (cuándo se creó)
  "username": "juan",
  "role": "user"
}
```

#### Signature (Parte 3)
```
HMAC-SHA256(
  base64(header) + "." + base64(payload),
  SECRET_KEY
)
```

### ¿Cómo se Genera?

```python
from auth.auth_handler import crear_token

# En el login, después de validar contraseña:
token = crear_token({"sub": usuario.username})
# Retorna: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Expira en 30 minutos (configurable en .env)
```

### ¿Cómo se Verifica?

```python
from auth.auth_handler import verificar_token

# En rutas protegidas:
payload = verificar_token(token_del_header)

if payload:
    username = payload.get("sub")  # "juan"
    # Token válido y no expirado
else:
    # Token inválido, expirado o firmado con otra clave
    # Lanzar 401 Unauthorized
```

### Flujo en FastAPI:

```python
from fastapi import Depends
from auth.dependencies import get_current_user

@app.get("/me")
async def get_profile(current_user: User = Depends(get_current_user)):
    """
    Ruta protegida. Automáticamente:
    1. Extrae token del header Authorization
    2. Verifica firma y expiración
    3. Busca usuario en BD
    4. Lo retorna si es válido
    """
    return current_user
```

---

## 📁 Estructura del Proyecto

```
jwt_passlib_Santiago-Torres/
├── auth/
│   ├── __init__.py
│   ├── auth_handler.py      # Crear y verificar tokens JWT
│   ├── auth_service.py       # Hashear y verificar contraseñas
│   └── dependencies.py       # Middleware de autenticación
├── core/
│   ├── __init__.py
│   ├── database.py           # Conexión a PostgreSQL
│   └── logger.py             # Sistema de logging
├── models/
│   ├── __init__.py
│   └── user_model.py         # Modelo User (tabla users)
├── routes/
│   ├── __init__.py
│   └── user_routes.py        # Endpoints /register, /login, /me, /admin
├── schemas/
│   ├── __init__.py
│   └── user_schemas.py       # Validación con Pydantic
├── main.py                   # Aplicación FastAPI principal
├── streamlit_app.py          # Interfaz de usuario con Streamlit
├── requirements.txt          # Dependencias Python
├── env.example               # Variables de entorno (ejemplo)
├── .env                      # Variables de entorno (local, no en git)
└── README.md                 # Este archivo
```

---

## 🚀 Instalación y Ejecución

### 1. Clonar el Repositorio

```bash
git clone https://github.com/tu-usuario/jwt_passlib_Santiago-Torres
cd jwt_passlib_Santiago-Torres
```

### 2. Crear Entorno Virtual

```bash
# Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalar Dependencias

```bash
pip install -r requirements.txt
```

### 4. Configurar Variables de Entorno

```bash
# Copiar archivo de ejemplo
Copy-Item env.example .env  # Windows
# cp env.example .env       # Linux/Mac

# Editar .env con tus datos (especialmente DB_PASS y SECRET_KEY)
```

### 5. Generar SECRET_KEY Segura

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
# Copiar salida y pegarla en .env como SECRET_KEY
```

### 6. Configurar Base de Datos PostgreSQL

```bash
# Crear base de datos (asume PostgreSQL instalado)
createdb -U postgres autenticacion

# Las tablas se crearán automáticamente al ejecutar main.py
```

### 7. Ejecutar la Aplicación

```bash
# Terminal 1: Backend FastAPI
python main.py
# Se abrirá http://127.0.0.1:8000/docs (Swagger UI)

# Terminal 2: Frontend Streamlit (opcional)
streamlit run streamlit_app.py
# Se abrirá http://localhost:8501
```

---

## 📝 Ejemplo de Uso

### 1. Registrar Usuario (Postman o cURL)

```bash
POST http://localhost:8000/api/v1/register
Content-Type: application/json

{
  "username": "juan_perez",
  "password": "MiPassword123!",
  "role": "user"
}
```

**Respuesta:**
```json
{
  "id": 1,
  "username": "juan_perez",
  "role": "user",
  "is_active": true,
  "created_at": "2025-11-14T10:30:00",
  "updated_at": null
}
```

### 2. Login

```bash
POST http://localhost:8000/api/v1/login
Content-Type: application/json

{
  "username": "juan_perez",
  "password": "MiPassword123!"
}
```

**Respuesta:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqdWFuX3BlcmV6IiwiZXhwIjoxNzAwMDAxODAwfQ.xKH...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "username": "juan_perez",
    "role": "user",
    "is_active": true,
    "created_at": "2025-11-14T10:30:00",
    "updated_at": null
  }
}
```

### 3. Acceder a Ruta Protegida

```bash
GET http://localhost:8000/api/v1/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqdWFuX3BlcmV6IiwiZXhwIjoxNzAwMDAxODAwfQ.xKH...
```

**Respuesta:**
```json
{
  "id": 1,
  "username": "juan_perez",
  "role": "user",
  "is_active": true,
  "created_at": "2025-11-14T10:30:00",
  "updated_at": null
}
```

---

## 🛡️ Buenas Prácticas Implementadas

### 1. **Contraseñas Seguras**
- ✅ Hashing con Argon2 (no MD5, no SHA1)
- ✅ Salt aleatorio incluido automáticamente
- ✅ Nunca se almacenan en texto plano
- ✅ Comparación resistente a timing attacks

### 2. **Tokens Seguros**
- ✅ Expiración automática (30 min por defecto)
- ✅ Firma con SECRET_KEY (solo servidor puede verificar)
- ✅ Validación de algoritmo (HS256)
- ✅ Claims personalizados (sub, exp, iat)

### 3. **Validación de Entrada**
- ✅ Longitud mínima de username (3 caracteres)
- ✅ Longitud mínima de password (6 caracteres)
- ✅ Caracteres permitidos en username (alfanuméricos, -, _)
- ✅ Validación con Pydantic en esquemas

### 4. **Manejo de Errores**
- ✅ 401 Unauthorized para tokens inválidos
- ✅ 403 Forbidden para acceso denegado
- ✅ Mensajes de error genéricos (no revelar información sensible)
- ✅ Logging de errores para auditoría

### 5. **Estructura del Código**
- ✅ Separación de responsabilidades (auth, routes, models, schemas)
- ✅ Funciones con docstrings completos
- ✅ Comentarios explicativos en partes complejas
- ✅ Tipos de datos explícitos (type hints)

### 6. **Configuración Segura**
- ✅ Variables de entorno (.env) para datos sensibles
- ✅ SECRET_KEY no en repositorio (en .gitignore)
- ✅ Diferentes configs para dev/prod
- ✅ Validación de variables requeridas

---

## 📊 Análisis de Seguridad

### Amenazas Prevenidas:

| Amenaza | Solución | Evidencia |
|---------|----------|-----------|
| **Fuerza Bruta en Contraseñas** | Argon2 con memory-hard | `auth_service.py` usa Argon2 |
| **Contraseñas en Texto Plano** | Hashing irreversible | `hashear_password()` siempre |
| **Tokens Forjados** | Firma con SECRET_KEY | `crear_token()` firma payload |
| **Tokens Expirados** | Verificación de exp claim | `verificar_token()` valida exp |
| **Acceso Sin Autenticación** | Dependencia get_current_user | Todas las rutas /me, /admin la usan |
| **SQL Injection** | ORM (SQLAlchemy) | Todas las queries usan .filter() |
| **CORS no Autorizado** | Whitelist de orígenes | `CORSMiddleware` en main.py |

### Limitaciones Conocidas:

⚠️ **Producción**: Considera implementar:
- Refresh tokens (para expiración más corta de access tokens)
- Rate limiting (prevenir fuerza bruta)
- HTTPS obligatorio (tokens viajan en headers)
- 2FA (autenticación de dos factores)
- Auditoría de intentos fallidos
- Revocación de tokens (blacklist)

---

## 📚 Conceptos Clave Explicados

### Password Hashing vs Encryption

```python
# ❌ INCORRECTO: Encryption (reversible)
encrypted = algoritmo_aes.encrypt("password")
# Un atacante puede decriptar con la clave

# ✅ CORRECTO: Hashing (irreversible)
hashed = passlib.hash("password")
# Imposible obtener "password" del hash, solo verificar
```

### Stateless vs Stateful

```python
# ❌ Sessions Stateful (antiguo)
# Servidor guarda sesión en memoria/BD
# Cliente envía session_id
# Server toma espacio

# ✅ JWT Stateless (moderno)
# Servidor solo VERIFICA el JWT, no lo guarda
# Cliente envía token con datos
# Escalable horizontalmente
```

### Timing Attacks

```python
# ❌ VULNERABLE
if password == hashed:  # Comparación normal
    # Atacante puede medir tiempo para adivinar

# ✅ SEGURO
if pwd_context.verify(password, hashed):  # Passlib
    # Tiempo siempre igual (timing-safe)
```

---

## 🎬 Video Explicativo

> **[Enlace al video (5-8 minutos)](https://youtu.be/43biV9-cgs8)**


---

## 💡 Conclusiones y Aprendizajes

### ¿Qué aprendí sobre Seguridad?

1. **No reinventar la rueda**: Usar librerías probadas (Passlib, PyJWT) es más seguro que código casero.

2. **Defense in Depth**: Múltiples capas:
   - Validación de entrada (min length)
   - Hashing seguro (Argon2)
   - Firma de tokens (SECRET_KEY)
   - Expiración (exp claim)
   - Validación de rol (admin/user)

3. **Stateless es Escalable**: JWT permite servidores sin estado, crítico para APIs y microservicios.

4. **Detalles Importan**: Timing attacks, salt aleatorio, comparación segura... los atacantes explotan pequeños detalles.

5. **Seguridad ≠ Usabilidad**: Siempre hay trade-offs. JWT corto (fácil) vs Refresh tokens (seguro).



## 👨‍💻 Autor

**Santiago Torres** - Módulo 7: Seguridad y Autenticación

---

**Última actualización:** Noviembre 18, 2025
