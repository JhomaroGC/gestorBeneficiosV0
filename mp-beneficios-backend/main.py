from fastapi import Path
from enum import Enum
import uuid
from passlib.hash import pbkdf2_sha256
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, ForeignKey, DateTime, Date
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime, timedelta
from passlib.context import CryptContext

from jose import JWTError, jwt, ExpiredSignatureError

# ----------Configuración---------#
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
DATABASE_URL = "sqlite:///./mp_beneficios.db"

"""
Explicación:
SECRET_KEY: Es una cadena secreta utilizada para firmar y verificar los tokens JWT (JSON Web Tokens). Es fundamental para la seguridad de la autenticación.
ALGORITHM: Especifica el algoritmo criptográfico que se usará para firmar los JWT. En este caso, es "HS256" (HMAC con SHA-256).
DATABASE_URL: Es la URL de conexión a la base de datos. Aquí se está usando SQLite y el archivo de la base de datos se llama mp_beneficios.db, que estará en el mismo directorio donde se ejecuta la aplicación.
"""

# ----------Base de datos---------#
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

"""
Explicación:
engine: Crea una conexión a la base de datos utilizando la URL proporcionada. El parámetro connect_args={"check_same_thread": False} es específico de SQLite y permite que la conexión sea utilizada en múltiples hilos.
SessionLocal: Es una fábrica de sesiones que se utilizará para interactuar con la base de datos. Cada vez que se necesite una sesión, se llamará a SessionLocal() para obtener una nueva instancia.   
Base: Es la clase base para los modelos de la base de datos. Todos los modelos que definamos (tablas) heredarán de esta clase.
"""
# ----------Modelos DB---------#


class UserDB(Base):
    """
- class User(Base): Define un modelo que hereda de la clase base de SQLAlchemy.
__tablename__: Especifica el nombre de la tabla en la base de datos.
- Cada atributo (id, name, etc.) es una columna de la tabla.
- relationship("BenefitRequestDB", back_populates="users"): Define una relación con otra tabla llamada BenefitRequestDB, permitiendo acceder a las solicitudes de beneficios asociadas a cada usuario.
- En resumen:
Este modelo representa a los usuarios en la base de datos, con campos para su información básica, contraseña cifrada, rol, fecha de creación y la relación con las solicitudes de beneficios.

    Args:
        Base (_type_): _description_
    """
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    cedula = Column(String, index=True)
    name = Column(String)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    rol = Column(String, default="Usuario")
    user_status = Column(String, default="activo")
    created_at = Column(DateTime, default=datetime.now().today().date())
    request = relationship("BenefitRequestDB", back_populates="users")


class BenefitRequestDB(Base):
    """
    __tablename__: Define el nombre de la tabla en la base de datos.
id: Columna entera, clave primaria, identificador único de la solicitud.
user_id: Columna entera, clave foránea que conecta cada solicitud con un usuario específico.
benefit_type: Columna de texto para el tipo de beneficio solicitado.
status: Columna de texto para el estado de la solicitud (por ejemplo, "pending", "approved").
created_at: Fecha de creación de la solicitud.
users = relationship("UserDB", back_populates="request"): Relación ORM que permite acceder al usuario asociado a la solicitud.

    Args:
        Base (_type_): _description_
    """
    __tablename__ = "benefit_requests"
    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"))
    user_cedula = Column(String)
    user_name = Column(String)
    user_email = Column(String)
    benefit_type = Column(String)
    status = Column(String, default="Solicitado")
    consumido_en = Column(String, default="Sin consumir")
    created_at = Column(DateTime, default=datetime.now().today().date())
    users = relationship("UserDB", back_populates="request")


Base.metadata.create_all(bind=engine)
"""
Explicación:crea en la base de datos todas las tablas definidas por los modelos (UserDB, BenefitRequestDB) si no existen aún.
Utiliza el motor de conexión (engine) configurado previamente para ejecutar la creación de las tablas.
En resumen: Inicializa la estructura de la base de datos según los modelos definidos en el código.
"""
# ----------Schemas Pydantic---------#
"""
En esta sección se define clases que sirven para validar y estructurar los datos que entran y salen de la API.
Estas clases heredan de BaseModel de Pydantic y se usan para:

- Validar los datos recibidos en las solicitudes (por ejemplo, al crear un usuario).
- Definir cómo se verán las respuestas de la API (por ejemplo, al devolver información de un usuario).
- Asegurar que los datos tengan el tipo y formato correcto.
"""


class UserCreate(BaseModel):
    """
    Valida los datos necesarios para crear un usuario

    Args:
        BaseModel (_type_): _description_
    """
    cedula: str
    name: str
    email: str
    password: str
    rol: str
    user_status: str


class UserResponse(BaseModel):
    """define como se devuelve la información de un usuario

    Args:
        BaseModel (_type_): _description_
    """
    id: str
    cedula: str
    name: str
    email: str
    rol: str
    user_status: str
    created_at: datetime


class Token(BaseModel):
    """Estructura la respuesta al autenticar, incluyendo el token y los datos del usuario

    Args:
        BaseModel (_type_): _description_
    """
    access_token: str
    token_type: str
    user: UserResponse


class BenefitRequestCreate(BaseModel):
    """Valida los datos necesarios para crear una solicitud de beneficio

    Args:
        BaseModel (_type_): _description_
    """
    benefit_type: str


class LoginRequest(BaseModel):
    """ 
    Especifica que el JSON enviado al hacer login debe tener dos campos: email (cadena) y password (cadena).
FastAPI usa esta clase para validar automáticamente que los datos recibidos sean correctos antes de ejecutar la función de login.
    """
    email: str
    password: str


class BenefitRequestUpdateResponse(BaseModel):
    """
    Define la estructura de salida cuando se actualiza el estado de una solicitud de beneficio.

    Campos:
    - id: Identificador único de la solicitud.
    - user_id: Identificador del usuario dueño de la solicitud.
    - cedula: Documento de identidad del usuario.
    - nombre: Nombre del usuario.
    - email: Correo electrónico del usuario.
    - benefit_type: Tipo de beneficio solicitado.
    - status: Estado actualizado de la solicitud (ej. 'Consumido').
    - created_at: Fecha de creación de la solicitud.
    """
    id: str
    user_id: str
    cedula: str
    nombre: str
    email: str
    benefit_type: str
    status: str
    created_at: datetime


class BenefitRequestTiendasResponse(BaseModel):
    """Define como se devuelve la información de una solicitud de beneficio

    Args:
        BaseModel (_type_): _description_
    """
    id: str
    user_id: str
    cedula: str
    nombre: str
    email: str
    benefit_type: str
    status: str
    consumido_en: str
    created_at: datetime

    class Config:
        """Permite que el modelo Pydantic pueda leer datos directamente desde objetos ORM de SQLAlchemy (como los que devuelven las consultas a la base de datos), no solo desde diccionarios.
        Esto facilita convertir los resultados de la base de datos en respuestas JSON automáticamente."""
        orm_mode = True


class BenefitRequestResponse(BaseModel):
    """Define como se devuelve la información de una solicitud de beneficio

    Args:
        BaseModel (_type_): _description_
    """
    id: str
    user_id: str
    cedula: str
    nombre: str
    email: str
    benefit_type: str
    status: str
    consumido_en: str
    created_at: datetime

    class Config:
        """Permite que el modelo Pydantic pueda leer datos directamente desde objetos ORM de SQLAlchemy (como los que devuelven las consultas a la base de datos), no solo desde diccionarios.
        Esto facilita convertir los resultados de la base de datos en respuestas JSON automáticamente."""
        orm_mode = True


# ----------Utilidades---------#
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
""" 
Explicación: Crea un contexto de cifrado de contraseñas usando la librería passlib.

Especifica que se usará el algoritmo bcrypt para cifrar y verificar contraseñas.
Permite manejar de forma segura el almacenamiento y la comparación de contraseñas en la base de datos.
En resumen: Prepara las funciones para cifrar y validar contraseñas de usuarios.

"""


def hash_password(password: str) -> str:
    safe_password = password[:71]  # Truncar a 72 caracteres
    return pbkdf2_sha256.hash(safe_password)


app = FastAPI()  # Inicialización de la aplicación FastAPI

# , "https://gestorbeneficiosv0-3.onrender.com" (Permitir que React acceda a la API)

origins = ["https://gestorbeneficiosv0-4.onrender.com/tiendas"]
app.add_middleware(
    CORSMiddleware,
    # Url del frontend de React
    # allow_origins=["http://127.0.0.1:5000", "http://localhost:5000"],
    allow_origins = origins,
    allow_credentials=True,
    allow_methods=["*"],  # Permitir todos los métodos HTTP
    allow_headers=["*"],  # Permitir todos los encabezados
)
"""
CORS (Cross-Origin Resource Sharing) configura los permisos para que aplicaciones web que se ejecutan en un dominio diferente (por ejemplo, tu frontend en React en http://localhost:3000) puedan acceder a la API de FastAPI.

En este código, se agrega el middleware CORSMiddleware y se permite:
Que el frontend en http://localhost:3000 haga peticiones a la API.
El uso de credenciales (cookies, headers de autenticación, etc.).
Todos los métodos HTTP (GET, POST, PUT, etc.).
Todos los encabezados.
Esto es necesario cuando el frontend y el backend están en servidores diferentes, para evitar bloqueos por políticas de seguridad del navegador.
"""


def get_db():
    """Proporciona una sesión de base de datos para cada solicitud y se asegura de cerrarla después de usarla.

    Yields:
        _type_: _description_
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(data: dict, expires_delta: int = 300000):
    """Crea un token JWT con una fecha de expiración. Este token se usa para autenticar usuarios en la API, permitiendo que accedan a rutas protegidas mientras el token sea válido.

    Args:
        data (dict): Datos que se incluirán en el token.
        expires_delta (int, optional): Tiempo en minutos para que el token expire. Defaults to 30.

    Returns:
        _type_: _description_
    """
    to_encode = data.copy()
    expire = datetime.now() + timedelta(minutes=expires_delta)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(lambda x: x), db: Session = Depends(get_db)):
    """Obtiene el usuario actual basado en el token JWT proporcionado. Si el token es inválido o ha expirado, lanza una excepción de autenticación.

    Args:
        token (str, optional): Token JWT. Defaults to Depends(lambda: None).
        db (Session, optional): Sesión de base de datos. Defaults to Depends(get_db).

    Raises:
        HTTPException: Si el token es inválido o ha expirado.

    Returns:
        _type_: _description_
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user
    """
     obtiene el usuario actual a partir de un token JWT enviado en la solicitud.

¿Cómo funciona?

Recibe el token JWT y una sesión de base de datos.
Intenta decodificar el token usando la clave secreta y el algoritmo configurados.
Extrae el user_id del token (campo "sub").
Si el token es inválido, ha expirado o no contiene el user_id, lanza una excepción de autenticación.
Busca en la base de datos el usuario con ese user_id.
Si no existe, lanza una excepción.
Si todo es correcto, retorna el usuario autenticado.
En resumen:
Valida el token y devuelve el usuario correspondiente, permitiendo proteger rutas que requieren autenticación.
    """


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


async def get_current_user_secure(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """ Obtiene el usuario actual basado en el token JWT proporcionado. Si el token es inválido o ha expirado, lanza una excepción de autenticación."""

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if not email:
            raise credentials_exception
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

    user = db.query(UserDB).filter(UserDB.email == email).first()
    if not user.email:
        raise credentials_exception
    return user

# ----------Rutas---------#


@app.get("/")
def read_root():
    return {"message": "Usa sólo los beneficios a los que tienes derecho, ver N54"}


@app.post("/register", response_model=Token)
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Registra un nuevo usuario en la base de datos, cifrando su contraseña y generando un token JWT para autenticación.

    Args:
        user (UserCreate): Datos del usuario a registrar.
        db (Session, optional): Sesión de base de datos. Defaults to Depends(get_db).

    Raises:
        HTTPException: Si el correo electrónico ya está registrado.
        """
    db_user = db.query(UserDB).filter(UserDB.email == user.email).first()
    if db_user:  # verifica si el usuario ya existe
        raise HTTPException(status_code=400, detail="Email already registered")
    new_user = UserDB(
        id=str(uuid.uuid4()),
        cedula=user.cedula,
        name=user.name,
        email=user.email,
        hashed_password=hash_password(
            user.password),
        rol=user.rol,
        user_status=user.user_status
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    access_token = create_access_token(data={"sub": new_user.email})
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "user": {
            "id": new_user.id,
            "cedula": new_user.cedula,
            "name": new_user.name,
            "email": new_user.email,
            "rol": new_user.rol,
            "user_status": new_user.user_status,
            "created_at": new_user.created_at,
        }
    }


@app.post("/login", response_model=Token)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    """Autentica a un usuario verificando su correo y contraseña, y genera un token JWT si las credenciales son correctas.

    Args:
        email (str): Correo electrónico del usuario.
        password (str): Contraseña del usuario.
        db (Session, optional): Sesión de base de datos. Defaults to Depends(get_db).

    Raises:
        HTTPException: Si las credenciales son incorrectas.

    Returns:
        _type_: _description_
    """
    # recibe json {email, password}
    user = db.query(UserDB).filter(UserDB.email == data.email).first()

    if not user or not pbkdf2_sha256.verify(data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email})
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "user": {
            "id": user.id,
            "cedula": user.cedula,
            "name": user.name,
            "email": user.email,
            "rol": user.rol,
            "user_status": user.user_status,
            "created_at": user.created_at
        }
    }


@app.get("/request_tiendas", response_model=list[BenefitRequestResponse])
def get_requests_tiendas(db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user_secure)):
    """Obtiene todas las solicitudes de beneficios todos los usuarios. Disponible solo para tiendas

    Args:
        db (Session, optional): Sesión de base de datos. Defaults to Depends(get_db).
        current_user (UserDB, optional): Usuario autenticado. Defaults to Depends(get_current_user_secure).
    """
    requests = db.query(BenefitRequestDB).filter(BenefitRequestDB.status ==
                                                 "Solicitado").order_by(BenefitRequestDB.created_at.desc()).all()

    return [
        BenefitRequestResponse(
            id=req.id,
            user_id=req.user_id,
            cedula=str(req.users.cedula),
            nombre=req.users.name,
            email=req.users.email,
            benefit_type=req.benefit_type,
            status=req.status,
            consumido_en=req.consumido_en,
            created_at=req.created_at
        ) for req in requests
    ]


@app.get("/request", response_model=list[BenefitRequestResponse])
def get_requests(db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user_secure)):
    """Obtiene todas las solicitudes de beneficios del usuario autenticado.

    Args:
        db (Session, optional): Sesión de base de datos. Defaults to Depends(get_db).
        current_user (UserDB, optional): Usuario autenticado. Defaults to Depends(get_current_user_secure).
    """
    requests = db.query(BenefitRequestDB).filter(BenefitRequestDB.user_id ==
                                                 current_user.id).order_by(BenefitRequestDB.created_at.desc()).all()
    return [
        BenefitRequestResponse(
            id=req.id,
            user_id=req.user_id,
            cedula=req.users.cedula,
            nombre=req.users.name,
            email=req.users.email,
            benefit_type=req.benefit_type,
            status=req.status,
            consumido_en=req.consumido_en,
            created_at=req.created_at
        ) for req in requests
    ]


@app.post("/request")
def create_request(request: BenefitRequestCreate, db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user_secure)):
    """Crea una nueva solicitud de beneficio para el usuario autenticado.

    Args:
        request (BenefitRequestCreate): Datos de la solicitud de beneficio.
        db (Session, optional): Sesión de base de datos. Defaults to Depends(get_db).
        current_user (UserDB, optional): Usuario autenticado. Defaults to Depends(get_current_user_secure).

    Returns:
        _type_: _description_
    """
    today = datetime.now().today().date()

    # validar duplicados
    existing_request = db.query(BenefitRequestDB).filter(
        BenefitRequestDB.user_id == current_user.id,
        BenefitRequestDB.benefit_type == request.benefit_type,
        BenefitRequestDB.created_at >= today
    ).first()

    if existing_request:
        raise HTTPException(
            status_code=400, detail="Usted ya ha realizado esta solicitud hoy")

    new_request = BenefitRequestDB(
        id=str(uuid.uuid4()),
        user_id=current_user.id,
        benefit_type=request.benefit_type,
        created_at=datetime.now().today(),
        status="Solicitado",
        consumido_en="Sin consumir"
    )
    db.add(new_request)
    db.commit()
    db.refresh(new_request)
    return {
        "id": new_request.id,
        "user_id": new_request.user_id,
        "cedula": current_user.cedula,
        "nombre": current_user.name,
        "email": current_user.email,
        "benefit_type": new_request.benefit_type,
        "status": new_request.status,
        "consumido_en": new_request.consumido_en,
        "created_at": new_request.created_at
    }


@app.put("/request/{request_id}")
def update_request_status(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(get_current_user_secure)
):
    """
    Actualiza el estado de una solicitud de beneficio de 'Solicitado' a 'Consumido'.

    Reglas:
    - Solo se permite la actualización si la solicitud pertenece al usuario autenticado.
    - La solicitud debe haber sido creada en la fecha actual (hoy).
    - El estado actual debe ser 'Solicitado'; de lo contrario, se rechaza la operación.

    Args:
        request_id (str): Identificador único de la solicitud a actualizar.
        db (Session, optional): Sesión de base de datos. Defaults to Depends(get_db).
        current_user (UserDB, optional): Usuario autenticado. Defaults to Depends(get_current_user_secure).

    Raises:
        HTTPException: Si la solicitud no existe, no pertenece al usuario, 
                       no fue creada hoy o ya está en otro estado.

    Returns:
        dict: Datos de la solicitud actualizada con el nuevo estado.
    """
    # Fecha actual (solo día, sin hora)
    today = datetime.now().date()
    # Buscar la solicitud en la BD
    request = db.query(BenefitRequestDB).filter(
        BenefitRequestDB.created_at >= today,
        BenefitRequestDB.id == request_id
    ).first()
    if not request:
        raise HTTPException(
            status_code=404, detail="Solicitud no encontrada o no creada hoy")

    # Actualizar estado a 'Consumido'
    request.status = "Consumido"
    request.consumido_en = current_user.cedula
    db.commit()
    db.refresh(request)
    return {
        "id": request.id,
        "user_id": request.user_id,
        "cedula": current_user.cedula,
        "nombre": current_user.name,
        "email": current_user.email,
        "benefit_type": request.benefit_type,
        "status": request.status,
        "created_at": request.created_at
    }

@app.delete("/request/{request_id}")
def delete_request(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: UserDB = Depends(get_current_user_secure)
):
    """Elimina una solicitud de beneficio específica del usuario autenticado.

    Args:
        request_id (str): Identificador único de la solicitud a eliminar.
        db (Session, optional): Sesión de base de datos. Defaults to Depends(get_db).
        current_user (UserDB, optional): Usuario autenticado. Defaults to Depends(get_current_user_secure)."""
    request = db.query(BenefitRequestDB).filter(
        BenefitRequestDB.id == request_id,
        BenefitRequestDB.user_id == current_user.id
    ).first()
    if not request: 
        raise HTTPException(
            status_code=404, detail="Solicitud no encontrada")
    db.delete(request)
    db.commit()
    return {"detail": "Solicitud eliminada exitosamente"}