from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
import os
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

# Obtener variables de entorno con valores por defecto
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASS", "postgres")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "autenticacion")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}" 

try:
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine) # crea una session que al crear un registro no haga el commit directamente, que no lo guarde , el binding cual es la session que va 
    
    Base = declarative_base() 
    
except SQLAlchemyError as e: 
    raise Exception(f"Error al conectar con la base de datos: {str(e)}")    

def get_db():
    db = SessionLocal()
    try:
        yield db
    except SQLAlchemyError as e:
        db.rollback() # devuelve los cambios de la base de datos
        raise Exception(f"Error en la operacion de base de datos: {str(e)}")
    finally:
        db.close()  
        
            
