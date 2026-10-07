from app.database import Base, engine, SessionLocal
from app.seed import seed

Base.metadata.create_all(bind=engine)
db=SessionLocal()
try:
    seed(db)
    print("Seed complete. Demo login: demo@brandshield.local / DemoPass123!")
finally:
    db.close()
