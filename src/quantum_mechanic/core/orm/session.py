# ================================================================
# MODULE: quantum_mechanic.core.orm.session
# ----------------------------------------------------------------
# PURPOSE:   Session factory for SQLAlchemy ORM operations.
#
# USAGE:
#   from quantum_mechanic.core.orm.session import make_session_factory
#   SessionLocal = make_session_factory(engine)
#   with SessionLocal() as session:
#       ...
# ================================================================

from __future__ import annotations

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a session factory bound to the given engine.

    Returns:
        A ``sessionmaker`` that produces ``Session`` instances.
        Use as a context manager:

            with SessionLocal() as session:
                ...

    Note:
        ``autocommit=False, autoflush=False`` — identical to the
        FastAPI SQLAlchemy best-practice pattern. Each store method
        must call ``session.commit()`` explicitly.
    """
    return sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
        class_=Session,
    )
