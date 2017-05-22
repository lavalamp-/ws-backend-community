# -*- coding: utf-8 -*-
from __future__ import absolute_import

from aldjemy.core import get_engine
from sqlalchemy.orm import sessionmaker


def get_sa_session():
    """
    Create and return a SQLAlchemy session.
    :return: A SQLAlchemy session.
    """
    engine = get_engine()
    _Session = sessionmaker(bind=engine)
    return _Session()
