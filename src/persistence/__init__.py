"""Persistence layer: repository interfaces + in-memory dev repository.

PostgreSQL is PLANNED; the interfaces are clean and the default
implementation is an in-memory repository suitable for development and tests.
Nothing is persisted to a database without an explicit DATABASE_URL-backed
implementation, so persistence is never faked.
"""
