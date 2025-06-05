# Refactoring Plan for Appointment System Backend

## Current Structure

Currently, the project follows a structure where:

- All code is in the `app` directory
- Routes are in `app/api/routes`
- Models are in `app/api/models`
- Schemas are in `app/api/schemas`
- Auth logic is spread across multiple files

## Target Structure (Based on FastAPI Project Structure Guide)

We'll refactor to a domain-driven design with the following structure:

```
backend-fastapi/
├── src/
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── router.py
│   │   ├── schemas.py
│   │   ├── models.py
│   │   ├── service.py
│   │   ├── dependencies.py
│   │   ├── exceptions.py
│   │   └── utils.py
│   ├── appointments/
│   │   ├── __init__.py
│   │   ├── router.py
│   │   ├── schemas.py
│   │   ├── models.py
│   │   ├── service.py
│   │   ├── dependencies.py
│   │   └── exceptions.py
│   ├── patients/
│   │   ├── __init__.py
│   │   ├── router.py
│   │   ├── schemas.py
│   │   ├── models.py
│   │   ├── service.py
│   │   └── utils.py
│   ├── doctors/
│   │   ├── __init__.py
│   │   ├── router.py
│   │   ├── schemas.py
│   │   ├── models.py
│   │   ├── service.py
│   │   └── utils.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── security.py
│   │   ├── pagination.py
│   │   ├── permissions.py
│   │   └── middleware.py
│   ├── config.py
│   ├── database.py
│   ├── exceptions.py
│   └── main.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── auth/
│   ├── appointments/
│   ├── patients/
│   └── doctors/
├── alembic/
├── requirements/
│   ├── base.txt
│   ├── dev.txt
│   ├── test.txt
│   └── prod.txt
├── .env.example
├── .env
├── docker-compose.yml
├── Dockerfile
└── README.md
```

## Refactoring Steps

### 1. Create New Directory Structure ✅

- Create the base `src` directory ✅
- Create domain-based subdirectories (auth, appointments, patients, doctors, core) ✅
- Create appropriate files in each directory ✅

### 2. Move and Refactor Auth Module ⏳

- Move auth-related code from `app/api/routes/auth.py` to `src/auth/router.py` ⏳
- Extract service logic to `src/auth/service.py` ⏳
- Move user model to `src/auth/models.py` ✅
- Move auth schemas to `src/auth/schemas.py` ⏳
- Move auth dependencies to `src/auth/dependencies.py` ⏳
- Create `src/auth/exceptions.py` for auth-specific exceptions ⏳

### 3. Create Core Module ✅

- Move security utilities to `src/core/security.py` ✅
- Create pagination utilities in `src/core/pagination.py` ✅
- Create permissions handling in `src/core/permissions.py` ✅
- Create custom middleware in `src/core/middleware.py` ✅

### 4. Create Other Domain Modules ⏳

- Create appointments module with appropriate files ⏳
- Create patients module with appropriate files ⏳
- Create doctors module with appropriate files ⏳

### 5. Move Global Files ✅

- Move `app/api/database.py` to `src/database.py` ✅
- Move `app/api/config.py` to `src/config.py` ✅
- Create `src/exceptions.py` for global exception handling ✅
- Refactor `app/api/main.py` to `src/main.py` ✅

### 6. Update Imports ⏳

- Update all import statements to reflect the new structure ⏳
- Fix circular dependencies ⏳

### 7. Update Alembic Configuration ⏳

- Update alembic configuration to point to the new structure ⏳

### 8. Update Requirements ✅

- Split requirements into base, dev, test, and prod files ✅

### 9. Create Docker Configuration ✅

- Create Dockerfile and docker-compose.yml ✅

### 10. Update Tests ⏳

- Reorganize tests to match the new structure ⏳
- Update test imports ⏳

## Implementation Plan

We'll tackle this refactoring in phases:

1. **Phase 1**: Create the new directory structure and move global files ✅
2. **Phase 2**: Refactor the auth module ⏳
3. **Phase 3**: Create the core module ✅
4. **Phase 4**: Create other domain modules ⏳
5. **Phase 5**: Update imports and fix dependencies ⏳
6. **Phase 6**: Update configuration files ✅
7. **Phase 7**: Update tests ⏳

## Benefits of the New Structure

- Clear separation of concerns
- Domain-driven design
- Easier to maintain and extend
- Better organization of code
- Improved testability

## Next Steps

1. Complete the auth module refactoring
2. Create the domain-specific modules
3. Update the alembic configuration
4. Complete test refactoring
