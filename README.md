# FastAPI Auth Backend

Minimal backend for the Flutter frontend.
Only the final account step is persisted for now, so the API stores username and password only.

## Endpoints

- `GET /health` - health check
- `POST /auth/signup` - create a new user (username + password)
- `POST /auth/login` - log in with username and password
- `POST /child/details` - store or update child details for a user
- `GET /child/details/{user_id}` - retrieve child details for a user

## Run

```bash
cd Backend
python -m uvicorn app.main:app --reload
```

## Database Schema

**users** table:
- `id` (SERIAL PRIMARY KEY)
- `username` (VARCHAR UNIQUE)
- `password_hash` (TEXT)
- `created_at` (TIMESTAMP)

**child_details** table:
- `id` (SERIAL PRIMARY KEY)
- `user_id` (FOREIGN KEY to users)
- `child_name` (VARCHAR)
- `child_age` (INTEGER)
- `child_grade` (VARCHAR, optional)
- `created_at` (TIMESTAMP)
- `updated_at` (TIMESTAMP)

## Request/Response Examples

### Signup
```json
{
  "username": "parent1",
  "password": "secret123"
}
```

### Save child details
```json
{
  "user_id": 1,
  "child_name": "Emma",
  "child_age": 7,
  "child_grade": "2nd Grade"
}
```

### Child details response
```json
{
  "id": 1,
  "child_name": "Emma",
  "child_age": 7,
  "child_grade": "2nd Grade"
}
```
```