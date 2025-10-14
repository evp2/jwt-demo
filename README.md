# Usage

### Add user via `/register` 
```

POST http://localhost:8080/register
Content-Type: application/json

{
  "username": "test",
  "email": "test@example.com",
  "password": "password",
}
```

### Obtaining token via `/login`
```
POST http://localhost:8080/login
Content-Type: application/json

{
  "username": "test",
  "password": "password"
}
```
### Accessing protected resource with token
```
GET http://localhost:8080
Authorization: Bearer {{jwt_token}}
```



