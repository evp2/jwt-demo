# Usage

### Obtaining token via token endpoint
```
POST http://localhost:8080/token
Authorization: Basic evp2 password


> {% client.global.set("auth_token", response.body); %}
```
### Accessing protected resource with token
```
GET http://localhost:8080
Authorization: Bearer {{auth_token}}
```



