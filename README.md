# Laravel JWT Authentication API

This guide will walk you through setting up **JWT Authentication in Laravel**, including **user registration, login, token authentication, password reset, and authorization** using Postman.

## 🚀 Features

- ✅ **User Registration & Login**  
- ✅ **JWT Token-Based Authentication**  
- ✅ **Token Refresh & Logout**  
- ✅ **Protected Routes (Middleware)**  
- ✅ **Secure API Communication**  

---

## 🔧 Full Setup Guide

### 1️⃣ **Install Laravel**
```sh
composer create-project --prefer-dist laravel/laravel jwt-auth
cd jwt-auth
```

### 2️⃣ **Set Up Environment**
Copy `.env.example` to `.env` and update database details:
```sh
cp .env.example .env
```
Edit `.env` file:
```
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=jwt_auth
DB_USERNAME=root
DB_PASSWORD=
```

### 3️⃣ **Run Migrations**
```sh
php artisan migrate
```

### 4️⃣ **Install JWT Package**
```sh
composer require tymon/jwt-auth
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
php artisan jwt:secret
```

### 5️⃣ **Set Authentication Guard to `jwt`**
Edit `config/auth.php`:
```php
'defaults' => [
    'guard' => 'api',
    'passwords' => 'users',
],

'guards' => [
    'api' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
],
```

### 6️⃣ **Create Authentication Controller**
```sh
php artisan make:controller AuthController
```
Edit `app/Http/Controllers/AuthController.php`:
```php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = JWTAuth::fromUser($user);

        return response()->json(['user' => $user, 'token' => $token], 201);
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    public function profile()
    {
        return response()->json(Auth::user());
    }

    public function logout()
    {
        Auth::logout();
        return response()->json(['message' => 'Successfully logged out']);
    }

    public function refresh()
    {
        return $this->respondWithToken(Auth::refresh());
    }

    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => Auth::factory()->getTTL() * 60
        ]);
    }
}
```

Register in `bootstrap/app.php`:
```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->alias([
        'auth' => UserAuthMiddleware::class,
    ]);
})
```

### 7️⃣ **Define API Routes**
Edit `routes/api.php`:
```php
use App\Http\Controllers\AuthController;

Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);

Route::middleware('auth:api')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/refresh', [AuthController::class, 'refresh']);
    Route::get('/profile', [AuthController::class, 'profile']);
});
```

### 8️⃣ **Start Laravel Server**
```sh
php artisan serve
```

---

## 🛠 Postman API Testing

### **1️⃣ Register User**
**Endpoint:** `POST /api/register`
```json
{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "password123",
    "password_confirmation": "password123"
}
```

### **2️⃣ Login User**
**Endpoint:** `POST /api/login`
```json
{
    "email": "john@example.com",
    "password": "password123"
}
```
**Response:**
```json
{
    "access_token": "your_jwt_token",
    "token_type": "bearer",
    "expires_in": 3600
}
```

### **3️⃣ Get User Profile (Protected Route)**
**Endpoint:** `GET /api/profile`
**Headers:**
```
Authorization: Bearer your_jwt_token
```

### **4️⃣ Logout User**
**Endpoint:** `POST /api/logout`
**Headers:**
```
Authorization: Bearer your_jwt_token
```
**Response:**
```json
{
    "message": "Successfully logged out"
}
```

### **5️⃣ Refresh Token**
**Endpoint:** `POST /api/refresh`
**Headers:**
```
Authorization: Bearer your_jwt_token
```

---

## 🔥 Security & Best Practices
- ✅ **Use HTTPS in Production**  
- ✅ **Set Expiration Time for Tokens**  
- ✅ **Store Tokens Securely (LocalStorage for SPA, SecureStorage for Mobile)**  
- ✅ **Implement Role-Based Access Control (RBAC)**  

---

## 🎯 Contributing
Feel free to submit issues or pull requests!

---

## 📜 License
This project is open-source and available under the **MIT License**.

---

### 🌟 **Star this repo if you found it useful!** ⭐
