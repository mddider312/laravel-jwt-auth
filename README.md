
# Laravel 9 JWT Authentication Tutorial: Login & Signup API


This is a comprehensive Laravel JWT Authentication example tutorial. In this article, we will learn how to create secure REST APIs in Laravel using JSON Web Token (JWT).


## Acknowledgements

- Install Laravel Application
- Database Connection
- Add User into MySQL Database
- Install & Configure JWT Authentication Package
- Set Up User Model
- Configure Auth Guard
- Build Authentication Controller
- Add Routes for Authentication
- Test REST API with Postman

# Install Laravel






```bash
 composer create-project laravel/laravel laravel-jwt-auth --prefer-dist
```
    
# Database connection

We have created a brand new Laravel application from scratch, now to store the user registration data, we have to create a database in MySQL and add the database name, user name, and password inside the .env file.

```bash
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=laravel
DB_USERNAME=root
DB_PASSWORD=

```

# Run Migration

```bash
php artisan migrate
```

# Install & Configure JWT Authentication Package

Execute the following command to install tymondesigns/jwt-auth, It is a third-party JWT package and allows user authentication using JSON Web Token in Laravel & Lumen securely.

```bash
composer require tymon/jwt-auth
```

Above command installed the jwt-auth package in the vendor folder, now we have to go to config/app.php file and include the laravel service provider inside the providers array.

Also include the JWTAuth and JWTFactory facades inside the aliases array.

```bash
'providers' => [
    ....
    ....
    Tymon\JWTAuth\Providers\LaravelServiceProvider::class,
],
'aliases' => [
    ....
    'JWTAuth' => Tymon\JWTAuth\Facades\JWTAuth::class,
    'JWTFactory' => Tymon\JWTAuth\Facades\JWTFactory::class,
    ....
],
```
In the next step, we have to publish the package’s configuration, following command copy JWT Auth files from vendor folder to config/jwt.php file.

```bash
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```
For handling the token encryption, generate a secret key by executing the following command.

```bash
php artisan jwt:secret
```

Open the app/Models/User.php file and replace the following code with the existing code.

```bash
<?php
namespace App\Models;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use HasFactory, Notifiable;
    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name',
        'email',
        'password',
    ];
    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];
    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];
    
    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier() {
        return $this->getKey();
    }
    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims() {
        return [];
    }    
}
```

Place the following code in config/auth.php file.

```php

<?php
return [
    'defaults' => [
        'guard' => 'api',
        'passwords' => 'users',
    ],

    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],
        'api' => [
            'driver' => 'jwt',
            'provider' => 'users',
            'hash' => false,
        ],
    ],
```

# Build Authentication Controller

```bash
 php artisan make:controller AuthController
```

Place the following code inside the app/Http/Controllers/AuthController.php file.

```bash
<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Validator;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct() {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }
    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request){
    	$validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }
        if (! $token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        return $this->createNewToken($token);
    }
    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request) {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|between:2,100',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);
        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }
        $user = User::create(array_merge(
                    $validator->validated(),
                    ['password' => bcrypt($request->password)]
                ));
        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user
        ], 201);
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout() {
        auth()->logout();
        return response()->json(['message' => 'User successfully signed out']);
    }
    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh() {
        return $this->createNewToken(auth()->refresh());
    }
    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function userProfile() {
        return response()->json(auth()->user());
    }
    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function createNewToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }
}
```

# Add Authentication Routes
We need to define the REST API authentication routes for auth process in Laravel JWT Authentication application. The routes that are served through routes/api.php are prefixed with api/ and authentication routes are denoted by auth/.

So it becomes /api/auth/signup, and it goes same for every route we have created for authentication.

We need to add authentication routes in routes/api.php instead of web.php:

```php
<?php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/
Route::group([
    'middleware' => 'api',
    'prefix' => 'auth'
], function ($router) {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/refresh', [AuthController::class, 'refresh']);
    Route::get('/user-profile', [AuthController::class, 'userProfile']);    
});
```
# Test Laravel JWT Authentication API with Postman

Start the laravel application with following command:
```bash
php artisan serve
```
We have created a secure REST API using JWT Authentication. To make the testing process easy and subtle, we will rely on Postman.

Authentication APIs for Login, Register, User Profile, Token Refresh and Logout.


## API Reference
```bash
Method	Endpoint
POST	/api/auth/register
POST	/api/auth/login
GET	/api/auth/user-profile
POST	/api/auth/refresh
POST	/api/auth/logout
```

# User Registration API in Laravel
Open the Postman, and add the user registration API in the address bar and select the HTTP request method to POST. Select the form-data and add the name, email, password, and password confirmation values in the input fields. Click on the Send button to see the response coming from the server.




![App Screenshot](https://www.positronx.io/wp-content/uploads/2020/06/laravel-jwt-user-registration-10336-02.png)

# Test Laravel Login API
To test login API in Laravel with JWT Authentication token, add the email and password details in the input fields and click on the Send button. You can see on successful login a JWT access token, token type, token expiration time, and user profile details returned.

![App Screenshot](https://www.positronx.io/wp-content/uploads/2020/06/laravel-jwt-login-10336-03.png)

# User Profile
Make sure you must define the access token as a header field "Authorization: Bearer Token" for User Profile, Token Refresh, and Logout REST APIs.

![App Screenshot](https://www.positronx.io/wp-content/uploads/2020/06/laravel-jwt-auth-10336-04.png)

# JWT Token Refresh in Laravel

To refresh a token We must have a valid JWT token, you can see we are getting the access_token and user data in Postman response block.

![App Screenshot](https://www.positronx.io/wp-content/uploads/2020/06/laravel-token-refesh-10336-06.png)

# Logout

We destroyed the JWT token on logout and you can use Postman to test the Logout API as follows.

# ![App Screenshot](https://www.positronx.io/wp-content/uploads/2020/06/laravel-logout-10336-05.png)

Conclusion
So this was it, in this article, we learned how to create secure user authentication REST API with JWT Authentication.