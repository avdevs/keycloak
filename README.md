## Keycloak OAuth2 Provider for Laravel Socialite

### Installation
```
    git clone https://github.com/avdevs/keycloak.git
```

### Requirements

        Download latest keycloak server repository from https://www.keycloak.org/ and setup keycloak server at admin console.

### Environment Setup

Add below key array in '/config/services.php' file.
```php
    'keycloak' => [
            'authServerUrl'         => env('KEYCLOAK_AUTHSERVERURL'),
            'realm'                 => env('KEYCLOAK_REALM'),
            'clientId'              => env('KEYCLOAK_CLIENTID'),
            'clientSecret'          => env('KEYCLOAK_CLIENTSECRET'),
            'redirectUri'           => env('KEYCLOAK_REDIRECTURUI'),
            'encryptionAlgorithm'   => env('KEYCLOAK_ENCRYPTIONALGORITHM'),
            'encryptionKeyPath'     => env('KEYCLOAK_ENCRYPTIONKEYPATH'),
            'encryptionKey'         => env('KEYCLOAK_ENCRYPTIONKEY'),
    ]
```
### Laravel AppServiceProvider

Add below code in /app/Providers/AppServiceProvider.php
file which helps to execute keycloak as a socialite provider.

```php
    use Avdevs\Keycloak\KeycloakProvider;
```

In boot() method, add below code

```php
    $this->bootKeycloakSocialite();
```

Add Function

```php
    private function bootKeycloakSocialite()
    {
        $socialite = $this->app->make('Laravel\Socialite\Contracts\Factory');
        $socialite->extend(
            'keycloak',
            function ($app) use ($socialite) {
                $config = $app['config']['services.keycloak'];
                return new KeycloakProvider($config);
            }
        );
    }
```

### Laravel Functions and Routes

```php
    use Socialite;
```

```php
    Route::get('/redirect/{provider}', 'ProviderAuthController@redirectToProvider');

    /**
     * Redirect to keycloak server.
     * @provider
     * @return
     */
    public function redirectToProvider($provider)
    {
        /* where $provider = 'keycloak' */
        return Socialite::driver($provider)
                    ->stateless()
                    ->scopes([]) // Array ex : name
                    ->redirect();
    }
```

```php
    Route::get('/callback/{provider}', 'ProviderAuthController@CallbackFunction');

    /**
     * retrieve user information which is located at keycloak serve.
     * @provider
     * @return
     */
    public function CallbackFunction($provider)
    {
        /* where $provider = 'keycloak' */
        $userData = Socialite::driver($provider)
                        ->stateless()
                        ->user();
        /* Note : */
        /* 1) Callback url is same for login and logout request. so this function executed twice. */
        /* 2) Must add below code, Because user data not retrieved while logout calls is requested. */
        if(!isset($userData->email)){
            return redirect()->back();
        }

        /* your logic for add or get user detail */

    }
```

```php
    Route::get('/logout/{provider}', 'ProviderAuthController@ProviderLogout');

     /**
     * Log the user out of the application.
     * @provider
     * @return void
     */
    public function ProviderLogout(provider)
    {
        /* where $provider = 'keycloak' */
        /* logout from laravel auth */
        Auth::logout();
        /* redirect to keycloak logout url */
        return redirect(
            Socialite::driver($provider)
                ->getLogoutUrl()
        );
    }
```
