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
### Class Modifications

Add createKeycloakDriver() function in /vendor/laravel/socialite/src/SocialiteManager.php
file to execute keycloak as a socialite provider as below.

```php
use Avdevs\Keycloak\KeycloakProvider;
```

add Keycloak Provider function in SocialiteManager class body like :

    /**
     * Create an instance of the keycloak driver.
     *
     * @return
     */
    protected function createKeycloakDriver()
    {
        $config = $this->app['config']['services.keycloak'];

        return new KeycloakProvider(
            $config
        );
    }

### Routes
```php
Route::get('/callback/{provider}', 'Controller@CallbackFunction');
Route::get('/redirect/{provider}', 'Controller@redirectToProvider');
Route::get('/logout/{provider}', 'Controller@KeycloakLogout ');
```
