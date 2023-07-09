# XXTEA for PHP

## Introduction

XXTEA is a fast and secure encryption algorithm. This is a XXTEA library for PHP.

This library is a fork of the original xxtea/xxtea-php repository and adds proper namespacing to be compatible with modern php code.

Further more this library can be used as a shim in places where the pecl extension is not available as it implements the two functions `xxtea_encrypt()` and `xxtea_decrypt()` provided by the pecl extension.

It is different from the original XXTEA encryption algorithm. It encrypts and decrypts string instead of uint32 array, and the key is also string.

## Installation

To install this library, you can add the following lines to your `composer.json` file:

```json
{ "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/arunagirinathar/xxtea-php"
        }
    ],
    "require": {
        "arunagirinathar/xxtea-php": "^1.0"
    }
```

After updating the composer.json file, run the following command to install the library:

```shell
composer install

```

Add the following lines to your composer.json 


## Usage

Here's an example of how to use the XXTEA encryption library:


```php
<?php
    use Arunagirinathar\XXTEAEncryption;
    require_once 'vendor/autoload.php';


    $str = "Hello World!";
    $key = "1234567890";
    $encrypt_data = xxtea_encrypt($str, $key);
    $decrypt_data = xxtea_decrypt($encrypt_data, $key);
    if ($str == $decrypt_data) {
        echo "success!";
    } else {
        echo "fail!";
    }
?>
```

In this example, we first include the autoloader from Composer, which will autoload the necessary classes. Then, we encrypt the string "Hello World!" using the xxtea_encrypt() function and a given key. Next, we decrypt the encrypted data using the xxtea_decrypt() function and the same key. Finally, we check if the decrypted data matches the original string and display the result accordingly.


