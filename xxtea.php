<?php

namespace Arunagirinathar;

/**
 * XXTEA encryption algorithm library for PHP.
 *
 * Encryption Algorithm Authors:
 * - David J. Wheeler
 * - Roger M. Needham
 *
 * Adapted by: Arunagirinathar <arunagirinathar@gmail.com>
 * 
 * Original Code Author: Ma Bingyao <mabingyao@gmail.com>
 * LastModified: July 9, 2023
 */
class XXTEAEncryption
{
    const DELTA = 0x9E3779B9;

    /**
     * Convert an array of long integers to a string.
     *
     * @param array $v The array of long integers.
     * @param bool $w Flag indicating whether the string should be truncated.
     * @return string The resulting string.
     */
    private static function long2str($v, $w)
    {
        $len = count($v);
        $n = $len << 2;
        if ($w) {
            $m = $v[$len - 1];
            $n -= 4;
            if (($m < $n - 3) || ($m > $n)) return false;
            $n = $m;
        }
        $s = array();
        for ($i = 0; $i < $len; $i++) {
            $s[$i] = pack("V", $v[$i]);
        }
        if ($w) {
            return substr(join('', $s), 0, $n);
        } else {
            return join('', $s);
        }
    }

    /**
     * Convert a string to an array of long integers.
     *
     * @param string $s The input string.
     * @param bool $w Flag indicating whether the length should be appended to the array.
     * @return array The resulting array of long integers.
     */
    private static function str2long($s, $w)
    {
        $v = unpack("V*", $s . str_repeat("\0", (4 - strlen($s) % 4) & 3));
        $v = array_values($v);
        if ($w) {
            $v[count($v)] = strlen($s);
        }
        return $v;
    }

    /**
     * Convert an integer to a 32-bit signed integer.
     *
     * @param int $n The input integer.
     * @return int The resulting 32-bit signed integer.
     */
    private static function int32($n)
    {
        return ($n & 0xffffffff);
    }

    /**
     * Perform the MX step of the XXTEA algorithm.
     *
     * @param int $sum The sum value.
     * @param int $y The Y value.
     * @param int $z The Z value.
     * @param int $p The P value.
     * @param int $e The E value.
     * @param array $k The key array.
     * @return int The resulting value.
     */
    private static function mx($sum, $y, $z, $p, $e, $k)
    {
        return ((($z >> 5 & 0x07ffffff) ^ $y << 2) + (($y >> 3 & 0x1fffffff) ^ $z << 4)) ^ (($sum ^ $y) + ($k[$p & 3 ^ $e] ^ $z));
    }

     /**
     * Fix the key array to ensure it has at least 4 elements.
     *
     * @param array $k The key array.
     * @return array The fixed key array.
     */
    private static function fixk($k)
    {
        if (count($k) < 4) {
            for ($i = count($k); $i < 4; $i++) {
                $k[$i] = 0;
            }
        }
        return $k;
    }
    
    /**
     * Encrypt a string using XXTEA encryption.
     *
     * @param string $str The string to be encrypted.
     * @param string $key The encryption key.
     * @return string The encrypted string.
     */
    public static function encrypt($str, $key)
    {
        if ($str == "") {
            return "";
        }
        $v = self::str2long($str, true);
        $k = self::fixk(self::str2long($key, false));
        $n = count($v) - 1;
        $z = $v[$n];
        $q = floor(6 + 52 / ($n + 1));
        $sum = 0;
        while (0 < $q--) {
            $sum = self::int32($sum + self::DELTA);
            $e = $sum >> 2 & 3;
            for ($p = 0; $p < $n; $p++) {
                $y = $v[$p + 1];
                $z = $v[$p] = self::int32($v[$p] + self::mx($sum, $y, $z, $p, $e, $k));
            }
            $y = $v[0];
            $z = $v[$n] = self::int32($v[$n] + self::mx($sum, $y, $z, $p, $e, $k));
        }
        return self::long2str($v, false);
    }

    /**
     * Decrypt a string using XXTEA encryption.
     *
     * @param string $str The string to be decrypted.
     * @param string $key The decryption key.
     * @return string The decrypted string.
     */
    public static function decrypt($str, $key)
    {
        if ($str == "") {
            return "";
        }
        $v = self::str2long($str, false);
        $k = self::fixk(self::str2long($key, false));
        $n = count($v) - 1;

        $y = $v[0];
        $q = floor(6 + 52 / ($n + 1));
        $sum = self::int32($q * self::DELTA);
        while ($sum != 0) {
            $e = $sum >> 2 & 3;
            for ($p = $n; $p > 0; $p--) {
                $z = $v[$p - 1];
                $y = $v[$p] = self::int32($v[$p] - self::mx($sum, $y, $z, $p, $e, $k));
            }
            $z = $v[$n];
            $y = $v[0] = self::int32($v[0] - self::mx($sum, $y, $z, $p, $e, $k));
            $sum = self::int32($sum - self::DELTA);
        }
        return self::long2str($v, true);
    }
}


/**
 * This part provides shims for the xxtea PECL Extension.
 * In case the pecl extension is not available similar
 * function are made available which make use of the
 * above pure php implementation to provide
 * seamless operation.
 */
if (!extension_loaded('xxtea')) {
    /**
     * Encrypt a string using XXTEA encryption.
     *
     * @param string $str The string to be encrypted.
     * @param string $key The encryption key.
     * @return string The encrypted string.
     */
    function xxtea_encrypt($str, $key)
    {
        return XXTEAEncryption::encrypt($str, $key);
    }

     /**
     * Decrypt a string using XXTEA encryption.
     *
     * @param string $str The string to be decrypted.
     * @param string $key The decryption key.
     * @return string The decrypted string.
     */
    function xxtea_decrypt($str, $key)
    {
        return XXTEAEncryption::decrypt($str, $key);
    }
}
