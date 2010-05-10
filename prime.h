/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <mayeu.tik@gmail.com> and <manu.kaul@gmail.com> wrote this file. As long as
 * you retain this notice you can do whatever you want with this stuff. If we
 * meet some day, and you think this stuff is worth it, you can buy us a beer
 * in return. Matthieu Maury & Manu Kaul
 * ----------------------------------------------------------------------------
 */

/*
 * Cryptography lab 2
 * Making & Breaking RSA
 *
 * Description: This file contains function to test and generate prime number
 */

int             isprime(mpz_t p);
void            primegen(mpz_t p);
void            set_prime_size(int s);
