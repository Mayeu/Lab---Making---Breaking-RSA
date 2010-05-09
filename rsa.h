/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <mayeu.tik@gmail.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */

/*
 * Cryptography lab 2
 * Making & Breaking RSA
 *
 * Description: This file contains RSA making and breaking related functions
 */

void            square_and_mult(mpz_t x, mpz_t c, mpz_t n, mpz_t r);
int             mul_inv(mpz_t d, mpz_t a, mpz_t b);
void            keygen(mpz_t e, mpz_t d, mpz_t n);
void            breakit(mpz_t c, mpz_t e, mpz_t n, unsigned long k,
                        mpz_t p);
