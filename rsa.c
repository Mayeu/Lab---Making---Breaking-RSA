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

#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>                /* needed to manipulate big-fat-ass int */
#include <time.h>
#include <math.h>
#include "prime.h"
#include "rsa.h"

/*
 * This is the Square and Multiply functions.
 * This provide encryption & decryption of RSA
 */

void
square_and_mult(mpz_t x, mpz_t c, mpz_t n, mpz_t r)
{
    /*
     * mpz_t is the second name for big-fat-ass integer 
     */
    mpz_t           z;
    int             i;

    // z = (mpz_t *) malloc(sizeof(mpz_t));
    mpz_init_set_ui(z, 1);      /* init and set z to 1 */

    /*
     * mpz_sizeinbase return the size of the number in the specified base 
     */
    for (i = mpz_sizeinbase(c, 2) - 1; i >= 0; i--) {
        mpz_mul(z, z, z);       /* z = z*z */
        mpz_mod(z, z, n);       /* z = z mod n */

        if (mpz_tstbit(c, i)) { /* mpz_tstbit return the value of the bit
                                 * i */
            mpz_mul(z, z, x);   /* z = z*x */
            mpz_mod(z, z, n);   /* z = z mod n */
        }
    }

    mpz_set(r, z);
}

/*
 * Multiplicative inverse
 * We assume that d is an allocated pointer to a mpz_t
 * return 1 if everything goes ok, 0 otherwise
 */
int
mul_inv(mpz_t d, mpz_t a, mpz_t b)
{
    mpz_t           a0,
                    b0,
                    t0,
                    t,
                    q,
                    r,
                    tmp;

    mpz_init_set(a0, a);
    mpz_init_set(b0, b);
    mpz_init_set_ui(t0, 0);
    mpz_init_set_ui(t, 1);
    mpz_init(q);
    mpz_init(r);
    mpz_fdiv_qr(q, r, a0, b0);  /* calcul q and r at the same time */
    mpz_init(tmp);

    while (mpz_cmp_ui(r, 0) > 0) {
        mpz_mul(tmp, q, t);     /* tmp = qt */
        mpz_sub(t0, t0, tmp);   /* t0 = t0 - tmp */
        mpz_mod(tmp, t0, a);    /* tmp = t0 mod a */
        mpz_set(t0, t);
        mpz_set(t, tmp);
        mpz_set(a0, b0);
        mpz_set(b0, r);
        mpz_fdiv_qr(q, r, a0, b0);      /* q and r at the same time */
    }

    if (mpz_cmp_ui(b0, 1) != 0)
        return 0;               /* no inverse!! */
    else
        mpz_set(d, t);

    return 1;
}

/*
 * Keygen
 * Generate public and private key
 * We assume that e, t and n are allocated and initialized
 */
void
keygen(mpz_t e, mpz_t d, mpz_t n)
{
    mpz_t           p,
                    q,
                    phi,
                    tmp,
                    log2;
    gmp_randstate_t state;      /* random init stat */

    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    mpz_init(p);
    mpz_init(q);

    /*
     * Generate p!=q
     */
    do {
        primegen(p);
        primegen(q);
    } while (!mpz_cmp(p, q));

    /*
     * n
     */
    mpz_mul(n, p, q);

    /*
     * phi(n)
     */
    mpz_init(phi);
    mpz_init(tmp);
    mpz_sub_ui(phi, p, 1);      /* phi = p-1 */
    mpz_sub_ui(tmp, q, 1);      /* tmp = q-1 */
    mpz_mul(phi, phi, tmp);     /* phi = phi*tmp */

    /*
     * Approximate log2n
     * To do so, we use bitcount+1.
     */
    mpz_init_set_ui(log2, mpz_sizeinbase(n, 2) + 1);

    /*
     * Choosing a random e
     */
    do {
        mpz_urandomm(e, state, phi);
        mpz_gcd(tmp, e, phi);
        /*
         * run until e > log2 and gcd(e. phi)=1
         */
    } while (mpz_cmp(e, log2) < 0 || mpz_cmp_ui(tmp, 1) != 0);

    /*
     * d := inv(e, phi(n))
     */
    if (mul_inv(d, phi, e) == 0) {
        printf
            ("Mayday mayday! Something went wrong! They are not inversible Oo Gonna explode !!");
        exit(-666);
    }
}

/*
 * Break the rsa: the brutal way
 * c: cypher
 * e: e
 * n: n
 * k: the good k (size of the key ?)
 * p: the plain version
 */
void
breakit(mpz_t c, mpz_t e, mpz_t n, unsigned long k, mpz_t p)
{
    mpz_t           tmp,
                   *array;
    double          kd;
    unsigned long   array_size,
                    i,
                    j;

    // printf("!!!!!!!!!!!!!!!!Debug: %lu\n", k);
    kd = k / 2.0;
    // printf("!!!!!!!!!!!!!!!!Debug: %f\n", kd);
    array_size = (long) pow(2, kd);
    // printf("!!!!!!!!!!!!!!!!Debug: %lu\n", array_size);


    /*
     * allocate the array for the result
     */
    array = (mpz_t *) malloc(array_size * sizeof(mpz_t));

    /*
     * let's go baby!
     */
    mpz_init(tmp);
    for (i = 1; i <= array_size; i++) {
        mpz_set_ui(tmp, i);
        mpz_init(array[i - 1]); /* initialize the mpz in the array */
        square_and_mult(tmp, e, n, array[i - 1]);
    }

    for (i = 0; i < array_size; i++) {
        mul_inv(tmp, n, array[i]);      /* tmp = inv(i^e mod n, n) */
        mpz_mul(tmp, c, tmp);
        mpz_mod(tmp, tmp, n);   /* tmp = c * inv(i^e mod n, n) mod n */
        for (j = 0; j < array_size; j++) {
            if (mpz_cmp(tmp, array[j]) == 0) {
                mpz_set_ui(tmp, 1);
                mpz_mul_ui(tmp, tmp, i + 1);
                mpz_mul_ui(tmp, tmp, j + 1);
                mpz_mod(tmp, tmp, n);
                mpz_set(p, tmp);
                return;
            }
        }
    }

    free(array);
}
