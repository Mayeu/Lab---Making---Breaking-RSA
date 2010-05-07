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
 * (Matthieu) I generally use BSD indentation with space instead of tab 
 *            (indent -orig -nut), but I'm ok for anything else :)
 */

#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>                /* needed to manipulate big-fat-ass int */
#include <time.h>

/*
 * Define time !
 */

#define PRIME_LENGTH 20         /* key length in bit */
#define ACCURACY 100            /* Number of check for the prime number */

/*
 * This is the Square and Multiply functions.
 * This provide encryption & decryption of RSA
 */

mpz_t          *
square_and_mult(mpz_t x, mpz_t c, mpz_t n)
{
    /*
     * mpz_t is the second name for big-fat-ass integer 
     */
    mpz_t          *z;
    int             i;

    z = (mpz_t *) malloc(sizeof(mpz_t));
    mpz_init_set_ui(*z, 1);     /* init and set z to 1 */

    /*
     * mpz_sizeinbase return the size of the number in the specified base 
     */
    for (i = mpz_sizeinbase(c, 2) - 1; i >= 0; i--) {
        mpz_mul(*z, *z, *z);    /* z = z*z */
        mpz_mod(*z, *z, n);     /* z = z mod n */

        if (mpz_tstbit(c, i)) { /* mpz_tstbit return the value of the bit
                                 * * * i */
            mpz_mul(*z, *z, x); /* z = z*x */
            mpz_mod(*z, *z, n); /* z = z mod n */
        }
    }

    return z;
}

/*
 * isprime : is this number prime ?
 * this use the Miller-Rabin method. The algorithm can be found at Wikipedia
 * return 1 (yes) and 0 (no)
 */
int
isprime(mpz_t p)
{
    gmp_randstate_t st;         /* random init stat */
    mpz_t           a,
                    d,
                    tmp,
                    x;
    int             i,
                    j;
    unsigned long   s;


    if (mpz_cmp_ui(p, 3) <= 0 || !mpz_tstbit(p, 0))     /* ensure that p * 
                                                         * is odd and *
                                                         * greater than 3 */
        return 0;

    /*
     * put p in the 2^s.d form
     */
    mpz_init(d);
    mpz_sub_ui(d, p, 1);        /* d = p-1 */
    s = 0;

    do {
        s++;
        mpz_divexact_ui(d, d, 2);
    } while (mpz_divisible_ui_p(d, 2));
    /*
     * now we have p as 2^s.d
     */

    gmp_randinit_default(st);
    gmp_randseed_ui(st, time(NULL));
    mpz_init(a);
    mpz_init(x);
    mpz_init(tmp);
    mpz_sub_ui(tmp, p, 1);      /* tmp = p - 1 */

    for (i = 0; i < ACCURACY; i++) {
        /*
         * generate a as 2 <= a <= n-2 
         */
        do {
            mpz_urandomm(a, st, tmp);   /* a will be between 0 and * tmp-1 
                                         * inclusive */
        } while (mpz_cmp_ui(a, 2) < 0);

        mpz_powm(x, a, d, p);   /* do x = a^d mod p */

        if (!mpz_cmp_ui(x, 1) || !mpz_cmp(x, tmp))      /* if x == 1 or x
                                                         * * == p-1 */
            continue;

        for (j = 1; j < s; j++) {
            mpz_powm_ui(x, x, 2, p);    /* do x = x^2 mod p */
            if (!mpz_cmp_ui(x, 1))      /* x == 1 */
                return 0;

            if (!mpz_cmp(x, tmp))       /* x == p-1 */
                break;
        }
        if (mpz_cmp(x, tmp))    /* x != p-1 */
            return 0;
    }
    return 1;
}

/*
 * primegen : generate a prime number
 * assume that p is an allocated pointer, and a initialized
 * mpz_t
 */

mpz_t          *
primegen(mpz_t * p)
{
    gmp_randstate_t state;      /* random init stat */
    unsigned long   i;

    if (p == NULL)
        return NULL;

    i = 0;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    do {
        mpz_urandomb(*p, state, PRIME_LENGTH);
    } while (!isprime(*p));

    return p;
}

/*
 * Multiplicative inverse
 * We assume that d is an allocated pointer to a mpz_t
 * return 1 if everything goes ok, 0 otherwise
 */
int
mul_inv(mpz_t * d, mpz_t a, mpz_t b)
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
        mpz_fdiv_qr(q, r, a0, b0);      /* calcul q and r at the same time 
                                         */
    }

    if (mpz_cmp_ui(b0, 1) != 0)
        return 0;               /* no inverse!! */
    else
        mpz_set(*d, t);

    return 1;
}

/*
 * Keygen
 * Generate public and private key
 * We assume that e, t and n are allocated and initialized
 */
void
keygen(mpz_t * e, mpz_t * d, mpz_t * n)
{
    mpz_t           p,
                    q,
                    phi,
                    tmp,
                    log2;
    gmp_randstate_t state;      /* random init stat */
    int             i;

    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    mpz_init(p);
    mpz_init(q);

    /*
     * Generate p!=q
     */
    do {
        primegen(&p);
        primegen(&q);
    } while (mpz_cmp(p, q) == 0);

    /*
     * n
     */
    mpz_mul(*n, p, q);

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
    mpz_init_set_ui(log2, (mpz_sizeinbase(*n, 2) + 1));

    /*
     * Choosing a random e
     */
    do {
        mpz_urandomm(*e, state, phi);
        mpz_gcd(tmp, *e, phi);
        /*
         * run until e > log2 and gcd(e. phi)=1
         */
    } while (mpz_cmp(*e, log2) <= 0 || mpz_cmp_ui(tmp, 1) != 0);

    /*
     * d := inv(e, phi(n))
     */
    if (mul_inv(d,phi,*e) == 0) {
        printf
            ("Mayday mayday! Something went wrong! They are not inversible Oo Gonna explode !!");
        exit(-666);
    }
}

/*
 * Encryptien/Decryption test
 */
void
ed_test()
{
    mpz_t           n,
                    a,
                    b,
                   *x,
                    p,
                    c;

    x = (mpz_t *) malloc(sizeof(mpz_t));

    /*
     * little test of Square & Multiply functions
     * Using exemple in the book page 177 (Example 5.5)
     * n = 11413
     * b = 3533
     * plaintext = 9726
     * cypher = 5761
     */

    printf("-- Testing the encryption/decryption\n");

    mpz_init_set_ui(n, 11413);
    mpz_init_set_ui(b, 3533);
    mpz_init_set_ui(a, 6597);
    mpz_init_set_ui(*x, 9726);
    mpz_init_set_ui(c, 5761);

    printf("n = ");
    mpz_out_str(stdout, 10, n);
    printf("\nb = ");
    mpz_out_str(stdout, 10, b);
    printf("\nplain = ");
    mpz_out_str(stdout, 10, *x);
    printf("\nexcpected cypher = ");
    mpz_out_str(stdout, 10, c);
    printf("\n");

    x = square_and_mult(*x, b, n);

    printf("\nfound cypher = ");
    mpz_out_str(stdout, 10, c);
    printf("\n");
    x = square_and_mult(*x, a, n);
    printf("\nback to = ");
    mpz_out_str(stdout, 10, *x);
    printf("\n");

    if (!mpz_cmp_ui(*x, 9726))  /* return 0 if oqual */
        printf("zOMG !! It's working!! Oo\n");
    else
        printf("fail n00b!!\n");
}

/*
 * Prime generator test
 */
void
prime_test()
{
    mpz_t           p;

    printf("\n-- Prime test\n");

    mpz_init_set_ui(p, 0);

    primegen(&p);
    printf("This is a prime number: ");
    mpz_out_str(stdout, 10, p);
    printf
        ("\nYep really! Test it with: http://www.alpertron.com.ar/ECM.HTM\n");
}

/*
 * Keygen, encryption and decryption with generated key
 */
void
key_test()
{
    mpz_t           e,
                    d,
                    n,
                    x,
                   *c;

    printf("\n-- Keygen test\n");
    mpz_init(e);
    mpz_init(d);
    mpz_init(n);

    keygen(&e, &d, &n);

    printf("--Generated key:\nPublic: (");
    mpz_out_str(stdout, 10, e);
    printf(", ");
    mpz_out_str(stdout, 10, n);
    printf(")\nPrivate: (");
    mpz_out_str(stdout, 10, d);
    printf(", ");
    mpz_out_str(stdout, 10, n);
    printf(")\n");

    printf("With this key i'll encrypt: ");
    mpz_init_set_ui(x, 12948);
    mpz_out_str(stdout, 10, x);
    c = square_and_mult(x, e, n);
    printf("\ngot: ");
    mpz_out_str(stdout, 10, *c);
    printf("\nNow we try to decrypt it: ");
    c = square_and_mult(*c, d, n);
    printf("\ngot: ");
    mpz_out_str(stdout, 10, *c);
    printf("\n");
}

/*
 * all the test
 */
void
all_test()
{

    ed_test();                  /* encryption/decryption test */
    prime_test();               /* prime generator */
    key_test();                 /* key generator */
}

/*
 * Main
 */

int
main(int argc, char **argv)
{

    all_test();

    return 0;
}
