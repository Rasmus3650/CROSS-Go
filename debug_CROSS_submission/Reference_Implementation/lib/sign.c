/**
 *
 * Reference ISO-C11 Implementation of CROSS.
 *
 * @version 2.0 (February 2025)
 *
 * Authors listed in alphabetical order:
 * 
 * @author: Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author: Marco Gianvecchio <marco.gianvecchio@mail.polimi.it>
 * @author: Patrick Karl <patrick.karl@tum.de>
 * @author: Gerardo Pelosi <gerardo.pelosi@polimi.it>
 * @author: Jonas Schupp <jonas.schupp@tum.de>
 * 
 * 
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **/

#include <stddef.h>  //  size_t
#include <string.h>  // memcpy

#include "api.h"

/*----------------------------------------------------------------------------*/

int crypto_sign_keypair(unsigned char *pk,
                        unsigned char *sk)
{
   /* keygen cannot fail */
   CROSS_keygen((sk_t *) sk,
                (pk_t *) pk);

   return 0; // NIST convention: 0 == zero errors
} // end crypto_sign_keypair

/*----------------------------------------------------------------------------*/
/*                                                                            */
/*... generating a signed message sm[0],sm[1],...,sm[*smlen-1]                */
/*... from original message m[0],m[1],...,m[mlen-1]                           */
/*... under secret key sk[0],sk[1],...                                        */
int crypto_sign(unsigned char *sm,                              // out: message || signature
   unsigned long long *smlen,                      // out: total length
   const unsigned char *m,                         // in: message
   unsigned long long mlen,                        // in: message length
   const unsigned char *sk,                        // in: secret key
   uint8_t *out_root_seed,                         // out: generated root_seed
   uint8_t *out_salt)                              // out: generated salt
{
// Copy message into beginning of sm
memcpy(sm, m, mlen);

// Generate the signature (directly after the message)
KAT_CROSS_sign((const sk_t *) sk,
      (const char *const) m,
      (const uint64_t) mlen,
      (CROSS_sig_t *) (sm + mlen),   // Signature stored at sm + mlen
      out_root_seed,
      out_salt);

// Total length = message + signature
*smlen = mlen + (unsigned long long) sizeof(CROSS_sig_t);

return 0; // success
}// end crypto_sign

/*----------------------------------------------------------------------------*/
/*                                                                            */
/*.  ... verifying a signed message sm[0],sm[1],...,sm[smlen-1]               */
/*.  ... under public key pk[0],pk[1],...                                     */
/*.  ... and producing original message m[0],m[1],...,m[*mlen-1]              */
int crypto_sign_open(unsigned char *m,                          // out parameter
                     unsigned long long *mlen,                  // out parameter
                     const unsigned char *sm,                   // in parameter
                     unsigned long long smlen,                  // in parameter
                     const unsigned char *pk)                   // in parameter
{

   /* verify returns 1 if signature is ok, 0 otherwise */
   *mlen = smlen-(unsigned long long) sizeof(CROSS_sig_t);
   
   memcpy((unsigned char *) m, (const unsigned char *) sm, (size_t) *mlen);
   int ok = CROSS_verify((const pk_t *const) pk,            // in parameter
                        (const char *const) m,                  // in parameter
                        (const uint64_t) *mlen,                 // in parameter
                        (const CROSS_sig_t * const) (sm+*mlen));// in parameter


   return ok-1; // NIST convention: 0 == zero errors, -1 == error condition
} // end crypto_sign_open

/*----------------------------------------------------------------------------*/
