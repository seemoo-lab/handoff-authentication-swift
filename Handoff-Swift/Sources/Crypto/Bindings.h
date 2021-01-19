//
//  Bindings.h
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 19.06.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

#ifndef Bindings_h
#define Bindings_h

typedef uint8_t ccec25519key[32];
typedef ccec25519key ccec25519secretkey;
typedef ccec25519key ccec25519pubkey;
typedef ccec25519key ccec25519base;

typedef uint8_t ccec25519signature[64];


/*!
 @function    cced25519_sign
 @abstract    Signs a message using a secret key.
 
 @param      di      A valid descriptor for a 512 bit hash function for the platform
 @param        sig        Receives the 64-byte signature.
 @param        len        Number of bytes to sign.
 @param        msg        Data to sign.
 @param        pk        32-byte public key as generated by cced25519_make_key_pair().
 @param        sk        32-byte secret key as generated by cced25519_make_key_pair().
 */
void cced25519_sign_compat(ccec25519signature sig, const void *msg, size_t len, const ccec25519key pk, const const ccec25519key sk);


/*!
 @function    cced25519_verify
 @abstract    Verifies a signed message using a public key.
 
 @param      di      A valid descriptor for a 512 bit hash function for the platform
 @param        len        Number of bytes of data to verify.
 @param        msg        Data to verify.
 @param        sig        64-byte signature to verify data against.
 @param        pk        32-byte public key. Should have been generated by the peer using
 cced25519_make_key_pair().
 
 @result        0=Signed message is valid. Non-zero=Bad message.
 */
int cced25519_verify_compat(const void *msg, size_t len, const const ccec25519signature sig, const const ccec25519key pk);




/*!
 @function        cccurve25519
 @abstract        Perform Curve25519 Diffie-Hellman.
 http://cr.yp.to/ecdh.html
 
 @param      out  Output shared secret or public key.
 @param      sk   Input secret key.
 @param      base Input basepoint (for computing a shared secret)
 or NULL (for computing a public key).
 */

void cccurve25519(ccec25519key out,
                  const ccec25519secretkey sk,
                  const ccec25519base base);


long * kCryptoHashDescriptor_SHA512;

void CryptoHKDF (long * hashDescriptor,uint8_t *input,size_t input_size,uint8_t *salt,size_t salt_size,
                 uint8_t *info,size_t info_size,long out_len,uint8_t *outData);

//Private function. Cannot be called
//void _chacha20_poly1305_encrypt_all
//    (uint8_t *keyData,uint8_t *nonce,size_t nonceLength,uint8_t *aadBytes,
//     size_t aadBytesLength,uint8_t *plaintextBytes,size_t plaintextLength,
//     uint8_t *outputBytes,size_t *out_len);


//Private function. Cannot be called
//int _chacha20_poly1305_decrypt_all
//(uint8_t *keyData,uint8_t *nonce,long nonce_len,uint8_t *aadBytes,size_t aad_len,
// uint8_t *enc_msg,size_t enc_msg_len,uint8_t * output,uint8_t *authTag);

int _chacha20_poly1305_decrypt_all(uint8_t *key, uint8_t *nonce,size_t nonce_len, uint8_t *aad, size_t aad_len, uint8_t *encr_msg, size_t encr_msg_len, uint8_t *output, uint8_t *authTag, size_t authTag_len);

int chacha20_poly1305_decrypt_all_64x64
(uint8_t *key,uint8_t *nonce,uint8_t *aad,size_t aad_len,uint8_t *encr_msg,
 size_t encr_msg_len,uint8_t *output,uint8_t *authTag);


int chacha20_poly1305_encrypt_all_64x64
(uint8_t *key,uint8_t *nonce,uint8_t *aad,size_t aad_len,uint8_t *message,
 size_t message_len,uint8_t *output,uint8_t *authTag);


void chacha20_poly1305_decrypt_all_96x32 (uint8_t *key,uint8_t *nonce,uint8_t *aad,size_t aad_len,uint8_t *encr_msg,
                                           size_t encr_msg_len,uint8_t *output,uint8_t *authTag);

void chacha20_poly1305_encrypt_all_96x32
    (uint8_t *key,uint8_t *nonce,uint8_t *aad,size_t aad_len,uint8_t *message,
     size_t message_len,uint8_t *output,uint8_t *authTag);


//Mark: Core crypto

// This is just a stub right now.
// Eventually we will optimize by platform.
struct ccchacha20poly1305_info {
    
};

extern const struct ccchacha20poly1305_info ccchacha20poly1305_info_default;


/*!
 @function      ccchacha20poly1305_decrypt_oneshot
 @abstract      Decrypt with chacha20poly1305.
 
 @param      info           Descriptor for the mode
 @param      key            Secret chacha20 key
 @param      nonce          Unique nonce per encryption
 @param      aad_nbytes     Length of the additional data in bytes
 @param      aad            Additional data to authenticate
 @param      ctext_nbytes   Length of the ciphertext in bytes
 @param      ctext          Input ciphertext
 @param      ptext          Output plaintext
 @param      tag            Expected authentication tag
 
 @discussion See RFC 7539 for details.
 
 The key is 32 bytes in length.
 
 The nonce is 12 bytes in length.
 
 The generated tag is 16 bytes in length.
 
 In-place processing is supported.
 */
int ccchacha20poly1305_decrypt_oneshot(const struct ccchacha20poly1305_info *info, const uint8_t *key, const uint8_t *nonce, size_t aad_nbytes, const void *aad, size_t ctext_nbytes, const void *ctext, void *ptext, const uint8_t *tag);


/*!
 @function      ccchacha20poly1305_encrypt_oneshot
 @abstract      Encrypt with chacha20poly1305.
 
 @param      info           Descriptor for the mode
 @param      key            Secret chacha20 key
 @param      nonce          Unique nonce per encryption
 @param      aad_nbytes     Length of the additional data in bytes
 @param      aad            Additional data to authenticate
 @param      ptext_nbytes   Length of the plaintext in bytes
 @param      ptext          Input plaintext
 @param      ctext          Output ciphertext
 @param      tag            Generated authentication tag
 
 @discussion See RFC 7539 for details.
 
 The key is 32 bytes in length.
 
 The nonce is 12 bytes in length.
 
 The generated tag is 16 bytes in length.
 
 In-place processing is supported.
 
 @warning The key-nonce pair must be unique per encryption.
 
 @warning A single message can be at most (2^38 - 64) bytes in length.
 */
int ccchacha20poly1305_encrypt_oneshot(const struct ccchacha20poly1305_info *info, const uint8_t *key, const uint8_t *nonce, size_t aad_nbytes, const void *aad, size_t ptext_nbytes, const void *ptext, void *ctext, uint8_t *tag);


//MARK: - Core Crypto GCM
/*!
 @function   ccgcm_one_shot
 @abstract   Encrypt or decrypt with GCM.
 
 @param      mode           Descriptor for the mode
 @param      key_nbytes     Length of the key in bytes
 @param      key            Key for the underlying blockcipher (AES)
 @param      iv_nbytes      Length of the IV in bytes
 @param      iv             Initialization vector
 @param      adata_nbytes   Length of the additional data in bytes
 @param      adata          Additional data to authenticate
 @param      nbytes         Length of the data in bytes
 @param      in             Input plaintext or ciphertext
 @param      out            Output ciphertext or plaintext
 @param      tag_nbytes     Length of the tag in bytes
 @param      tag            Authentication tag
 
 @result     0 iff successful.
 
 @discussion Perform GCM encryption or decryption.
 
 @warning The key-IV pair must be unique per encryption. The IV must be nonzero in length.
 
 In stateful protocols, if each packet exposes a guaranteed-unique value, it is recommended to format this as a 12-byte value for use as the IV.
 
 In stateless protocols, it is recommended to choose a 16-byte value using a cryptographically-secure pseudorandom number generator (e.g. @p ccrng).
 
 In-place processing is supported.
 
 On encryption, @p tag is purely an output parameter. The generated tag is written to @p tag.
 
 On decryption, @p tag is primarily an input parameter. The caller should provide the authentication tag generated during encryption. The function will return nonzero if the input tag does not match the generated tag.
 
 @warning To support legacy applications, @p tag is also an output parameter during decryption. The generated tag is written to @p tag. Legacy callers may choose to compare this to the tag generated during encryption. Do not follow this usage pattern in new applications.
 */
int ccgcm_one_shot(const struct ccmode_gcm *mode,
                   size_t key_nbytes, const void *key,
                   size_t iv_nbytes, const void *iv,
                   size_t adata_nbytes, const void *adata,
                   size_t nbytes, const void *in, void *out,
                   size_t tag_nbytes, void *tag);

const struct ccmode_gcm *ccaes_gcm_decrypt_mode(void);

//const struct ccmode_gcm *ccaes_gcm_decrypt_mode(void)
//{
//    static struct ccmode_gcm gcm_decrypt;
//#if CCMODE_GCM_VNG_SPEEDUP
//    ccaes_vng_factory_gcm_decrypt(&gcm_decrypt);
//#else
//    const struct ccmode_ecb* ecb_base_encrypt_mode = ccaes_ecb_encrypt_mode();
//    ccmode_factory_gcm_decrypt(&gcm_decrypt, ecb_base_encrypt_mode);
//#endif
//    return &gcm_decrypt;
//}

#endif /* Bindings_h */