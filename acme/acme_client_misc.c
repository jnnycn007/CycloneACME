/**
 * @file acme_client_misc.c
 * @brief Helper functions for ACME client
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2026 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneACME Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL ACME_TRACE_LEVEL

//Dependencies
#include "acme/acme_client.h"
#include "acme/acme_client_jose.h"
#include "acme/acme_client_misc.h"
#include "pkix/pem_key_import.h"
#include "pkix/pem_cert_key_import.h"
#include "pkix/x509_csr_create.h"
#include "encoding/base64url.h"
#include "encoding/oid.h"
#include "jansson.h"
#include "jansson_private.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (ACME_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Load public/private key pair
 * @param[in] keyPair Pointer to the key pair
 * @param[in] publicKey Public key (PEM format)
 * @param[in] publicKeyLen Length of the public key
 * @param[in] privateKey Private key (PEM format)
 * @param[in] privateKeyLen Length of the private key
 * @param[in] password NULL-terminated string containing the password. This
 *   parameter is required if the private key is encrypted
 * @return Error code
 **/

error_t acmeClientLoadKeyPair(AcmeKeyPair *keyPair, const char_t *publicKey,
   size_t publicKeyLen, const char_t *privateKey, size_t privateKeyLen,
   const char_t *password)
{
   error_t error;
   X509KeyType type;

   //Clear key pair
   osMemset(keyPair, 0, sizeof(AcmeKeyPair));

   //Extract the type of the public key
   type = pemGetPublicKeyType(publicKey, publicKeyLen);

#if (ACME_CLIENT_RSA_SUPPORT == ENABLED)
   //RSA public key?
   if(type == X509_KEY_TYPE_RSA)
   {
      //Save public key type
      keyPair->type = X509_KEY_TYPE_RSA;

      //Initialize RSA public and private keys
      rsaInitPublicKey(&keyPair->rsaPublicKey);
      rsaInitPrivateKey(&keyPair->rsaPrivateKey);

      //Decode the PEM file that contains the RSA public key
      error = pemImportRsaPublicKey(&keyPair->rsaPublicKey, publicKey,
         publicKeyLen);

      //Check status code
      if(!error)
      {
         //Decode the PEM file that contains the RSA private key
         error = pemImportRsaPrivateKey(&keyPair->rsaPrivateKey, privateKey,
            privateKeyLen, password);
      }

      //Check status code
      if(!error)
      {
         //Select RSA keys
         keyPair->publicKey = &keyPair->rsaPublicKey;
         keyPair->privateKey = &keyPair->rsaPrivateKey;

         //Select the relevant signature algorithm
         osStrcpy(keyPair->alg, "RS256");
      }
   }
   else
#endif
#if (ACME_CLIENT_ECDSA_SUPPORT == ENABLED)
   //EC public key?
   if(type == X509_KEY_TYPE_EC)
   {
      //Save public key type
      keyPair->type = X509_KEY_TYPE_EC;

      //Initialize EC public and private keys
      ecInitPublicKey(&keyPair->ecPublicKey);
      ecInitPrivateKey(&keyPair->ecPrivateKey);

      //Decode the PEM file that contains the EC public key
      error = pemImportEcPublicKey(&keyPair->ecPublicKey, publicKey,
         publicKeyLen);

      //Check status code
      if(!error)
      {
         //Decode the PEM file that contains the EC private key
         error = pemImportEcPrivateKey(&keyPair->ecPrivateKey, privateKey,
            privateKeyLen, password);
      }

      //Check status code
      if(!error)
      {
         //Select EC keys
         keyPair->publicKey = &keyPair->ecPublicKey;
         keyPair->privateKey = &keyPair->ecPrivateKey;

         //Select the relevant signature algorithm
         if(osStrcmp(keyPair->ecPublicKey.curve->name, "secp256r1") == 0 &&
            osStrcmp(keyPair->ecPrivateKey.curve->name, "secp256r1") == 0)
         {
            //ECDSA using P-256 and SHA-256
            osStrcpy(keyPair->alg, "ES256");
         }
         else if(osStrcmp(keyPair->ecPublicKey.curve->name, "secp384r1") == 0 &&
            osStrcmp(keyPair->ecPrivateKey.curve->name, "secp384r1") == 0)
         {
            //ECDSA using P-384 and SHA-384
            osStrcpy(keyPair->alg, "ES384");
         }
         else if(osStrcmp(keyPair->ecPublicKey.curve->name, "secp521r1") == 0 &&
            osStrcmp(keyPair->ecPrivateKey.curve->name, "secp521r1") == 0)
         {
            //ECDSA using P-521 and SHA-512
            osStrcpy(keyPair->alg, "ES512");
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_KEY;
         }
      }
   }
   else
#endif
#if (ACME_CLIENT_ED25519_SUPPORT == ENABLED)
   //Ed22519 public key?
   if(type == X509_KEY_TYPE_ED25519)
   {
      //Save public key type
      keyPair->type = X509_KEY_TYPE_ED25519;

      //Initialize EdDSA public and private keys
      eddsaInitPublicKey(&keyPair->eddsaPublicKey);
      eddsaInitPrivateKey(&keyPair->eddsaPrivateKey);

      //Decode the PEM file that contains the EdDSA public key
      error = pemImportEddsaPublicKey(&keyPair->eddsaPublicKey, publicKey,
         publicKeyLen);

      //Check status code
      if(!error)
      {
         //Decode the PEM file that contains the EdDSA private key
         error = pemImportEddsaPrivateKey(&keyPair->eddsaPrivateKey,
            privateKey, privateKeyLen, password);
      }

      //Check status code
      if(!error)
      {
         //Valid Ed25519 key pair?
         if(keyPair->eddsaPublicKey.curve == ED25519_CURVE &&
            keyPair->eddsaPrivateKey.curve == ED25519_CURVE)
         {
            //Select EdDSA keys
            keyPair->publicKey = &keyPair->eddsaPublicKey;
            keyPair->privateKey = &keyPair->eddsaPrivateKey;

            //Select the relevant signature algorithm
            osStrcpy(keyPair->alg, "EdDSA");
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_KEY;
         }
      }
   }
   else
#endif
#if (ACME_CLIENT_ED448_SUPPORT == ENABLED)
   //Ed448 public key?
   if(type == X509_KEY_TYPE_ED448)
   {
      //Save public key type
      keyPair->type = X509_KEY_TYPE_ED448;

      //Initialize EdDSA public and private keys
      eddsaInitPublicKey(&keyPair->eddsaPublicKey);
      eddsaInitPrivateKey(&keyPair->eddsaPrivateKey);

      //Decode the PEM file that contains the EdDSA public key
      error = pemImportEddsaPublicKey(&keyPair->eddsaPublicKey, publicKey,
         publicKeyLen);

      //Check status code
      if(!error)
      {
         //Decode the PEM file that contains the EdDSA private key
         error = pemImportEddsaPrivateKey(&keyPair->eddsaPrivateKey,
            privateKey, privateKeyLen, password);
      }

      //Check status code
      if(!error)
      {
         //Valid Ed448 key pair?
         if(keyPair->eddsaPublicKey.curve == ED448_CURVE &&
            keyPair->eddsaPrivateKey.curve == ED448_CURVE)
         {
            //Select EdDSA keys
            keyPair->publicKey = &keyPair->eddsaPublicKey;
            keyPair->privateKey = &keyPair->eddsaPrivateKey;

            //Select the relevant signature algorithm
            osStrcpy(keyPair->alg, "EdDSA");
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_KEY;
         }
      }
   }
   else
#endif
   //Invalid public key?
   {
      //The supplied public key is not valid
      error = ERROR_INVALID_KEY;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      acmeClientUnloadKeyPair(keyPair);
   }

   //Return status code
   return error;
}


/**
 * @brief Load certificate/private key pair
 * @param[in] keyPair Pointer to the key pair
 * @param[in] cert Certificate (PEM format)
 * @param[in] certLen Length of the certificate
 * @param[in] privateKey Private key (PEM format)
 * @param[in] privateKeyLen Length of the private key
 * @param[in] password NULL-terminated string containing the password. This
 *   parameter is required if the private key is encrypted
 * @return Error code
 **/

error_t acmeClientLoadCertKeyPair(AcmeKeyPair *keyPair, const char_t *cert,
   size_t certLen, const char_t *privateKey, size_t privateKeyLen,
   const char_t *password)
{
   error_t error;
   X509KeyType type;

   //Clear key pair
   osMemset(keyPair, 0, sizeof(AcmeKeyPair));

   //Extract the type of the public key contained in the certificate
   type = pemGetCertPublicKeyType(cert, certLen);

#if (ACME_CLIENT_RSA_SUPPORT == ENABLED)
   //RSA public key?
   if(type == X509_KEY_TYPE_RSA)
   {
      //Save public key type
      keyPair->type = X509_KEY_TYPE_RSA;

      //Initialize RSA public and private keys
      rsaInitPublicKey(&keyPair->rsaPublicKey);
      rsaInitPrivateKey(&keyPair->rsaPrivateKey);

      //Extract the RSA public key from the certificate
      error = pemImportRsaCertPublicKey(&keyPair->rsaPublicKey, cert, certLen);

      //Check status code
      if(!error)
      {
         //Decode the PEM file that contains the RSA private key
         error = pemImportRsaPrivateKey(&keyPair->rsaPrivateKey, privateKey,
            privateKeyLen, password);
      }

      //Check status code
      if(!error)
      {
         //Select RSA keys
         keyPair->publicKey = &keyPair->rsaPublicKey;
         keyPair->privateKey = &keyPair->rsaPrivateKey;

         //Select the relevant signature algorithm
         osStrcpy(keyPair->alg, "RS256");
      }
   }
   else
#endif
#if (ACME_CLIENT_ECDSA_SUPPORT == ENABLED)
   //EC public key?
   if(type == X509_KEY_TYPE_EC)
   {
      //Save public key type
      keyPair->type = X509_KEY_TYPE_EC;

      //Initialize EC public and private keys
      ecInitPublicKey(&keyPair->ecPublicKey);
      ecInitPrivateKey(&keyPair->ecPrivateKey);

      //Extract the EC public key from the certificate
      error = pemImportEcCertPublicKey(&keyPair->ecPublicKey, cert, certLen);

      //Check status code
      if(!error)
      {
         //Decode the PEM file that contains the EC private key
         error = pemImportEcPrivateKey(&keyPair->ecPrivateKey, privateKey,
            privateKeyLen, password);
      }

      //Check status code
      if(!error)
      {
         //Select EC keys
         keyPair->publicKey = &keyPair->ecPublicKey;
         keyPair->privateKey = &keyPair->ecPrivateKey;

         //Select the relevant signature algorithm
         if(osStrcmp(keyPair->ecPublicKey.curve->name, "secp256r1") == 0 &&
            osStrcmp(keyPair->ecPrivateKey.curve->name, "secp256r1") == 0)
         {
            //ECDSA using P-256 and SHA-256
            osStrcpy(keyPair->alg, "ES256");
         }
         else if(osStrcmp(keyPair->ecPublicKey.curve->name, "secp384r1") == 0 &&
            osStrcmp(keyPair->ecPrivateKey.curve->name, "secp384r1") == 0)
         {
            //ECDSA using P-384 and SHA-384
            osStrcpy(keyPair->alg, "ES384");
         }
         else if(osStrcmp(keyPair->ecPublicKey.curve->name, "secp521r1") == 0 &&
            osStrcmp(keyPair->ecPrivateKey.curve->name, "secp521r1") == 0)
         {
            //ECDSA using P-521 and SHA-512
            osStrcpy(keyPair->alg, "ES512");
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_KEY;
         }
      }
   }
   else
#endif
#if (ACME_CLIENT_ED25519_SUPPORT == ENABLED)
   //Ed22519 public key?
   if(type == X509_KEY_TYPE_ED25519)
   {
      //Save public key type
      keyPair->type = X509_KEY_TYPE_ED25519;

      //Initialize EdDSA public and private keys
      eddsaInitPublicKey(&keyPair->eddsaPublicKey);
      eddsaInitPrivateKey(&keyPair->eddsaPrivateKey);

      //Extract the EdDSA public key from the certificate
      error = pemImportEddsaCertPublicKey(&keyPair->eddsaPublicKey, cert,
         certLen);

      //Check status code
      if(!error)
      {
         //Decode the PEM file that contains the EdDSA private key
         error = pemImportEddsaPrivateKey(&keyPair->eddsaPrivateKey,
            privateKey, privateKeyLen, password);
      }

      //Check status code
      if(!error)
      {
         //Valid Ed25519 key pair?
         if(keyPair->eddsaPublicKey.curve == ED25519_CURVE &&
            keyPair->eddsaPrivateKey.curve == ED25519_CURVE)
         {
            //Select EdDSA keys
            keyPair->publicKey = &keyPair->eddsaPublicKey;
            keyPair->privateKey = &keyPair->eddsaPrivateKey;

            //Select the relevant signature algorithm
            osStrcpy(keyPair->alg, "EdDSA");
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_KEY;
         }
      }
   }
   else
#endif
#if (ACME_CLIENT_ED448_SUPPORT == ENABLED)
   //Ed448 public key?
   if(type == X509_KEY_TYPE_ED448)
   {
      //Save public key type
      keyPair->type = X509_KEY_TYPE_ED448;

      //Initialize EdDSA public and private keys
      eddsaInitPublicKey(&keyPair->eddsaPublicKey);
      eddsaInitPrivateKey(&keyPair->eddsaPrivateKey);

      //Extract the EdDSA public key from the certificate
      error = pemImportEddsaCertPublicKey(&keyPair->eddsaPublicKey, cert,
         certLen);

      //Check status code
      if(!error)
      {
         //Decode the PEM file that contains the EdDSA private key
         error = pemImportEddsaPrivateKey(&keyPair->eddsaPrivateKey,
            privateKey, privateKeyLen, password);
      }

      //Check status code
      if(!error)
      {
         //Valid Ed448 key pair?
         if(keyPair->eddsaPublicKey.curve == ED448_CURVE &&
            keyPair->eddsaPrivateKey.curve == ED448_CURVE)
         {
            //Select EdDSA keys
            keyPair->publicKey = &keyPair->eddsaPublicKey;
            keyPair->privateKey = &keyPair->eddsaPrivateKey;

            //Select the relevant signature algorithm
            osStrcpy(keyPair->alg, "EdDSA");
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_KEY;
         }
      }
   }
   else
#endif
   //Invalid public key?
   {
      //The supplied public key is not valid
      error = ERROR_INVALID_KEY;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      acmeClientUnloadKeyPair(keyPair);
   }

   //Return status code
   return error;
}


/**
 * @brief Unload public/private key pair
 * @param[in] keyPair Pointer to the key pair
 **/

void acmeClientUnloadKeyPair(AcmeKeyPair *keyPair)
{
#if (ACME_CLIENT_RSA_SUPPORT == ENABLED)
   //RSA key pair?
   if(keyPair->type == X509_KEY_TYPE_RSA)
   {
      //Release RSA public and private keys
      rsaFreePublicKey(&keyPair->rsaPublicKey);
      rsaFreePrivateKey(&keyPair->rsaPrivateKey);
   }
   else
#endif
#if (ACME_CLIENT_ECDSA_SUPPORT == ENABLED)
   //EC key pair?
   if(keyPair->type == X509_KEY_TYPE_EC)
   {
      //Release EC public and private keys
      ecFreePublicKey(&keyPair->ecPublicKey);
      ecFreePrivateKey(&keyPair->ecPrivateKey);
   }
   else
#endif
#if (ACME_CLIENT_ED25519_SUPPORT == ENABLED) || \
   (ACME_CLIENT_ED448_SUPPORT == ENABLED)
   //EdDSA key pair?
   if(keyPair->type == X509_KEY_TYPE_ED25519 ||
      keyPair->type == X509_KEY_TYPE_ED448)
   {
      //Release EdDSA public and private keys
      eddsaFreePublicKey(&keyPair->eddsaPublicKey);
      eddsaFreePrivateKey(&keyPair->eddsaPrivateKey);
   }
   else
#endif
   //Invalid key pair?
   {
      //Just for sanity
   }

   //Clear key pair
   osMemset(keyPair, 0, sizeof(AcmeKeyPair));
}


/**
 * @brief Send HTTP request
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientSendRequest(AcmeClientContext *context)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Check HTTP request state
   if(context->requestState == ACME_REQ_STATE_SEND_HEADER)
   {
      //Send HTTP request header
      error = httpClientWriteHeader(&context->httpClientContext);

      //Check status code
      if(!error)
      {
         //Check whether the HTTP request contains a body
         if(context->bufferLen > 0)
         {
            //Debug message
            TRACE_DEBUG("HTTP request body (%" PRIuSIZE " bytes):\r\n", context->bufferLen);
            TRACE_DEBUG("%s\r\n\r\n", context->buffer);

            //Point to the first byte of the body
            context->bufferPos = 0;

            //Send HTTP request body
            context->requestState = ACME_REQ_STATE_SEND_BODY;
         }
         else
         {
            //Receive HTTP response header
            context->requestState = ACME_REQ_STATE_RECEIVE_HEADER;
         }
      }
   }
   else if(context->requestState == ACME_REQ_STATE_SEND_BODY)
   {
      //Send HTTP request body
      if(context->bufferPos < context->bufferLen)
      {
         //Send more data
         error = httpClientWriteBody(&context->httpClientContext,
            context->buffer + context->bufferPos,
            context->bufferLen - context->bufferPos, &n, 0);

         //Check status code
         if(!error)
         {
            //Advance data pointer
            context->bufferPos += n;
         }
      }
      else
      {
         //Update HTTP request state
         context->requestState = ACME_REQ_STATE_RECEIVE_HEADER;
      }
   }
   else if(context->requestState == ACME_REQ_STATE_RECEIVE_HEADER)
   {
      //Receive HTTP response header
      error = httpClientReadHeader(&context->httpClientContext);

      //Check status code
      if(!error)
      {
         //Update HTTP request state
         context->requestState = ACME_REQ_STATE_PARSE_HEADER;
      }
   }
   else if(context->requestState == ACME_REQ_STATE_PARSE_HEADER)
   {
      //Parse HTTP response header
      error = acmeClientParseResponseHeader(context);

      //Check status code
      if(!error)
      {
         //Flush the receive buffer
         context->bufferLen = 0;
         context->bufferPos = 0;

         //Update HTTP request state
         context->requestState = ACME_REQ_STATE_RECEIVE_BODY;
      }
   }
   else if(context->requestState == ACME_REQ_STATE_RECEIVE_BODY)
   {
      //Receive HTTP response body
      if(context->bufferLen < ACME_CLIENT_BUFFER_SIZE)
      {
         //Receive more data
         error = httpClientReadBody(&context->httpClientContext,
            context->buffer + context->bufferLen,
            ACME_CLIENT_BUFFER_SIZE - context->bufferLen, &n, 0);

         //Check status code
         if(error == NO_ERROR)
         {
            //Advance data pointer
            context->bufferLen += n;
         }
         else if(error == ERROR_END_OF_STREAM)
         {
            //The end of the response body has been reached
            error = NO_ERROR;

            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_CLOSE_BODY;
         }
         else
         {
            //Just for sanity
         }
      }
      else
      {
         //Update HTTP request state
         context->requestState = ACME_REQ_STATE_CLOSE_BODY;
      }
   }
   else if(context->requestState == ACME_REQ_STATE_CLOSE_BODY)
   {
      //Close HTTP response body
      error = httpClientCloseBody(&context->httpClientContext);

      //Check status code
      if(!error)
      {
         //Properly terminate the body with a NULL character
         context->buffer[context->bufferLen] = '\0';

         //Debug message
         if(context->bufferLen > 0)
         {
            TRACE_DEBUG("HTTP response body (%" PRIuSIZE " bytes):\r\n", context->bufferLen);
            TRACE_DEBUG("%s\r\n\r\n", context->buffer);
         }

         //Clear error description
         context->errorType[0] = '\0';

         //Check HTTP status code
         if(!HTTP_STATUS_CODE_2YZ(context->statusCode))
         {
            //When the server responds with an error status, it should provide
            //additional information using a problem document (refer to RFC 8555,
            //section 6.7)
            acmeClientParseProblemDetails(context);

            //An error response with the "badNonce" error type must include a
            //Replay-Nonce header field with a fresh nonce that the server will
            //accept in a retry of the original query
            if(osStrcmp(context->errorType, "urn:ietf:params:acme:error:badNonce") == 0 &&
               context->badNonceErrors < ACME_CLIENT_MAX_BAD_NONCE_ERRORS &&
               context->nonce[0] != '\0')
            {
               //Increment error counter
               context->badNonceErrors++;

               //On receiving such a response, a client should retry the request
               //using the new nonce (refer to RFC 8555, section 6.5)
               context->requestState = ACME_REQ_STATE_INIT;
            }
            else
            {
               //Reset error counter
               context->badNonceErrors = 0;
               //Update HTTP request state
               context->requestState = ACME_REQ_STATE_COMPLETE;
            }
         }
         else
         {
            //Reset error counter
            context->badNonceErrors = 0;
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_COMPLETE;
         }
      }
   }
   else
   {
      //Invalid state
      error = ERROR_WRONG_STATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Format HTTP request header
 * @param[in] context Pointer to the ACME client context
 * @param[in] method NULL-terminating string containing the HTTP method
 * @param[in] url Target URL
 * @return Error code
 **/

error_t acmeClientFormatRequestHeader(AcmeClientContext *context,
   const char_t *method, const char_t *url)
{
   error_t error;
   const char_t *path;

   //Make sure the URL is valid
   if(url == NULL || url[0] == '\0')
      return ERROR_INVALID_PARAMETER;

   //Create a new HTTP request
   error = httpClientCreateRequest(&context->httpClientContext);
   //Any error to report?
   if(error)
      return error;

   //Set HTTP request method
   error = httpClientSetMethod(&context->httpClientContext, method);
   //Any error to report?
   if(error)
      return error;

   //Get the path portion of the URL
   path = acmeClientGetPath(url);

   //The URI identifies a particular resource
   error = httpClientSetUri(&context->httpClientContext, path);
   //Any error to report?
   if(error)
      return error;

   //A client must send a Host header field in all HTTP/1.1 requests (refer
   //to RFC 7230, section 5.4)
   if(context->serverPort == HTTPS_PORT)
   {
      //A host without any trailing port information implies the default port
      //for the service requested
      error = httpClientAddHeaderField(&context->httpClientContext, "Host",
         context->serverName);
   }
   else
   {
      //Append the port number information to the host
      error = httpClientFormatHeaderField(&context->httpClientContext,
         "Host", "%s:%" PRIu16, context->serverName, context->serverPort);
   }

   //Any error to report?
   if(error)
      return error;

   //ACME clients must send a User-Agent header field (refer to RFC 8555,
   //section 6.1)
   error = httpClientAddHeaderField(&context->httpClientContext, "User-Agent",
      "Mozilla/5.0");
   //Any error to report?
   if(error)
      return error;

   //Check ACME client state
   if(context->state == ACME_CLIENT_STATE_DOWNLOAD_CERT)
   {
      //The default format is application/pem-certificate-chain (refer to
      //RFC 8555, section 7.4.2)
      error = httpClientAddHeaderField(&context->httpClientContext, "Accept",
         "application/pem-certificate-chain");
      //Any error to report?
      if(error)
         return error;
   }

   //POST request?
   if(osStrcmp(method, "POST") == 0)
   {
      //Client requests must have the Content-Type header field set to
      //"application/jose+json" (refer to RFC 8555, section 6.2)
      error = httpClientAddHeaderField(&context->httpClientContext,
         "Content-Type", "application/jose+json");
      //Any error to report?
      if(error)
         return error;

      //Specify the length of the request body
      error = httpClientSetContentLength(&context->httpClientContext,
         context->bufferLen);
      //Any error to report?
      if(error)
         return error;

      //Once a nonce value has appeared in an ACME request, the server will
      //consider it invalid (refer to RFC 8555, section 6.5)
      context->nonce[0] = '\0';
   }
   else
   {
      //The HTTP request body is empty
      context->bufferLen = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format JWS protected header
 * @param[in] keyPair Pointer to the key pair
 * @param[in] kid Key identifier (account URL)
 * @param[in] nonce Unique value that enables the verifier of a JWS to
 *   recognize when replay has occurred
 * @param[in] url URL to which the client is directing the request
 * @param[out] buffer Output buffer where to store the JSON object
 * @param[out] written Length of the resulting JSON object
 * @return Error code
 **/

error_t acmeClientFormatJwsProtectedHeader(const AcmeKeyPair *keyPair,
   const char_t *kid, const char_t *nonce, const char_t *url,
   char_t *buffer, size_t *written)
{
   error_t error;
   int_t ret;
   size_t n;
   char_t *protected;
   json_t *protectedObj;

   //Initialize status code
   error = NO_ERROR;

   //Initialize pointer
   protected = NULL;

   //Initialize JSON object
   protectedObj = json_object();

   //Start of exception handling block
   do
   {
      //The "alg" (algorithm) Header Parameter identifies the cryptographic
      //algorithm used to secure the JWS (refer to RFC 7515, section 4.1.1)
      ret = json_object_set_new(protectedObj, "alg", json_string(keyPair->alg));
      //Any error to report?
      if(ret != 0)
         break;

      //The "jwk" and "kid" fields are mutually exclusive (refer to RFC 8555,
      //section 6.2)
      if(kid == NULL)
      {
         //Export the public key to JWK format
         error = acmeClientFormatJwk(keyPair, buffer, &n, FALSE);
         //Any error to report?
         if(error)
            break;

         //For newAccount requests, and for revokeCert requests authenticated by
         //a certificate key, there must be a "jwk" field
         ret = json_object_set_new(protectedObj, "jwk", json_loads(buffer, 0, NULL));
         //Any error to report?
         if(ret != 0)
            break;
      }
      else
      {
         //For all other requests, the request is signed using an existing
         //account, and there must be a "kid" field
         ret = json_object_set_new(protectedObj, "kid", json_string(kid));
         //Any error to report?
         if(ret != 0)
            break;
      }

      //Valid nonce?
      if(nonce != NULL)
      {
         //The "nonce" header parameter must be carried in the protected header
         //of the JWS (refer to RFC 8555, section 6.5.2)
         ret = json_object_set_new(protectedObj, "nonce", json_string(nonce));
         //Any error to report?
         if(ret != 0)
            break;
      }

      //The JWS protected header must include an "url" field
      ret = json_object_set_new(protectedObj, "url", json_string(url));
      //Any error to report?
      if(ret != 0)
         break;

      //Generate the JSON representation of the JWK object
      protected = json_dumps(protectedObj, JSON_COMPACT);

      //End of exception handling block
   } while(0);

   //Valid JSON representation?
   if(protected != NULL)
   {
      //Copy JSON string
      osStrcpy(buffer, protected);
      //Total number of bytes that have been written
      *written = osStrlen(protected);

      //Release JSON string
      jsonp_free(protected);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release JSON object
   json_decref(protectedObj);

   //Return status code
   return error;
}


/**
 * @brief Export a public key to JWK format
 * @param[in] keyPair Pointer to the key pair
 * @param[out] buffer Output buffer where to store the JSON representation
 * @param[out] written Length of the resulting JSON representation
 * @param[in] sort Sort members of the JWK representation in lexicographic order
 * @return Error code
 **/

error_t acmeClientFormatJwk(const AcmeKeyPair *keyPair, char_t *buffer,
   size_t *written, bool_t sort)
{
   error_t error;

#if (ACME_CLIENT_RSA_SUPPORT == ENABLED)
   //RSA public key?
   if(keyPair->type == X509_KEY_TYPE_RSA)
   {
      //Export the RSA public key to JWK format
      error = jwkExportRsaPublicKey(&keyPair->rsaPublicKey, buffer, written,
         sort);
   }
   else
#endif
#if (ACME_CLIENT_ECDSA_SUPPORT == ENABLED)
   //EC public key?
   if(keyPair->type == X509_KEY_TYPE_EC)
   {
      //Export the EC public key to JWK format
      error = jwkExportEcPublicKey(&keyPair->ecPublicKey, buffer, written,
         sort);
   }
   else
#endif
#if (ACME_CLIENT_ED25519_SUPPORT == ENABLED) || \
   (ACME_CLIENT_ED448_SUPPORT == ENABLED)
   //EdDSA public key?
   if(keyPair->type == X509_KEY_TYPE_ED25519 ||
      keyPair->type == X509_KEY_TYPE_ED448)
   {
      //Export the EdDSA public key to JWK format
      error = jwkExportEddsaPublicKey(&keyPair->eddsaPublicKey, buffer,
         written, sort);
   }
   else
#endif
   //Invalid public key?
   {
      //Report an error
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
}


/**
 * @brief Generate CSR (Certificate Signing Request)
 * @param[in] context Pointer to the ACME client context
 * @param[out] buffer Output buffer where to store the CSR
 * @param[out] written Length of the resulting CSR
 * @return Error code
 **/

error_t acmeClientGenerateCsr(AcmeClientContext *context, uint8_t *buffer,
   size_t *written)
{
   error_t error;
   uint_t i;
   X509CertRequestInfo *certReqInfo;
   X509SubjectAltName *subjectAltName;
   X509SignAlgoId signatureAlgo;

   //Initialize status code
   error = NO_ERROR;

   //Allocate a memory buffer to hold the certificate request information
   certReqInfo = cryptoAllocMem(sizeof(X509CertRequestInfo));

   //Successful memory allocation?
   if(certReqInfo != NULL)
   {
      //Clear certificate request information
      osMemset(certReqInfo, 0, sizeof(X509CertRequestInfo));

      //The CSR must indicate the exact same set of requested identifiers as the
      //initial newOrder request (refer to RFC 8555, section 7.4)
      certReqInfo->subject.commonName.value = context->identifiers[0].value;
      certReqInfo->subject.commonName.length = osStrlen(context->identifiers[0].value);

      //The Subject Alternative Name extension allows identities to be bound
      //to the subject of the certificate.  These identities may be included
      //in addition to or in place of the identity in the subject field of the
      //certificate (refer to RFC 8555, section 4.2.1.6)
      subjectAltName = &certReqInfo->attributes.extensionReq.subjectAltName;

      //The extension may contain multiple domain names
      subjectAltName->numGeneralNames = MIN(context->numIdentifiers,
         X509_MAX_SUBJECT_ALT_NAMES);

      //Set the Subject Alternative Name extension
      for(i = 0; i < subjectAltName->numGeneralNames; i++)
      {
         subjectAltName->generalNames[i].type = X509_GENERAL_NAME_TYPE_DNS;
         subjectAltName->generalNames[i].value = context->identifiers[i].value;
         subjectAltName->generalNames[i].length = osStrlen(context->identifiers[i].value);
      }

#if (ACME_CLIENT_RSA_SUPPORT == ENABLED)
      //RSA key pair?
      if(context->certKey.type == X509_KEY_TYPE_RSA)
      {
         //Set public key identifier
         certReqInfo->subjectPublicKeyInfo.oid.value = RSA_ENCRYPTION_OID;
         certReqInfo->subjectPublicKeyInfo.oid.length = sizeof(RSA_ENCRYPTION_OID);

         //Select the signature algorithm
         signatureAlgo.oid.value = SHA256_WITH_RSA_ENCRYPTION_OID;
         signatureAlgo.oid.length = sizeof(SHA256_WITH_RSA_ENCRYPTION_OID);
      }
      else
#endif
#if (ACME_CLIENT_ECDSA_SUPPORT == ENABLED)
      //EC key pair?
      if(context->certKey.type == X509_KEY_TYPE_EC)
      {
         X509OctetString *namedCurve;

         //Set public key identifier
         certReqInfo->subjectPublicKeyInfo.oid.value = EC_PUBLIC_KEY_OID;
         certReqInfo->subjectPublicKeyInfo.oid.length = sizeof(EC_PUBLIC_KEY_OID);

         //Select the signature algorithm
         signatureAlgo.oid.value = ECDSA_WITH_SHA256_OID;
         signatureAlgo.oid.length = sizeof(ECDSA_WITH_SHA256_OID);

         //Point to the named curve
         namedCurve = &certReqInfo->subjectPublicKeyInfo.ecParams.namedCurve;

         //Valid elliptic curve?
         if(context->certKey.ecPublicKey.curve != NULL)
         {
            //Select the relevant named curve
            namedCurve->value = context->certKey.ecPublicKey.curve->oid;
            namedCurve->length = context->certKey.ecPublicKey.curve->oidSize;
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_KEY;
         }
      }
      else
#endif
#if (ACME_CLIENT_ED25519_SUPPORT == ENABLED)
      //Ed25519 key pair?
      if(context->certKey.type == X509_KEY_TYPE_ED25519)
      {
         //Set public key identifier
         certReqInfo->subjectPublicKeyInfo.oid.value = ED25519_OID;
         certReqInfo->subjectPublicKeyInfo.oid.length = sizeof(ED25519_OID);

         //Select the signature algorithm
         signatureAlgo.oid.value = ED25519_OID;
         signatureAlgo.oid.length = sizeof(ED25519_OID);
      }
      else
#endif
#if (ACME_CLIENT_ED448_SUPPORT == ENABLED)
      //Ed448 key pair?
      if(context->certKey.type == X509_KEY_TYPE_ED448)
      {
         //Set public key identifier
         certReqInfo->subjectPublicKeyInfo.oid.value = ED448_OID;
         certReqInfo->subjectPublicKeyInfo.oid.length = sizeof(ED448_OID);

         //Select the signature algorithm
         signatureAlgo.oid.value = ED448_OID;
         signatureAlgo.oid.length = sizeof(ED448_OID);
      }
      else
#endif
      //Invalid key pair?
      {
         //Report an error
         error = ERROR_INVALID_KEY;
      }

      //Check status code
      if(!error)
      {
         //The CSR is signed by the private key corresponding to the public key
         error = x509CreateCsr(context->prngAlgo, context->prngContext,
            certReqInfo, context->certKey.publicKey, &signatureAlgo,
            context->certKey.privateKey, (uint8_t *) buffer, written);
      }

      //Release previously allocated memory
      cryptoFreeMem(certReqInfo);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Parse HTTP response header
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientParseResponseHeader(AcmeClientContext *context)
{
   error_t error;
   size_t n;
   char_t *p;
   const char_t *nonce;
   const char_t *location;
   const char_t *contentType;

   //Get HTTP response status code
   context->statusCode = httpClientGetStatus(&context->httpClientContext);

   //The server must include a Replay-Nonce header field in every successful
   //response to a POST request and should provide it in error responses as well
   if(context->state != ACME_CLIENT_STATE_DIRECTORY)
   {
      //The Replay-Nonce HTTP header field includes a server-generated value
      //that the server can use to detect unauthorized replay in future client
      //requests (refer to RFC 8555, section 6.5.1)
      nonce = httpClientGetHeaderField(&context->httpClientContext,
         "Replay-Nonce");

      //Replay-Nonce header field found?
      if(nonce != NULL)
      {
         //Check the length of the header field value
         if(osStrlen(nonce) <= ACME_CLIENT_MAX_NONCE_LEN)
         {
            //The value of the Replay-Nonce header field must be an octet string
            //encoded according to the Base64url
            error = base64urlDecode(nonce, osStrlen(nonce), NULL, &n);

            //Clients must ignore invalid Replay-Nonce values
            if(!error)
            {
               //Copy the value of the Replay-Nonce header field
               osStrcpy(context->nonce, nonce);
            }
         }
      }
   }

   //When the server responds to a newAccount or a newOrder requests it must
   //return a Location header field pointing to the created resource
   if(context->state == ACME_CLIENT_STATE_NEW_ACCOUNT)
   {
      //The server returns the account URL in a Location header field (refer
      //to RFC 8555, section 7.3)
      location = httpClientGetHeaderField(&context->httpClientContext,
         "Location");

      //Location header field found?
      if(location != NULL)
      {
         //Check the length of the header field value
         if(osStrlen(location) <= ACME_CLIENT_MAX_URL_LEN)
         {
            //Copy the value of the Location header field
            osStrcpy(context->account.url, location);
         }
      }
   }
   else if(context->state == ACME_CLIENT_STATE_NEW_ORDER)
   {
      //The server returns the order identifier in a Location header field
      location = httpClientGetHeaderField(&context->httpClientContext,
         "Location");

      //Location header field found?
      if(location != NULL)
      {
         //Check the length of the header field value
         if(osStrlen(location) <= ACME_CLIENT_MAX_URL_LEN)
         {
            //Copy the value of the Location header field
            osStrcpy(context->order.url, location);
         }
      }
   }
   else
   {
      //Just for sanity
   }

   //Get the Content-Type header field
   contentType = httpClientGetHeaderField(&context->httpClientContext,
      "Content-Type");

   //Content-Type header field found?
   if(contentType != NULL)
   {
      //Retrieve the header field value
      n = osStrlen(contentType);
      //Limit the length of the string
      n = MIN(n, ACME_CLIENT_MAX_CONTENT_TYPE_LEN);

      //Save the media type
      osStrncpy(context->contentType, contentType, n);
      //Properly terminate the string with a NULL character
      context->contentType[n] = '\0';

      //Discard the parameters that may follow the type/subtype
      osStrtok_r(context->contentType, "; \t", &p);
   }
   else
   {
      //The Content-Type header field is not present in the response
      context->contentType[0] = '\0';
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse error response
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientParseProblemDetails(AcmeClientContext *context)
{
   error_t error;
   const char_t *type;
   json_t *rootObj;
   json_t *typeObj;

   //Initialize status code
   error = ERROR_INVALID_RESPONSE;

   //Clear error type
   context->errorType[0] = '\0';

   //Check the media type
   if(osStrcasecmp(context->contentType, "application/problem+json") == 0)
   {
      //When the server responds with an error status, it should provide
      //additional information using a problem document (refer to RFC 7807)
      rootObj = json_loads(context->buffer, 0, NULL);

      //Successful parsing?
      if(json_is_object(rootObj))
      {
         //The "type" string is used as the primary identifier for the problem
         //type
         typeObj = json_object_get(rootObj, "type");

         //The object must be a valid string
         if(json_is_string(typeObj))
         {
            //Get the value of the string
            type = json_string_value(typeObj);

            //Check the length of the URN
            if(osStrlen(type) <= ACME_CLIENT_MAX_URN_LEN)
            {
               //Save the error type
               osStrcpy(context->errorType, type);

               //Successful parsing
               error = NO_ERROR;
            }
         }
      }

      //Release JSON object
      json_decref(rootObj);
   }

   //Return status code
   return error;
}


/**
 * @brief TLS initialization
 * @param[in] httpClientContext Pointer to the HTTP client context
 * @param[in] tlsContext Pointer to the TLS context
 * @param[in] param Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientInitTlsContext(HttpClientContext *httpClientContext,
   TlsContext *tlsContext, void *param)
{
   error_t error;
   AcmeClientContext *context;

   //Point to the ACME client context
   context = (AcmeClientContext *) param;

   //Perform TLS related initialization
   if(context->tlsInitCallback != NULL)
   {
      //Invoke callback function
      error = context->tlsInitCallback(context, tlsContext);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Extract the path name from a given URL
 * @brief param[in] NULL-terminated string that contains the URL
 * @return Path component of the URL
 **/

const char_t *acmeClientGetPath(const char_t *url)
{
   const char_t *p;

   //Default path name
   static const char_t defaultPath[] = "/";

   //The scheme is followed by a colon and two forward slashes
   p = osStrstr(url, "://");

   //The path name begins with a single forward slash
   if(p != NULL)
   {
      p = osStrchr(p + 3, '/');
   }
   else
   {
      p = osStrchr(url, '/');
   }

   //A path is always defined for a URI, though the defined path may be empty
   if(p == NULL)
   {
      p = defaultPath;
   }

   //Return the path component
   return p;
}

#endif
