"use strict";

/********* Imports ********/

import {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  HMACWithSHA256,
  HMACWithSHA512,
  SHA256,
  SHA512,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  generateEG,
  computeDH,
  generateECDSA,
  signWithECDSA,
  verifyWithECDSA,
  randomHexString,
  hexStringSlice,
} from "./lib";

/********* Implementation ********/


export default class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
      // the certificate authority DSA public key is used to
      // verify the authenticity and integrity of certificates
      // of other users (see handout and receiveCertificate)

      // you can store data as needed in these objects.
      // Feel free to modify their structure as you see fit.
      this.caPublicKey = certAuthorityPublicKey;
      this.govPublicKey = govPublicKey;
      this.conns = {}; // data for each active connection
      this.certs = {}; // certificates of other users
      this.secrets = {}; // our secret data
    };

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  generateCertificate(username) {

    // Generate EG keypair for certificate
    const certificateKeyPair = generateEG();

    // Put public key in certificate
    const certificate = {
      username: username,
      pk: certificateKeyPair.pub
    };

    // Store private key
    this.secrets.sk = certificateKeyPair.sec;

    // Return the certificate
    return certificate;
  }

  /**
   * Receive and store another user's certificate.
   *
   * Arguments:
   *   certificate: certificate object/dictionary
   *   signature: string
   *
   * Return Type: void
   */
  receiveCertificate(certificate, signature) {
    // stringifies certificate for signature verification
    const certificate_json = JSON.stringify(certificate);

    // Attempts to verify signature, throws exception if fails
    if (verifyWithECDSA(this.caPublicKey, certificate_json, signature)) {
      // If signature verification successful, stores certificate
      this.certs[certificate.username] = certificate.pk;
      this.conns[certificate.username] = {
        sentMessage: false,
        receivedMessage: false
      };
    }
  }

  /**
   * Generate the message to be sent to another user.
   *
   * Arguments:
   *   name: string
   *   plaintext: string
   *
   * Return Type: Tuple of [dictionary, string]
   */
  sendMessage(name, plaintext) {
    var kdfOutput; 
    var messageKey;
    var keypairObject;
    // If have never communicated with user before
    if (!(this.conns[name].sentMessage)) {
      // Generate an EG keypair
      keypairObject = generateEG();

      // Store these as the current DH ratchet keys
      this.conns[name].myDHsk = keypairObject.sec;
      this.conns[name].myDHpk = keypairObject.pub;

      /* Computes a shared secret from the secret key associated with our certificate and the public key associated with their certificate */
      var rootKey = computeDH(this.secrets.sk,this.certs[name]);
      /* Computes DH salt from our current EG secret key and their certificate public key */
      var DHsalt = computeDH(this.conns[name].myDHsk,this.certs[name]);
      /* Obtain a root chain key and a send chain key by HKDFing root_key and DHsalt */
      kdfOutput = HKDF(rootKey,512,DHsalt,"HKDF");
      this.conns[name].currentRootKey = hexStringSlice(kdfOutput,0,256);
      this.conns[name].currentSendKey = hexStringSlice(kdfOutput,256,512);
    }
    // Now obtain a message key by building a KDF out of HMAC and increment send key for next time
    kdfOutput = HMACWithSHA512(this.conns[name].currentSendKey,"message key generation");
    this.conns[name].currentSendKey = hexStringSlice(kdfOutput,0,256);
    messageKey = hexStringSlice(kdfOutput,256,384);

    // Encrypt the messageKey with the government public key using ElGamal encrypton
    keypairObject = generateEG();
    const header = {
      DHpk: this.conns[name].myDHpk,
      vGov: keypairObject.pub,
      cGov: encryptWithGCM( hexStringSlice(computeDH(keypairObject.sec,this.govPublicKey),0,128), messageKey )
    };

    // Encrypt the plaintext with the messageKey, passing the header as authenticated data
    const ciphertext = encryptWithGCM(messageKey, plaintext, JSON.stringify(header));
    return [header, ciphertext];
  }


  /**
   * Decrypt a message received from another user.
   *
   * Arguments:
   *   name: string
   *   [header, ciphertext]: Tuple of [dictionary, string]
   *
   * Return Type: string
   */
  receiveMessage(name, [header, ciphertext]) {
    // If haven't communicated with the sender before
    var kdfOutput;
    var keypairObject;
    var messageKey;
    var plaintext;
    if (!(this.conns[name].receivedMessage)) {
      // The sender's current DH public key
      this.conns[name].theirDHpk = header.DHpk;

      // Generate an EG keypair
      keypairObject = generateEG();
      this.conns[name].myDHpk = keypairObject.pub;
      this.conns[name].myDHsk = keypairObject.sec;

      /* Computes the shared secret from the secret key associated with our certificate and the public key associated with their certificate */
      var rootKey = computeDH(this.secrets.sk,this.certs[name]);
      /* Computes DH salt from the secret key associated to our certificate, and the public key sent with the header */
      var DHsalt = computeDH(this.secrets.sk,header.DHpk);
      // HKDF to get root key and send key
      kdfOutput = HKDF(rootKey,512,DHsalt,"HKDF");
      this.conns[name].currentRootKey = hexStringSlice(kdfOutput,0,256);
      this.conns[name].currentReceiveKey = hexStringSlice(kdfOutput,256,512);
    }
    if (!(this.conns[name].theirDHpk==header.DHpk)) {

      // Generate an EG keypair
      keypairObject = generateEG();
      var DHsalt = computeDH(this.conns[name].myDHpk, header.DHpk);

      // Update root key and receive key
      kdfOutput = HKDF(this.conns[name].currentRootKey,512,DHsalt,"HKDF");
      this.conns[name].currentRootKey = hexStringSlice(kdfOutput,0,256);
      this.conns[name].currentReceiveKey = hexStringSlice(kdfOutput,256,512);
    }

    // Now obtain a message key by building a KDF out of HMAC 
    kdfOutput = HMACWithSHA512(this.conns[name].currentReceiveKey,"message key generation");
    this.conns[name].currentReceiveKey = hexStringSlice(kdfOutput,0,256);
    messageKey = hexStringSlice(kdfOutput,256,384);

    // decrypts the message
    plaintext = decryptWithGCM(messageKey, ciphertext, JSON.stringify(header));
    return plaintext;

  }
};
