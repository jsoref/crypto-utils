/*
   Copyright 2005 Red Hat, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
   
   In addition, as a special exception, Red Hat, Inc. gives permission
   to link the code of this program with the OpenSSL library (or with
   modified versions of OpenSSL that use the same license as OpenSSL),
   and distribute linked combinations including the two. You must obey
   the GNU General Public License in all respects for all of the code
   used other than OpenSSL. If you modify this file, you may extend
   this exception to your version of the file, but you are not
   obligated to do so. If you do not wish to do so, delete this
   exception statement from your version.

*/

/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Dr Vipul Gupta <vipul.gupta@sun.com>, Sun Microsystems Laboratories
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

/*
** keyutil.c
**
** utility for managing certificates and the cert database
**
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/time.h>
#include <termios.h>

#include <prerror.h>
#include <secerr.h>

#include <nspr.h>
#include <nss.h>
#include <cert.h>
#include <certt.h>
#include <prio.h>
#include <prlong.h>
#include <prtime.h>
#include <pk11func.h>
#include <pk11pub.h>
#include <pkcs11t.h>
#include <assert.h>
#include <secmod.h>
#include <base64.h>
#include <seccomon.h>
#include <secmodt.h>
#include <secoidt.h>
#include <keythi.h>
#include <keyhi.h>
#include <cryptohi.h>
#include <plarenas.h>
#include <secasn1.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>

#include "keyutil.h"
#include "secutil.h"

#define MIN_KEY_BITS		512
/* MAX_KEY_BITS should agree with MAX_RSA_MODULUS in freebl */
#define MAX_KEY_BITS		8192
#define DEFAULT_KEY_BITS	1024

#define SEC_CT_PRIVATE_KEY		"private-key"
#define SEC_CT_PUBLIC_KEY		"public-key"
#define SEC_CT_CERTIFICATE		"certificate"
#define SEC_CT_CERTIFICATE_REQUEST	"certificate-request"
#define SEC_CT_PKCS7			"pkcs7"
#define SEC_CT_CRL			"crl"

#define NS_CERTREQ_HEADER "-----BEGIN NEW CERTIFICATE REQUEST-----"
#define NS_CERTREQ_TRAILER "-----END NEW CERTIFICATE REQUEST-----"

#define NS_CERT_HEADER "-----BEGIN CERTIFICATE-----"
#define NS_CERT_TRAILER "-----END CERTIFICATE-----"

#define NS_CRL_HEADER  "-----BEGIN CRL-----"
#define NS_CRL_TRAILER "-----END CRL-----"

#define KEY_HEADER  "-----BEGIN PRIVATE KEY-----"
#define KEY_TRAILER "-----END PRIVATE KEY-----"

#define ENCRYPTED_KEY_HEADER  "-----BEGIN ENCRYPTED PRIVATE KEY-----"
#define ENCRYPTED_KEY_TRAILER "-----END ENCRYPTED PRIVATE KEY-----"

#define REP_MECHANISM mechanism[testId/2/2%46]

#define NUM_KEYSTROKES 120
#define RAND_BUF_SIZE 60

#define ERROR_BREAK rv = SECFailure;break;

#define GEN_BREAK(e) rv=e; break;

struct tuple_str {
    PRErrorCode	 errNum;
    const char * errString;
};

typedef struct tuple_str tuple_str;

#define ER2(a,b)   {a, b},
#define ER3(a,b,c) {a, c},

#include "secerr.h"
#include "sslerr.h"


char *progName;

static void 
Usage(char *progName)
{
    fprintf(stderr, "Usage: %s [options] arguments\n", progName);
    fprintf(stderr, "-c command one of [genreq|makecert]");
	fprintf(stderr, "-s subject subject distingusehed name");
	fprintf(stderr, "-g keysize in bits");
	fprintf(stderr, "-v validity in months");
	fprintf(stderr, "-z noise file");
	fprintf(stderr, "-f password file");
	fprintf(stderr, "-d digest algorithm");
	fprintf(stderr, "-i input (key to encrypt)");
	fprintf(stderr, "-k key out, when csr or cert generation");
	fprintf(stderr, "-o output (a csr or cert)");
	fprintf(stderr, "-p passout, the pbe password");
	fprintf(stderr, "\n");
	exit(1);
}

static CERTCertificateRequest *
GetCertRequest(PRFileDesc *inFile, PRBool ascii)
{
    CERTCertificateRequest *certReq = NULL;
    CERTSignedData signedData;
    PRArenaPool *arena = NULL;
    SECItem reqDER;
    SECStatus rv;

    reqDER.data = NULL;
    do {
	    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	    if (arena == NULL) {
	    GEN_BREAK (SECFailure);
	    }
	
 	    rv = SECU_ReadDERFromFile(&reqDER, inFile, ascii);
	    if (rv) {
	    break;
	    }
        certReq = (CERTCertificateRequest*) PORT_ArenaZAlloc
		  (arena, sizeof(CERTCertificateRequest));
        if (!certReq) { 
        GEN_BREAK(SECFailure);
        }
	    certReq->arena = arena;

	    /* Since cert request is a signed data, must decode to get the inner
	       data
	     */
	    PORT_Memset(&signedData, 0, sizeof(signedData));
	    rv = SEC_ASN1DecodeItem(arena, &signedData, 
		SEC_ASN1_GET(CERT_SignedDataTemplate), &reqDER);
	    if (rv) {
	    break;
	    }
	    rv = SEC_ASN1DecodeItem(arena, certReq, 
		        SEC_ASN1_GET(CERT_CertificateRequestTemplate), &signedData.data);
	    if (rv) {
	    break;
	    }
   	    rv = CERT_VerifySignedDataWithPublicKeyInfo(&signedData, 
		&certReq->subjectPublicKeyInfo, NULL /* wincx */);
    } while (0);

    if (reqDER.data) {
   	SECITEM_FreeItem(&reqDER, PR_FALSE);
    }

    if (rv) {
   	    SECU_PrintError(progName, "bad certificate request\n");
   	    if (arena) {
   	    PORT_FreeArena(arena, PR_FALSE);
      	}
   	    certReq = NULL;
    }

    return certReq;
}

static SECStatus
CertReq(SECKEYPrivateKey *privk, SECKEYPublicKey *pubk, KeyType keyType,
        SECOidTag hashAlgTag, CERTName *subject, char *phone, int ascii, 
	    const char *emailAddrs, const char *dnsNames,
        certutilExtnList extnList,
        PRFileDesc *outFile)
{
    CERTSubjectPublicKeyInfo *spki;
    CERTCertificateRequest *cr;
    SECItem *encoding;
    SECOidTag signAlgTag;
    SECItem result;
    SECStatus rv;
    PRArenaPool *arena;
    PRInt32 numBytes;
    void *extHandle;

    /* Create info about public key */
    spki = SECKEY_CreateSubjectPublicKeyInfo(pubk);
    if (!spki) {
	SECU_PrintError(progName, "unable to create subject public key");
	return SECFailure;
    }
    
    /* Generate certificate request */
    cr = CERT_CreateCertificateRequest(subject, spki, NULL);
    if (!cr) {
	SECU_PrintError(progName, "unable to make certificate request");
	return SECFailure;
    }

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if ( !arena ) {
	SECU_PrintError(progName, "out of memory");
	return SECFailure;
    }
    
    extHandle = CERT_StartCertificateRequestAttributes(cr);
    if (extHandle == NULL) {
        PORT_FreeArena (arena, PR_FALSE);
	    return SECFailure;
    }
    if (AddExtensions(extHandle, emailAddrs, dnsNames, extnList)
                  != SECSuccess) {
        PORT_FreeArena (arena, PR_FALSE);
        return SECFailure;
    }
    CERT_FinishExtensions(extHandle);
    CERT_FinishCertificateRequestAttributes(cr);

    /* Der encode the request */
    encoding = SEC_ASN1EncodeItem(arena, NULL, cr,
                                  SEC_ASN1_GET(CERT_CertificateRequestTemplate));
    if (encoding == NULL) {
	SECU_PrintError(progName, "der encoding of request failed");
	return SECFailure;
    }

    /* Sign the request */
    signAlgTag = SEC_GetSignatureAlgorithmOidTag(keyType, hashAlgTag);
    if (signAlgTag == SEC_OID_UNKNOWN) {
	SECU_PrintError(progName, "unknown Key or Hash type");
	return SECFailure;
    }
    rv = SEC_DerSignData(arena, &result, encoding->data, encoding->len, 
			 privk, signAlgTag);
    if (rv) {
	SECU_PrintError(progName, "signing of data failed");
	return SECFailure;
    }

    /* Encode request in specified format */
    if (ascii) {
	char *obuf;
	char *name, *email, *org, *state, *country;
	SECItem *it;
	int total;

	it = &result;

	obuf = BTOA_ConvertItemToAscii(it);
	total = PL_strlen(obuf);

	name = CERT_GetCommonName(subject);
	if (!name) {
	    name = strdup("(not specified)");
	}

	if (!phone)
	    phone = strdup("(not specified)");

	email = CERT_GetCertEmailAddress(subject);
	if (!email)
	    email = strdup("(not specified)");

	org = CERT_GetOrgName(subject);
	if (!org)
	    org = strdup("(not specified)");

	state = CERT_GetStateName(subject);
	if (!state)
	    state = strdup("(not specified)");

	country = CERT_GetCountryName(subject);
	if (!country)
	    country = strdup("(not specified)");

	PR_fprintf(outFile, "%s\n", NS_CERTREQ_HEADER);
	numBytes = PR_Write(outFile, obuf, total);
	if (numBytes != total) {
	    SECU_PrintSystemError(progName, "write error");
	    return SECFailure;
	}
	PR_fprintf(outFile, "\n%s\n", NS_CERTREQ_TRAILER);
    } else {
	numBytes = PR_Write(outFile, result.data, result.len);
	if (numBytes != (int)result.len) {
	    SECU_PrintSystemError(progName, "write error");
	    return SECFailure;
	}
    }
    return SECSuccess;
}

static CERTCertificate *
MakeV1Cert(CERTCertDBHandle *	handle, 
		CERTCertificateRequest *req,
	    char *issuerNickName, 
		PRBool selfsign, 
		unsigned int serialNumber,
		int warpmonths,
        int validityMonths)
{
    CERTCertificate *issuerCert = NULL;
    CERTValidity *validity;
    CERTCertificate *cert = NULL;
    PRExplodedTime printableTime;
    PRTime now, after;

    if ( !selfsign ) {
	    issuerCert = CERT_FindCertByNicknameOrEmailAddr(handle, issuerNickName);
	    if (!issuerCert) {
	        SECU_PrintError(progName, "could not find certificate named \"%s\"",
			    issuerNickName);
	    return NULL;
	    }
    }

    now = PR_Now();
    PR_ExplodeTime (now, PR_GMTParameters, &printableTime);
    if ( warpmonths ) {
	printableTime.tm_month += warpmonths;
	now = PR_ImplodeTime (&printableTime);
	PR_ExplodeTime (now, PR_GMTParameters, &printableTime);
    }
    printableTime.tm_month += validityMonths;
    after = PR_ImplodeTime (&printableTime);

    /* note that the time is now in micro-second unit */
    validity = CERT_CreateValidity (now, after);
    if (validity) {
        cert = CERT_CreateCertificate(serialNumber, 
				      (selfsign ? &req->subject 
				                : &issuerCert->subject), 
	                              validity, req);
    
        CERT_DestroyValidity(validity);
    }
    if ( issuerCert ) {
	CERT_DestroyCertificate (issuerCert);
    }
    
    return(cert);
}

static SECItem *
SignCert(CERTCertDBHandle *handle, CERTCertificate *cert, PRBool selfsign, 
         SECOidTag hashAlgTag,
         SECKEYPrivateKey *privKey, char *issuerNickName, void *pwarg)
{
    SECItem der;
    SECItem *result = NULL;
    SECKEYPrivateKey *caPrivateKey = NULL;    
    SECStatus rv;
    PRArenaPool *arena;
    SECOidTag algID;
    void *dummy;

	if ( !selfsign ) {
        CERTCertificate *issuer = PK11_FindCertFromNickname(issuerNickName, pwarg);
        if ( (CERTCertificate *)NULL == issuer ) {
            SECU_PrintError(progName, "unable to find issuer with nickname %s", 
	                issuerNickName);
            return (SECItem *)NULL;
        }

        privKey = caPrivateKey = PK11_FindKeyByAnyCert(issuer, pwarg);
        CERT_DestroyCertificate(issuer);
        if (caPrivateKey == NULL) {
	        SECU_PrintError(progName, "unable to retrieve key %s", issuerNickName);
	        return NULL;
        }
    }
	
    arena = cert->arena;

    algID = SEC_GetSignatureAlgorithmOidTag(privKey->keyType, hashAlgTag);
    if (algID == SEC_OID_UNKNOWN) {
	fprintf(stderr, "Unknown key or hash type for issuer.");
	goto done;
    }

    rv = SECOID_SetAlgorithmID(arena, &cert->signature, algID, 0);
    if (rv != SECSuccess) {
	fprintf(stderr, "Could not set signature algorithm id.");
	goto done;
    }

    /* we only deal with cert v3 here */
    *(cert->version.data) = 2;
    cert->version.len = 1;

    der.len = 0;
    der.data = NULL;
    dummy = SEC_ASN1EncodeItem (arena, &der, cert,
			 	SEC_ASN1_GET(CERT_CertificateTemplate));
    if (!dummy) {
	fprintf (stderr, "Could not encode certificate.\n");
	goto done;
    }

    result = (SECItem *) PORT_ArenaZAlloc (arena, sizeof (SECItem));
    if (result == NULL) {
	fprintf (stderr, "Could not allocate item for certificate data.\n");
	goto done;
    }

    rv = SEC_DerSignData(arena, result, der.data, der.len, privKey, algID);
    if (rv != SECSuccess) {
	fprintf (stderr, "Could not sign encoded certificate data.\n");
	/* result allocated out of the arena, it will be freed
	 * when the arena is freed */
	result = NULL;
	goto done;
    }
    cert->derCert = *result;
done:
    if (caPrivateKey) {
	SECKEY_DestroyPrivateKey(caPrivateKey);
    }
    return result;
}

static SECStatus
CreateCert(
	CERTCertDBHandle *handle, 
	char             *issuerNickName, 
	PRFileDesc       *inFile,
	PRFileDesc       *outFile, 
	SECKEYPrivateKey *selfsignprivkey,
	void 	         *pwarg,
	SECOidTag        hashAlgTag,
	unsigned int     serialNumber, 
	int              warpmonths,
	int              validityMonths,
	const char       *emailAddrs,
	const char       *dnsNames,
	PRBool           ascii,
	PRBool           selfsign,
	certutilExtnList extnList,
    CERTCertificate  **outCert)
{
    void                   *extHandle;
    SECItem                *certDER;
    PRArenaPool            *arena			= NULL;
    SECItem                reqDER;
    CERTCertExtension      **CRexts;
    CERTCertificate        *subjectCert 	= NULL;
    CERTCertificateRequest *certReq	        = NULL;
    SECStatus               rv 			    = SECSuccess;

    reqDER.data = NULL;
    do {
	    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	    if (!arena) {
	        GEN_BREAK (SECFailure);
	    }
	
	    /* Create a certrequest object from the input cert request der */
	    certReq = GetCertRequest(inFile, ascii);
		if (certReq == NULL) {
		    GEN_BREAK (SECFailure)
		}

    	subjectCert = MakeV1Cert (handle, certReq, issuerNickName, selfsign,
				  serialNumber, warpmonths, validityMonths);
    	if (subjectCert == NULL) {
		    GEN_BREAK (SECFailure)
		}
        
        extHandle = CERT_StartCertExtensions (subjectCert);
	    if (extHandle == NULL) {
	    GEN_BREAK (SECFailure)
	    }
        
        rv = AddExtensions(extHandle, emailAddrs, dnsNames, extnList);
        if (rv != SECSuccess) {
	    GEN_BREAK (SECFailure)
	    }
        
        if (certReq->attributes != NULL &&
            certReq->attributes[0] != NULL &&
	        certReq->attributes[0]->attrType.data != NULL &&
	        certReq->attributes[0]->attrType.len   > 0    &&
            SECOID_FindOIDTag(&certReq->attributes[0]->attrType)
                == SEC_OID_PKCS9_EXTENSION_REQUEST) {
            rv = CERT_GetCertificateRequestExtensions(certReq, &CRexts);
            if (rv != SECSuccess)
                break;
            rv = CERT_MergeExtensions(extHandle, CRexts);
            if (rv != SECSuccess)
                break;
        }

        CERT_FinishExtensions(extHandle);

        certDER = SignCert(handle, subjectCert, selfsign, hashAlgTag,
	                   selfsignprivkey, issuerNickName,pwarg);

        if (certDER) {
            if (ascii) {
                PR_fprintf(outFile, "%s\n%s\n%s\n", NS_CERT_HEADER, 
                    BTOA_DataToAscii(certDER->data, certDER->len), 
			        NS_CERT_TRAILER);
            } else {
                PR_Write(outFile, certDER->data, certDER->len);
           }
        }

    } while (0);
    
    CERT_DestroyCertificateRequest(certReq);
    PORT_FreeArena (arena, PR_FALSE);
    if (rv == SECSuccess) {
    	PR_fprintf(PR_STDOUT, "%s Copying the cert pointer\n", progName);
        *outCert = subjectCert;
    } else {
    	PRErrorCode  perr = PR_GetError();
        fprintf(stderr, "%s: unable to create cert, (%s)\n", 
        		progName, SECU_Strerror(perr));
        if (subjectCert) 
            CERT_DestroyCertificate (subjectCert);
    }
    
    return (rv);
}

//static certutilExtnList certutil_extns;

//struct KeyPairStr { SECKEYPrivateKey *refPrivk; SECKEYPublicKey *pubkey; };

typedef struct KeyPairStr KeyPair;

typedef struct _PrivateKeyStr PrivateKey;


/*  Keyutil commands  */
typedef enum _CommandType {
    cmd_CertReq,
    cmd_CreateNewCert,
	cmd_ImportKey
} CommandType;


PRBool GetKeyPassword(const char *pwFile, SECItem *pwitem)
{
    int i;
    unsigned char phrase[200];
    PRFileDesc *fd;
    PRInt32 nb;

    if (!pwFile) 
    	return PR_FALSE;
    
    fd = PR_Open(pwFile, PR_RDONLY, 0);
    if (!fd) 
    	return PR_FALSE;

    nb = PR_Read(fd, phrase, sizeof(phrase));
    PR_Close(fd);
    
    /* handle the Windows EOL case */
    i = 0;
    while (phrase[i] != '\r' && phrase[i] != '\n' && i < nb)
    	i++;
    phrase[i] = '\0';
    if (nb == 0)
        return PR_FALSE;

	pwitem->data = (unsigned char *) PORT_Strdup((char*)phrase);
	pwitem->len = (unsigned int) strlen((char*)phrase);
	pwitem->type = siBuffer;
	
    return PR_TRUE;
}

/* returns 0 for success, -1 for failure (EOF encountered) */
static int
UpdateRNG(void)
{
    char           randbuf[RAND_BUF_SIZE];
    int            fd,  count;
    int            c;
    int            rv		= 0;
    cc_t           orig_cc_min;
    cc_t           orig_cc_time;
    tcflag_t       orig_lflag;
    struct termios tio;
    char meter[] = { 
      "\r|                                                            |" };

#define FPS fprintf(stderr, 
    FPS "\n");
    FPS "A random seed must be generated that will be used in the\n");
    FPS "creation of your key.  One of the easiest ways to create a\n");
    FPS "random seed is to use the timing of keystrokes on a keyboard.\n");
    FPS "\n");
    FPS "To begin, type keys on the keyboard until this progress meter\n");
    FPS "is full.  DO NOT USE THE AUTOREPEAT FUNCTION ON YOUR KEYBOARD!\n");
    FPS "\n");
    FPS "\n");
    FPS "Continue typing until the progress meter is full:\n\n");
    FPS meter);
    FPS "\r|");

    /* turn off echo on stdin & return on 1 char instead of NL */
    fd = fileno(stdin);

    tcgetattr(fd, &tio);
    orig_lflag = tio.c_lflag;
    orig_cc_min = tio.c_cc[VMIN];
    orig_cc_time = tio.c_cc[VTIME];
    tio.c_lflag &= ~ECHO;
    tio.c_lflag &= ~ICANON;
    tio.c_cc[VMIN] = 1;
    tio.c_cc[VTIME] = 0;
    tcsetattr(fd, TCSAFLUSH, &tio);

    /* Get random noise from keyboard strokes */
    count = 0;
    while (count < sizeof randbuf) {
	c = getc(stdin);
	if (c == EOF) {
	    rv = -1;
	    break;
	}
	randbuf[count] = c;
	if (count == 0 || c != randbuf[count-1]) {
	    count++;
	    FPS "*");
	}
    }
    PK11_RandomUpdate(randbuf, sizeof randbuf);
    memset(randbuf, 0, sizeof randbuf);

    FPS "\n\n");
    FPS "Finished.  Press enter to continue: ");

    while ((c = getc(stdin)) != '\n' && c != EOF)
	    ;
    if (c == EOF) 
	rv = -1;
    FPS "\n");

#undef FPS

#if defined(XP_UNIX) && !defined(VMS)
    /* set back termio the way it was */
    tio.c_lflag = orig_lflag;
    tio.c_cc[VMIN] = orig_cc_min;
    tio.c_cc[VTIME] = orig_cc_time;
    tcsetattr(fd, TCSAFLUSH, &tio);
#endif
    return rv;
}

static SECStatus 
CERTUTIL_FileForRNG(const char *noise)
{
    char buf[2048];
    PRFileDesc *fd;
    PRInt32 count;

    fd = PR_Open(noise,PR_RDONLY,0);
    if (!fd) {
	fprintf(stderr, "%s: failed to open noise file %s\n", progName, noise);
	return SECFailure;
    }

    do {
	count = PR_Read(fd,buf,sizeof(buf));
	if (count > 0) {
	    PK11_RandomUpdate(buf,count);
	}
    } while (count > 0);

    PR_Close(fd);
    return SECSuccess;
}

SECKEYPrivateKey *
GenerateRSAPrivateKey(KeyType keytype, 
	PK11SlotInfo *slot,
    int rsasize,
    int publicExponent,
	char *noise, 
    SECKEYPublicKey **pubkeyp,
    secuPWData *pwdata)
{
    CK_MECHANISM_TYPE  mechanism;
    PK11RSAGenParams   rsaparams;
    SECKEYPrivateKey * privKey = NULL;

    if (slot == NULL) 
    	return NULL;

    if (PK11_Authenticate(slot, PR_TRUE, pwdata) != SECSuccess)
    	return NULL;

    /*
     * Do some random-number initialization.
     */

    if (noise) {
    	SECStatus rv = CERTUTIL_FileForRNG(noise);
    	if (rv != SECSuccess) {
    		PORT_SetError(PR_END_OF_FILE_ERROR); /* XXX */
    		return NULL;
    	}
    } else {
    	int rv = UpdateRNG();
    	if (rv) {
    		PORT_SetError(PR_END_OF_FILE_ERROR);
    		return NULL;
    	}
    }

    rsaparams.keySizeInBits = rsasize;
    rsaparams.pe = publicExponent;
    mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;

    fprintf(stderr, "\n\n");
    fprintf(stderr, "Generating key. This may take a few moments...\n\n");

    privKey = PK11_GenerateKeyPair(slot,
    		mechanism, &rsaparams, pubkeyp,
            PR_FALSE /* isPerm */, 
            PR_TRUE  /* isSensitive*/, 
            pwdata   /* wincx */
            );
    
    assert(privKey);
    assert(pubkeyp);
    return privKey;
}

static SECStatus
ValidateCert(CERTCertDBHandle *handle, CERTCertificate  *cert, char *name, char *date,
	    char *certUsage, PRBool checkSig, PRBool logit, secuPWData *pwdata)
{
    SECStatus rv;
    int64 timeBoundary;
    SECCertificateUsage usage;
    CERTVerifyLog reallog;
    CERTVerifyLog *log = NULL;

    if (!certUsage) {
	    PORT_SetError (SEC_ERROR_INVALID_ARGS);
	    return (SECFailure);
    }
    
    switch (*certUsage) {
	case 'O':
	    usage = certificateUsageStatusResponder;
	    break;
	case 'C':
	    usage = certificateUsageSSLClient;
	    break;
	case 'V':
	    usage = certificateUsageSSLServer;
	    break;
	case 'S':
	    usage = certificateUsageEmailSigner;
	    break;
	case 'R':
	    usage = certificateUsageEmailRecipient;
	    break;
	case 'J':
	    usage = certificateUsageObjectSigner;
	    break;
	default:
	    PORT_SetError (SEC_ERROR_INVALID_ARGS);
	    return (SECFailure);
    }
    do {
		if (date != NULL) {
		    rv = DER_AsciiToTime(&timeBoundary, date);
		    if (rv) {
			    SECU_PrintError(progName, "invalid input date");
			    GEN_BREAK (SECFailure)
		    }
		} else {
		    timeBoundary = PR_Now();
		}

		if ( logit ) {
		    log = &reallog;
		    
		    log->count = 0;
		    log->head = NULL;
		    log->tail = NULL;
		    log->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
		    if ( log->arena == NULL ) {
		    	SECU_PrintError(progName, "out of memory");
		    	GEN_BREAK (SECFailure)
		    }
		}
		fprintf(stdout, "%s: CERT_VerifyCertificate called\n", progName);
		rv = CERT_VerifyCertificate(handle, cert, checkSig, usage,
			     timeBoundary, pwdata, log, &usage);
		fprintf(stdout, "%s: CERT_VerifyCertificate returned %d\n", progName, rv);
		
		if ( log ) {
		    if ( log->head == NULL ) {
			    fprintf(stdout, "%s: certificate is valid\n", progName);
			    GEN_BREAK (SECSuccess)
		    } else {
			char *name;
			CERTVerifyLogNode *node;
			
			node = log->head;
			while ( node ) {
			    if (node->cert->nickname != NULL) {
				    name = node->cert->nickname;
			    } else {
				    name = node->cert->subjectName;
			    }
			    fprintf(stderr, "%s : %ld\n", name, node->error);
			    CERT_DestroyCertificate(node->cert);
			    node = node->next;
			}
		    }
		} else {
	        if (rv != SECSuccess) {
	    	    PRErrorCode perr = PORT_GetError();
			    fprintf(stdout, "%s: certificate is invalid: %s\n",
				    progName, SECU_Strerror(perr));
				GEN_BREAK (SECFailure)
	    	}
	    	fprintf(stdout, "%s: certificate is valid\n", progName);
	    	GEN_BREAK (SECSuccess)
		}
		
    } while (0);

    if (cert) {
        CERT_DestroyCertificate(cert);
    }

    return (rv);
}

/* Import a private key to the internal slot temorarily.
 * This function if for testing only.
 */
static SECStatus
ImportKey(CERTCertDBHandle *certHandle,
		  const char *passwordfile,
		  const char *keyfile, PRBool ascii)
{
	SECStatus rv = SECSuccess;
	PRFileDesc *inFile = NULL;
	SECItem nickname = { siBuffer, (unsigned char *) "nick", 4 };
	SECItem der = { 0, NULL, 0 };
	unsigned char myData[20];
	SECItem dummy;
	PK11SlotInfo *slot = NULL;

	SECKEYEncryptedPrivateKeyInfo epki;
	PRArenaPool *arena = NULL;
	SECItem pwitem = { 0, NULL, 0 };
	secuPWData pwdata = { 0, NULL };
	
	do {
		if (passwordfile) {
			if (!GetKeyPassword(passwordfile, &pwitem))
				return 255;
		} else {
			PR_fprintf(PR_STDERR, 
				"%s export/import of clear keys not impemented yet\n",
				progName);
		}
		
		inFile = PR_Open(keyfile, PR_RDONLY, 0);
		if (!inFile) GEN_BREAK(SEC_ERROR_IO);
		
	    rv = SECU_ReadDERFromFile(&der, inFile, ascii);
	    if (rv != SECSuccess) break;

		arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
		if (!arena) GEN_BREAK(SEC_ERROR_NO_MEMORY);
		epki.arena = arena;

		rv = SEC_QuickDERDecodeItem(arena, &epki,
				SECKEY_EncryptedPrivateKeyInfoTemplate, &der);
		if (rv) {
			SECU_PrintError(progName, 
			"unable to SEC_QuickDERDecodeItem the private key");
			break; 
		}
	    
		/* whatever garbage bytes are the stack are okay */
	    dummy.data = myData;
	    dummy.len = sizeof(myData);
	    
	    slot = PK11_GetInternalSlot();
		rv = PK11_ImportEncryptedPrivateKeyInfo(slot, 
				&epki, &pwitem, &nickname, &dummy, 
				PR_FALSE, PR_TRUE, /* not permanent, private */
				rsaKey, 0,         /* signing */
				&pwdata
	           );
		if (rv) {
			SECU_PrintError(progName, 
			"Unable to Import Encrypted PrivateKey into database");
		}
		
	} while (0);

	printf("Imported encrypted private key into the database\n");

	if (arena)
	    PORT_FreeArena(arena, PR_TRUE);
    if (inFile)
        PR_Close(inFile);
    
	return rv;
}

/* Output the private key to a file */
static SECStatus
KeyOut(const char *keyoutfile,
	   const char *passwordfile,
       SECKEYPrivateKey *privkey,
       SECKEYPublicKey *pubkey,
       SECOidTag algTag,
       secuPWData *pwdata,
       PRBool ascii)
{
	PRFileDesc *keyOutFile = NULL;
	PRUint32 total = 0, numBytes = 0;
	SECItem *derEPKI = NULL;
	char *b64 = NULL;
	SECItem pwitem = { 0, NULL, 0 };
	PRArenaPool *arena = NULL;
	SECKEYEncryptedPrivateKeyInfo *epki = NULL;
	int rv = SECSuccess;

	do {
        
		if (passwordfile) {
			if (!GetKeyPassword(passwordfile, &pwitem))
				return 255;
		} else {
			PR_fprintf(PR_STDERR, 
					"%s export of clear keys not impemented yet\n",
					progName);
		}
    	keyOutFile = PR_Open(keyoutfile, PR_RDWR | PR_CREATE_FILE | PR_TRUNCATE, 00660);
    	if (!keyOutFile) {
    	    PR_fprintf(PR_STDERR,
                       "%s -o: unable to open \"%s\" for writing\n",
    		           progName, keyoutfile);
    	    GEN_BREAK(255);
    	}

	    epki = PK11_ExportEncryptedPrivKeyInfo(NULL,
	    		algTag, &pwitem, privkey, 1000, pwdata);
		if (!epki) {
			rv = PORT_GetError();
			SECU_PrintError(progName, 
					"Can't export private key info (%d)\n", rv);
			GEN_BREAK(rv);
		}
		
		arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
		assert(arena);

        /* NULL dest to let it allocate memory for us */
		derEPKI = SEC_ASN1EncodeItem(arena, NULL, epki,
		            SECKEY_EncryptedPrivateKeyInfoTemplate);
		
        if (derEPKI == NULL) {
        	PR_fprintf(PR_STDERR, "%s ASN1 Encode failed (%dl)\n",
        		    progName, PR_GetError());
        	GEN_BREAK(255);
        }
	    
	    assert(derEPKI);      
	    assert(derEPKI->len);
		assert(derEPKI->data);
    	   
		if (!passwordfile) {
			/* Make a decrypted key the one to write out. 
			 * Can't use SECKEYPrivateKeyInfo *
			 * *PK11_ExportPrivateKeyInfo(
		     * CERTCertificate *cert, void *wincx);
		     * as it always returns NULL.
			 * We exported the key encrypted, decrypt it
			 * and write that one out.
			 */
		}
 
        if (ascii) {
        	char *header = passwordfile 
                ? ENCRYPTED_KEY_HEADER : KEY_HEADER;
        	char *trailer = passwordfile 
                ? ENCRYPTED_KEY_TRAILER : KEY_TRAILER;
        	
    		b64 = BTOA_ConvertItemToAscii(derEPKI);
    	    assert(b64);
    	    total = PL_strlen(b64);
       	
            PR_fprintf(keyOutFile, "%s\n", header);
            
        	numBytes = PR_Write(keyOutFile, b64, total);
        	assert(numBytes == total);
        	
        	PR_fprintf(keyOutFile, "\n%s\n", trailer);
        } else {
            numBytes = PR_Write(keyOutFile, derEPKI, derEPKI->len);
            assert(numBytes == derEPKI->len);
        }
    	
		printf("Wrote %d bytes of encoded data to %s \n", 
				numBytes, keyoutfile);
		/* can we read it and reverse operations */
		
    } while (0);
	
    if (keyOutFile) {
        PR_Close(keyOutFile);
    }
 
  	if (arena) {
   	    PORT_FreeArena(arena, PR_FALSE);
    }
	
	return rv;
}

/* Generate a certificate signing request
 * or a self_signed certificate.
 */
static int keyutil_main(
		CERTCertDBHandle *certHandle,
		const char       *noisefile, 
        const char       *passwordfile, 
        const char       *subjectstr,
        int              keysize, 
    	int              warpmonths,
    	int              validityMonths,
    	PRBool           ascii,
        const char       *certreqfile,
        const char       *certfile,
        const char       *keyoutfile)
{
	static certutilExtnList nullextnlist = {PR_FALSE};
	
	CERTCertificate *cert       = NULL;
	PRFileDesc *outFile         = NULL;
	PRFileDesc *keyOutFile      = NULL;
    CERTName   *subject         = NULL;
	SECKEYPrivateKey *privkey   = NULL;
	SECKEYPublicKey *pubkey     = NULL;
                               /* PK11_GetInternalSlot() ? */
	PK11SlotInfo *slot          = PK11_GetInternalKeySlot();
    secuPWData  pwdata          = { PW_NONE, 0 };
    KeyType     keytype         = rsaKey;
    SECOidTag   hashAlgTag      = SEC_OID_UNKNOWN;
    PRBool      doCert          = certfile != NULL;
	int         rv;

    outFile = PR_Open(certreqfile, PR_RDWR | PR_CREATE_FILE | PR_TRUNCATE, 00660);
	if (!outFile) {
	    PR_fprintf(PR_STDERR, 
		       "%s -o: unable to open \"%s\" for writing (%ld, %ld)\n",
		       progName, certreqfile,
		       PR_GetError(), PR_GetOSError());
	    return 255;
	}
    printf("Opened %s for writing\n", certreqfile);
	if (passwordfile) {
	    pwdata.source = PW_FROMFILE;
	    pwdata.data = (char *)passwordfile;
    } else {
        pwdata.source = PW_PLAINTEXT;
        pwdata.data = (char *)"badpassword";
    }

	privkey = GenerateRSAPrivateKey(keytype, slot, 
			keysize, 65537L, (char *)noisefile, &pubkey, &pwdata);
	
	if (!privkey) {
	    PR_fprintf(PR_STDERR,
	    		"%s Keypair generation failed: \"%d\"\n", 
	    		progName, PORT_GetError());
	    rv = 255;
		goto shutdown;
	}
	PR_fprintf(PR_STDOUT, "%s Got a key\n", progName);
    /*
     *  Certificate request
     */
	subject = CERT_AsciiToName((char *)subjectstr);
	if (!subject) {
	    PR_fprintf(PR_STDERR, "%s -s: improperly formatted name: \"%s\"\n",
	               progName, subjectstr);
	    rv = 255;
	    goto shutdown;
	}
	
	hashAlgTag = SEC_OID_MD5;
	
    /*  Make a cert request */
	rv = CertReq(privkey, pubkey, rsaKey, hashAlgTag, subject,
		         NULL,         /* PhoneNumber */
		         ascii,        /* ASCIIForIO */
		         NULL,         /* ExtendedEmailAddrs */
		         NULL,         /* ExtendedDNSNames */
		         nullextnlist, /* certutil_extns */
		         outFile);	     
    
	PR_Close(outFile);
	if (rv) {
	    PR_fprintf(PR_STDERR, "%s CertReq failed: \"%d\"\n", 
	    		progName, PORT_GetError());
	    rv = 255;
		goto shutdown;
	}

	PR_fprintf(PR_STDOUT, "%s Made a cert request\n", progName);
	if (doCert) {
	
	    /* If making a cert, we already have a cert request file.
	     * without any extensions, load it with any command line extensions
	     * and output the cert to other file. Delete the request file.
	     */   	
	    PRFileDesc *inFile = NULL;
	    unsigned int serialNumber;
	   
	    /*  Make a default serial number from the current time.  */
	    PRTime now = PR_Now();
	    LL_USHR(now, now, 19);
	    LL_L2UI(serialNumber, now);
		
	    privkey->wincx = &pwdata;
	    PR_Close(outFile);
	   
	    inFile  = PR_Open(certreqfile, PR_RDONLY, 0);
	    assert(inFile);
	    if (!inFile) {
		    PR_fprintf(PR_STDERR, "Failed to open file \"%s\" (%ld, %ld) for reading.\n",
	              certreqfile, PR_GetError(), PR_GetOSError());
		    rv = SECFailure;
		    goto shutdown;
	    }
	   
	    outFile = PR_Open(certfile, PR_RDWR | PR_CREATE_FILE | PR_TRUNCATE, 00660);
	   
	    if (!outFile) {
		    PR_fprintf(PR_STDERR, "Failed to open file \"%s\" (%ld, %ld).\n",
	                   certfile, PR_GetError(), PR_GetOSError());
		    rv = SECFailure;
		    goto	shutdown;
	    }
	
	    /*  Create a certificate (-C or -S).  */
	
	    /* issuerName == subject */
	    rv = CreateCert(certHandle, 
	        "tempnickname", inFile, outFile,
			privkey, &pwdata, hashAlgTag,
	        serialNumber, warpmonths, validityMonths,
	        NULL, NULL, ascii, PR_TRUE, NULL,
	        &cert);
	     /*
	      ExtendedEmailAddrs,ExtendedDNSNames,
	      ASCIIForIO,SelfSign,certutil_extns, thecert
	     */
	     if (rv) {
		     PR_fprintf(PR_STDERR, "Failed to create certificate \"%s\" (%ld).\n",
				   outFile, PR_GetError());
		     rv = SECFailure;
		     goto shutdown; 
	     }
	     PR_fprintf(PR_STDOUT, "%s Created a cert\n", progName);
	
	     /*  Sanity check: Check cert validity against current time. */
	
	     /* XXX temporary hack for fips - must log in to get priv key */
	    if (slot && PK11_NeedLogin(slot)) {
	        SECStatus newrv = PK11_Authenticate(slot, PR_TRUE, &pwdata);
	        if (newrv != SECSuccess) {
	            SECU_PrintError(progName, "could not authenticate to token %s.",
	                        PK11_GetTokenName(slot));
	            goto shutdown;
	        }
	    }
	    
	    /* Not sure we can validate yet */
	    if (PR_FALSE) {
	        rv = ValidateCert(certHandle, 
	        	cert,
	        	"tempnickname", 
	    		NULL,    // ValidityTime, --> PR_Now
	    		NULL,     // Usage.arg,    --> certificateUsageSSLServer
	    		PR_TRUE, // VerifySig,
	    		PR_TRUE, // DetailedInfo,
	            &pwdata);
	        if (rv != SECSuccess && PR_GetError() == SEC_ERROR_INVALID_ARGS) {
	        	SECU_PrintError(progName, "validation failed");
	            goto shutdown;
	        }    	
	    }
	}    

    /* If the caller wants the private key extract it and save it to a file. */
	if (keyoutfile) {
    	/* Two candidate tags to use: SEC_OID_DES_EDE3_CBC and
    	 * SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC
    	 */
	    rv = KeyOut(keyoutfile,
                passwordfile,
                privkey, pubkey,
	    		SEC_OID_DES_EDE3_CBC, 
	    		&pwdata, ascii);
	    if (rv != SECSuccess) {
	    	SECU_PrintError(progName, "Failed to write the key");
	    } else {
	    	printf("%s Wrote the key to\n%s\n", progName, keyoutfile);	
	    }
	}

shutdown:
    if (cert) {
    	CERT_DestroyCertificate(cert);
    }
    if (keyOutFile) {
        PR_Close(keyOutFile);
    }
	if (slot) {
	    PK11_FreeSlot(slot);
	}
    if (privkey) {
    	SECKEY_DestroyPrivateKey(privkey);
    }
    if (pubkey) {
    	SECKEY_DestroyPublicKey(pubkey);
    }

    if (rv == SECSuccess) {
	return 0;
    } else {
	return 255;
    }
}

/* $Id: keyutil.c,v 1.10 2008/03/23 10:09:40 emaldona Exp $ */

/* Key generation, encryption, and certificate utility code, based on
 * code from NSS's security utilities and the certutil application.  
 * Elio Maldonado <emaldona@redhat.com> 
 */


int main(int argc, char **argv)
{
    int optc, rv = 0;
    static const struct option options[] = {
    	{ "command",    required_argument, NULL, 'c'},
    	{ "subject",    required_argument, NULL, 's'},
    	{ "gkeysize",   required_argument, NULL, 'g'},
    	{ "validity",   required_argument, NULL, 'v'},
        { "filepwd",    required_argument, NULL, 'f' },
        { "digest",     required_argument, NULL, 'd' },
        { "znoisefile", required_argument, NULL, 'z' },
        { "input",      required_argument, NULL, 'i' }, /* key in */
        { "passout",    required_argument, NULL, 'p' },
        { "output",     required_argument, NULL, 'o' }, /* reg, cert, enckey */
        { "keyout",     required_argument, NULL, 'k' }, /* plaintext key */
        { "ascii",      no_argument,       NULL, 'a' }, /* ascii */
        { NULL }
    };
    char *cmdstr = NULL;
    char *noisefile = NULL;
    int  keysize = 1024;
	int  warpmonths = 0;
	int  validity_months = 24;
    char *keyfile = NULL;
    char *outfile = NULL;
    char *subject = NULL;
    char *passwordfile = NULL;
    char *digestAlgorithm = "md5";
    char *keyoutfile = 0;
    PRBool ascii = PR_FALSE;
    CERTCertDBHandle *certHandle = 0;
    SECStatus status = 0;
    CommandType cmd = cmd_CertReq;
    PRBool initialized = PR_FALSE;
    
    progName = argv[0];
    
    while ((optc = getopt_long(argc, argv, "ac:s:g:v:f:d:z:i:p:o:k:", options, NULL)) != -1) {
        switch (optc) {
        case 'a':
        	ascii = PR_TRUE;
        	break;
        case 'c':
            cmdstr = strdup(optarg);
            printf("cmdstr: %s\n", cmdstr);
        	if (strcmp(cmdstr, "importkey") == 0) {
                cmd = cmd_ImportKey;
                printf("\ncmd_ImportKey\n");        		
        	} else if (strcmp(cmdstr, "genreq") == 0) {
                cmd = cmd_CertReq;
                printf("\ncmd_CertReq\n");
            } else if (strcmp(cmdstr, "makecert") == 0) {
                cmd = cmd_CreateNewCert;
                printf("\ncmd_CreateNewCert\n");          
            } else {
                printf("\nInvalid argument: %s\n", cmdstr);
                exit(2);
            }
            printf("command:  %s\n", cmdstr);
            break;
        case 's':
            subject = strdup(optarg);
            printf("subject = %s\n", subject);
            break;
        case 'g':
        	keysize = atoi(optarg);
        	printf("keysize = %d bits\n", keysize);
            break;
        case 'v':
        	validity_months = atoi(optarg);
        	printf("valid for %d months\n", validity_months);
        	break;
        case 'f':
        	passwordfile = strdup(optarg);
        	printf("password from = %s\n", passwordfile);
        	break;
        case 'd':
            digestAlgorithm = strdup(optarg);
            printf("message digest %s\n", digestAlgorithm);
            break;
        case 'z':
        	noisefile = strdup(optarg);
        	printf("random seed from %s\n", noisefile);
            break;
        case 'i':
        	keyfile = strdup(optarg);
        	printf("will process a key from %s\n", keyfile);
            break;
        case 'o':
        	/* could be req or cert */
        	outfile = strdup(optarg);
        	printf("output will be written to %s\n", outfile);
            break;
        case 'k':
        	/* private key out in plaintext - side effect of req and cert */
        	keyoutfile = strdup(optarg);
        	printf("output key written to %s\n", keyoutfile);
        	break;
        default:
        	printf("Bad arguments\n");
            Usage(progName);
            break;
        }
    }
      
    /*  Initialize NSPR and NSS.  */
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);
   
    status = NSS_NoDB_Init(NULL);
    if (status  != SECSuccess ) {
    	printf("NSS initialization failed\n");
        return EXIT_FAILURE;
    }
    initialized = PR_TRUE;
    
    certHandle = CERT_GetDefaultCertDB();
    assert(certHandle);
    
    switch (cmd) {
    case cmd_CertReq:
    	/* FIXME Remove when done debugging */
    	printf("\ncmd_CertReq\n");
        /* certfile NULL signals only the request is needed */
        rv = keyutil_main(certHandle,
                noisefile, passwordfile, subject,
                keysize, warpmonths, validity_months,
                ascii, outfile, NULL, keyoutfile);
        break;
    case cmd_CreateNewCert:
    	printf("\ncmd_CreateNewCert\n");
	    rv = keyutil_main(certHandle,
                noisefile, passwordfile, subject,
                keysize, warpmonths, validity_months,
                ascii, "tmprequest", outfile, keyoutfile);
        break;
    case cmd_ImportKey:
    	rv = ImportKey(certHandle, passwordfile, keyfile, PR_TRUE);
    	break;
    default:
    	printf("\nEntered an inconsistent state, bailing out\n");
    	rv = -1;
    	break;
    }

    if ((initialized == PR_TRUE) && NSS_Shutdown() != SECSuccess) {
        exit(1);
    }
    PR_Cleanup();

    return rv;
}
