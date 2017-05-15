/**
  Copyright (C) 2017 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#include <windows.h>
#include <shlwapi.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

#define WC_RANSOM_KEY      "rw_public.bin" // public key blob belonging to authors

#define WC_PUBLIC_KEY      "00000000.pky"  // public key to encrypt AES keys
#define WC_PRIVATE_KEY     "00000000.dky"  // private key to decrypt AES keys
#define WC_ENCRYPTED_KEY   "00000000.eky"  // encrypted private key sent to remote server 

#define WC_BUF_SIZE        1048576         // writes/reads data in 1MB chunks

#define WC_ARCHIVE_EXT     ".WNCRY"        // encrypted archive extension
#define WC_SIGNATURE       "WANACRY!"      // signature for encrypted archives
#define WC_SIG_LEN         8               // 64-bit length
#define WC_ENCKEY_LEN    256               // 2048-bit
#define WC_RSA_KEY_LEN  2048               // 2048-bit
#define WC_AES_KEY_LEN    16               // 128-bit
#define WC_DATA_OFFSET  WC_SIG_LEN + WC_ENCKEY_LEN + 4 + 4 

#define WC_DECRYPT 0
#define WC_ENCRYPT 1

// structure of wanacrypt archive
typedef struct _wc_file_t {
    char     sig[WC_SIG_LEN];    // 64-bit signature
    uint32_t keylen;             // length of encrypted key
    uint8_t  key[WC_ENCKEY_LEN]; // AES key encrypted with RSA
    uint32_t unknown;            // usually 4, unsure what exactly for
    uint64_t datalen;            // length of file before encryption
    uint8_t  data;               // AES-128 ciphertext 
} wc_file_t;

// structure needed to import plaintext key into CAPI object
typedef struct _key_hdr_t {
    PUBLICKEYSTRUC hdr;                 // info about key
    DWORD          len;                 // key length in bytes
    BYTE           key[WC_AES_KEY_LEN]; // for AES-128
} key_hdr;

// structure to hold capi key object + encrypted AES key
typedef struct _wc_aes_key_t {
  HCRYPTKEY key;                  // call CryptDestroyKey after
  BYTE      enc[WC_ENCKEY_LEN];   // 
} aes_key_t;
    
void xstrerror (char *fmt, ...) 
{  
    char    *error=NULL;
    va_list arglist;
    char    buffer[2048];
    DWORD   dwError=GetLastError();
    
    va_start (arglist, fmt);
    wvnsprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
    va_end (arglist);
    
    if (FormatMessage (
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
        (LPSTR)&error, 0, NULL))
    {
      printf ("\n  [ %s : %s", buffer, error);
      LocalFree (error);
    } else {
      printf ("\n  [ %s : %ld", buffer, dwError);
    } 
}

void bin2hex(char *s, void *in, int len) {

  DWORD outlen=0;
  LPTSTR out;
  
  printf ("\n  [ %s\n\n", s);
  
  if (CryptBinaryToString(
      in, len, CRYPT_STRING_HEXASCIIADDR | CRYPT_STRING_NOCR,
      NULL, &outlen))
  {
    out = malloc(outlen);
    if (out!=NULL)
    {
      if (CryptBinaryToString(
          in, len, CRYPT_STRING_HEXASCIIADDR | CRYPT_STRING_NOCR,
          out, &outlen))
      {
        printf ("%s", out);
      }
      free(out);
    }      
  } 
}

// is file wana crypt archive
int valid_archive (const char *file, int info)
{
    uint8_t  key[WC_ENCKEY_LEN], sig[WC_SIG_LEN];
    uint32_t len, keylen, unk;
    uint64_t datalen;
    int      ok=0;
    void     *data;
    
    // open archive
    FILE *in = fopen(file, "rb");
    if(in==NULL) return ok;
    
    // read the signature
    len=fread(sig, 1, WC_SIG_LEN, in);
    
    // valid signature?
    if (len==WC_SIG_LEN && (memcmp(sig, WC_SIGNATURE, WC_SIG_LEN)==0)) 
    {
      // read encrypted key length
      len=fread((char*)&keylen, 1, sizeof(keylen), in);
      // valid key length?
      if (len==sizeof(keylen) && keylen == WC_ENCKEY_LEN)
      {
        // read encrypted key
        len=fread(key, 1, WC_ENCKEY_LEN, in);
        
        if (len==keylen) {
          // read unknown value
          len=fread(&unk, 1, sizeof(unk), in);
          
          if (len==sizeof(unk) && (unk==3 || unk==4)) 
          {
            // read length of original data
            len=fread(&datalen, 1, sizeof(datalen), in);
            
            ok=(len==sizeof(datalen));
              
            if (ok && info) {              
              // display info
              bin2hex("signature",           sig, WC_SIG_LEN);
              bin2hex("encrypted key",       key, WC_ENCKEY_LEN);
              bin2hex("unknown",             &unk, sizeof(unk));
              bin2hex("original file length",&datalen, sizeof(datalen));
              
              data = malloc(datalen+32);
              if (data != NULL)
              {
                len = fread(data, 1, datalen+16, in);
                bin2hex("ciphertext", data, len);
                free(data);
              }                
            }
          }
        }
      }
    }
    fclose(in);
    
    return ok;
}

// import public or private key
HCRYPTKEY import_rsa_key (HCRYPTPROV prov, const char *file) 
{
    HCRYPTKEY key=0;
    BYTE      buf[2048];
    DWORD     len;
    FILE      *fd;
    
    printf ("\n  [ opening key file", file);
    
    fd = fopen(file, "rb");
    
    if (fd != NULL) {
      printf ("\n  [ reading");
      len = fread(buf, 1, 2048, fd);
      
      if (!CryptImportKey(prov, buf, len, 0, CRYPT_EXPORTABLE, &key)) {
        xstrerror ("CryptImportKey");
      }
      fclose(fd);
    }
    return key;
}

// export RSA key blob (encrypted if required)
void export_rsa_key(HCRYPTPROV prov, HCRYPTKEY rsa_key, 
  const char *file, DWORD type, BOOL bEncrypt)
{
    HCRYPTKEY rw_key=0;
    FILE      *out;
    BYTE      buf[2048], tmp[1024];
    PBYTE     p;
    DWORD     len, r;
    
    // are we encrypting?
    if (bEncrypt) {
      // import the ransomware public key
      rw_key = import_rsa_key(prov, WC_RANSOM_KEY);
      
      if (rw_key == 0) {
        printf ("\n  [ unable to import ransomware public key");
        return;
      }
    }
    
    out = fopen(file, "wb");
    
    if (out != NULL) {
      
      // export the key to buffer
      len = sizeof(buf);
      if (CryptExportKey(rsa_key, 0, type, 0, buf, &len))
      {
        // encrypt the key before writing to disk?
        if (bEncrypt) {
          printf ("\n  [ encrypting %i bytes of private key", len);
          
          p = buf;
          
          while (len) {
            // the authors choose to finalize each block 
            // so the input must take into account any padding
            r = (len < 245) ? len : 245;
            
            // copy block
            memcpy (tmp, p, r);
            
            // update length + key buffer position
            len -= r;
            p   += r;
            
            // encrypt it
            if (!CryptEncrypt(rw_key, 0, TRUE, 0, 
                tmp, &r, sizeof(tmp))) 
            {
              xstrerror("CryptEncrypt"); 
              break;              
            }
            // save RSA ciphertext
            fwrite(tmp, 1, r, out);
          }
        } else {
          // write to file
          fwrite(buf, 1, len, out);
        }
      } else {
        xstrerror("CryptExportKey");
      }
      fclose(out);
    }
      
    // release public key
    if (rw_key != 0) {
      CryptDestroyKey(rw_key);
    }
}

// generate rsa key pair and export
void gen_rsa_key (void) {
    HCRYPTPROV prov;
    HCRYPTKEY  key;
    
    printf ("\n  [ generating RSA key pair");
    
    // acquire a crypto provider context
    if (CryptAcquireContext(&prov,
          NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES,
          CRYPT_VERIFYCONTEXT));
    {          
      printf ("\n  [ acquired crypto provider");
      
      // generate 2048-bit RSA key pair
      if (CryptGenKey(prov, AT_KEYEXCHANGE,
        (WC_RSA_KEY_LEN << 16) | CRYPT_EXPORTABLE, &key))
      {        
        // export the public key as blob
        printf ("\n  [ exporting public key");        
        export_rsa_key(prov, key, "00000000.pky", PUBLICKEYBLOB,  FALSE);
        
        // export the private key as blob
        printf ("\n  [ exporting private key");
        export_rsa_key(prov, key, "00000000.dky", PRIVATEKEYBLOB, FALSE);
        
        // export the private key (encrypted with ransomware public key) 
        printf ("\n  [ exporting private key (encrypted)");
        export_rsa_key(prov, key, "00000000.eky", PRIVATEKEYBLOB,  TRUE);
        
        CryptDestroyKey(key);
      }
      CryptReleaseContext(prov, 0);      
    }  
}

// generate an AES-128 key or obtain one from archive
// then import into key object 
aes_key_t* get_aes_key(HCRYPTPROV prov, HCRYPTKEY rsa_key, const char *file)
{
    aes_key_t *aes_key=0;
    key_hdr   key;
    FILE      *in;
    DWORD     mode, len;
    
    aes_key = malloc(sizeof(aes_key_t));
    
    // import from file?
    if (file!=NULL)
    {
      printf ("\n  [ importing AES key from archive");
      // open archive
      in = fopen(file, "rb");
    
      if (in != NULL) {
        printf ("\n  [ skipping signature");
        
        // skip signature + enclen
        fseek(in, WC_SIG_LEN + sizeof(uint32_t), SEEK_SET);
      
        // read encrypted key
        key.len = fread(aes_key->enc, 1, WC_ENCKEY_LEN, in);
        
        // decrypt AES key using private key
        if (!CryptDecrypt(rsa_key, 0, TRUE, 0, 
            aes_key->enc, &key.len)) 
        {
          xstrerror ("AES Key Decryption with CryptDecrypt");
          return 0;
        }
        // copy decrypted AES key to key header for importing
        memcpy (key.key, aes_key->enc, WC_AES_KEY_LEN);
        fclose(in);    
      }
    } else {
      // generate new one
      CryptGenRandom(prov, WC_AES_KEY_LEN, key.key);
      
      // encrypt using public key
      memcpy (aes_key->enc, key.key, WC_AES_KEY_LEN);      
      
      len = WC_AES_KEY_LEN;
      
      if (!CryptEncrypt(rsa_key, 0, TRUE, 
                0, aes_key->enc, &len, WC_ENCKEY_LEN)) {
        xstrerror ("CryptEncrypt");
        return 0;
      }      
    }      
    
    // set key parameters
    key.hdr.bType    = PLAINTEXTKEYBLOB;
    key.hdr.bVersion = CUR_BLOB_VERSION;
    key.hdr.reserved = 0;
    key.hdr.aiKeyAlg = CALG_AES_128;
    key.len          = WC_AES_KEY_LEN;
    
    // import it
    if (CryptImportKey (prov, (PBYTE)&key, sizeof(key), 
          0, CRYPT_NO_SALT, &aes_key->key))
    {
      printf ("\n  [ key imported ok");
      
      mode = CRYPT_MODE_CBC;
      
      // set to use CBC mode
      CryptSetKeyParam(aes_key->key, KP_MODE, (PBYTE)&mode, 0);
    }
    
    // fingers crossed :P
    return aes_key;
}
    
/**
 *
 * Attempt to encrypt a file using public key
 *
 */
void encrypt(HCRYPTPROV prov, HCRYPTKEY rsa_key, const char *infile)
{
    char            outfile[MAX_PATH];
    FILE            *in, *out;
    BYTE            *buf;
    DWORD           len, t;
    struct __stat64 st;
    aes_key_t       *aes_key;
     
    // set the output file name + extension
    lstrcpyn(outfile, infile, MAX_PATH);
    lstrcat (outfile, WC_ARCHIVE_EXT);
    
    // open file to encrypt
    in = fopen(infile, "rb");
    if (in==NULL) return;
    
    // open file for archive 
    out = fopen(outfile, "wb");
    
    if (out != NULL) 
    {
      // get a new AES-128 key for this file
      aes_key = get_aes_key(prov, rsa_key, NULL);
      
      if (aes_key != NULL) {
        // allocate 1MB of memory
        buf = malloc(WC_BUF_SIZE);
        
        if (buf != NULL)
        {
          // write the signature
          fwrite(WC_SIGNATURE, 1, WC_SIG_LEN, out);
          
          // write the encrypted key length
          t = WC_ENCKEY_LEN;
          fwrite(&t, 1, sizeof(t), out);
          
          // write the encrypted AES key
          fwrite(aes_key->enc, 1, WC_ENCKEY_LEN, out);
          
          // write the unknown value
          t = 4;
          fwrite(&t, 1, sizeof(t), out);
          
          // obtain 64-bit file size
          _stat64(infile, &st);
          // write size to file
          fwrite(&st.st_size, 1, sizeof(uint64_t), out);
          
          // encrypt data and write to archive
          for (;;) {
            // read in 1MB chunks
            len = fread(buf, 1, WC_BUF_SIZE, in);
        
            // no more data?
            if (len==0) break;

            // encrypt block
            CryptEncrypt(aes_key->key, 0, len<WC_BUF_SIZE, 
                0, buf, &len, WC_BUF_SIZE);

            // write to file
            fwrite(buf, 1, len, out);
          }
          free(buf);
        }
        CryptDestroyKey(aes_key->key);
        free(aes_key);
      }
      fclose(out);
    }
    fclose(in);
}

/**
 *
 * Attempt to decrypt a WanaCryptor archive using private key
 *
 */
void decrypt(HCRYPTPROV prov, HCRYPTKEY rsa_key, const char *infile)
{
    char      outfile[MAX_PATH];
    FILE      *in, *out;
    BYTE      *buf;
    aes_key_t *aes_key=NULL;
    DWORD     len;
    
    printf ("\n  [ reading from %s", infile);
    
    // open file to decrypt
    in = fopen(infile, "rb");
    if (in==NULL) return;
    
    // open output file
    lstrcpyn(outfile, infile, MAX_PATH);
    // remove extension
    PathRemoveExtension(outfile);
    
    printf ("\n  [ Saving to %s", outfile);
    out = fopen(outfile, "wb");
    
    if (out != NULL) {
      // get a AES-128 key for this archive
      aes_key = get_aes_key(prov, rsa_key, infile);
      
      if (aes_key != NULL) 
      {
        buf = malloc(WC_BUF_SIZE);
        if (buf != NULL)
        {
          // skip stuff in file to ciphertext  
          printf ("\n  [ reading data");
          fseek(in, WC_DATA_OFFSET + 8, SEEK_SET);
          
          for (;;) {
            // read in 1MB chunks
            len = fread(buf, 1, WC_BUF_SIZE, in);
        
            // no more data?
            if (len==0) break;

            // decrypt block
            if (!CryptDecrypt(aes_key->key, 0, TRUE, 
                0, buf, &len))
            {
              xstrerror("CryptDecrypt");
              break;
            }

            // write to file
            fwrite(buf, 1, len, out);
          }
        }
        CryptDestroyKey(aes_key->key);
        free(aes_key);
      }
      fclose(out);
    }
    fclose(in);
}

// encrypt or decrypt a file using public/private keys
void encrypt_file (const char *infile, int enc)
{
    HCRYPTPROV prov=0;
    HCRYPTKEY  rsa_key=0;
    DWORD      att, arc;
    char       *key_file;
    
    // is file accessible?
    att = GetFileAttributes(infile);
    
    if (att==INVALID_FILE_ATTRIBUTES) {
      printf ("\n  [ unable to access %s", infile);
      return;
    }
    
    // is this an archive?
    arc = valid_archive(infile, 0);
    
    // just warn user if infile is already archive
    if (arc && enc==WC_ENCRYPT) {
      printf ("\n  [ warning: %s is already a WanaCryptor archive", infile);
    }
    
    // if we're decrypting, make sure it's a valid archive
    // exit if not
    if (enc==WC_DECRYPT) {
      if (!arc) {
        printf ("\n  [ invalid WanaCryptor archive: %s", infile);
        return;
      }
    }
    
    printf ("\n  [ acquiring crypto provider");
    
    // acquire a crypto provider (same used by ransomware)
    if (CryptAcquireContext(&prov,
          NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES,
          CRYPT_VERIFYCONTEXT))
    {
      key_file = (enc==WC_ENCRYPT) ? WC_PUBLIC_KEY : WC_PRIVATE_KEY;
      
      printf ("\n  [ importing RSA key from %s", key_file);
          
      // import RSA public or private key
      rsa_key = import_rsa_key(prov, key_file);
 
      // imported ok? 
      if (rsa_key != 0)
      {
        printf ("\n  [ performing %scryption", 
            enc==WC_ENCRYPT ? "En" : "De");
            
        if (enc==WC_ENCRYPT) {
          encrypt(prov, rsa_key, infile);
        } else {
          decrypt(prov, rsa_key, infile);
        }       
        // release rsa key object
        CryptDestroyKey(rsa_key);
      }
      printf ("\n  [ releasing provider");      
      // release provider
      CryptReleaseContext(prov, 0);
    }      
}

char* getparam (int argc, char *argv[], int *i)
{
    int n=*i;
    
    if (argv[n][2] != 0) {
      return &argv[n][2];
    }
    if ((n+1) < argc) {
      *i=n+1;
      return argv[n+1];
    }
    printf ("  [ %c%c requires parameter\n", argv[n][0], argv[n][1]);
    exit (0);
}

void usage (void)
{
    printf ("\n\n");
    printf ("  [ usage: wanafork [options]\n\n");
    printf ("     -g           Generate RSA key pair and export blobs\n");
    printf ("     -e <file>    Encrypt file (requires 00000000.pky)\n");
    printf ("     -d <file>    Decrypt archive (requires 00000000.dky)\n");
    printf ("     -i <file>    Show information about archive\n\n");
    exit (0);
}

int main(int argc, char *argv[])
{
    int  i, g=0, v=0, enc=WC_ENCRYPT;
    char opt;
    char *file=NULL;
    
    puts ("\n  [ WanaCryptor Archive Tool - @odzhancode\n");
       
    for (i=1; i<argc; i++)
    {
      if (argv[i][0]=='-' || argv[i][0]=='/')
      {
        opt=argv[i][1];
        switch (opt)
        {
          case 'g': // generate RSA key pair
            g=1;
            break;
          case 'e': // encrypt file
            enc   = WC_ENCRYPT;
            file  = getparam (argc, argv, &i);
            break;            
          case 'd': // decrypt archive
            enc   = WC_DECRYPT;
            file  = getparam (argc, argv, &i);
            break;             
          case 'i': // display info about archive
            file  = getparam (argc, argv, &i);
            v=1;
            break;
          default:
            usage();
            break;
        }
      } else {
        file = argv[i];
      }
    }
    
    // generate RSA key pair?
    if (g) {
      gen_rsa_key();
      return 0;
    }
    
    // we have a file?
    if (file==NULL) {
      printf ("\n  [ no input file specified");
      usage();
    }
    
    // just information about archive?
    if (v) {
      valid_archive(file, 1);
      return 0;
    }
    // encrypt or decrypt (depends on enc value)
    encrypt_file(file, enc);
    return 0;
}

