# About

**This tool should only be used by security researchers studying the encryption and decryption process used by WanaCryptor ransomware.**

**It should not be used to recover mission critical files and I'm not responsible in any way for files or data you happen to lose as a result of using this tool.**

I'm advising you don't use it. The only reason it's being released is that it may help others understand the encryption/decryption process.

Right now, many people are trying to understand how this ransomware works so that's why I've decided to publish it early. In my opinion, it's not fit for release, but it may be of use to some.

# Encryption process

When WanaCryptor executes on a system, it generates a 2048-bit RSA key pair.
The public and private key blobs are exported to files, however the private key is encrypted using another RSA public key embedded inside the executable.

When the program begins to encrypt files, it generates a 128-bit AES key per file and uses the public key to encrypt it, storing it with the AES derived ciphertext.

The only way to recover the AES-128 key is either through exhaustive brute force or to decrypt using the private key. 
 
The WanaCryptor ransomware encrypts the private key and saves to **00000000.eky**

The only current way we know of recovery is to have the authors decrypt this key
and store in file named **00000000.dky**

# Files

**wanafork.c**

Tool to encrypt/decrypt WanaCryptor archives. Assumes necessary files required to encrypt files and decrypt archives are in the same directory. 
   
**rw_public.bin**

RSA public key used to encrypt users RSA private key. Only the authors of ransom ware currently have corresponding private key necessary to recover files. 

**wc_files\00000000.pky**

RSA public key dumped from XP system with WanaCryptor.

**wc_files\00000000.dky**   

RSA private key dumped from XP system with WanaCryptor. 

There was no ransom paid for this key, it was simply dumped from memory before the software could encrypt it using the master public key.

We needed something to test for encryption and decryption between **wanafork** and **@WanaDecryptor@.exe**.

**wc_files\00000000.eky** 

RSA private key encrypted by WanaCryptor. Although this isn't useful for anything, it may be wise just to document its structure which only appears to have a 32-bit value prepended to RSA ciphertext.
 
There are some encrypted archives in wc_files\arc ranging in sizes of 0-8 bytes that should decrypt fine using wanafork.

I'm already aware wanafork won't work with files over 1MB. It'll be fixed later.

# Developing tool for Linux

The main obstacle developers will find when importing CAPI key blobs is that the values are stored using Little-Endian convention.

It's best to convert them into PEM files first before attempting to use with other cryptography libraries. You can do this using OpenSSL.

  	openssl rsa -pubin -inform MS\ PUBLICKEYBLOB -in rw_public.bin -outform PEM -out rw_public.pem
  	openssl rsa -pubin -inform MS\ PUBLICKEYBLOB -in 00000000.pky -outform PEM -out pky.pem
  	openssl rsa -pubin -inform MS\ PUBLICKEYBLOB -in 00000000.dky -outform PEM -out dky.pem
 
 
# License

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
  POSSIBILITY OF SUCH DAMAGE.

# Authors

@odzhancode
5/14/2017 9:50:22 PM 