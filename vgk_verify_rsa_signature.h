// VGK Anti-Cheat RSA Signature Verification Function
// 
// Parameters:
//   pSignedData - ASN.1 DER encoded signed data (PKCS#7 format)
//   cbSignedData - Size of signed data in bytes
//   pszKeyIdentifier - Key identifier string to match against key table
// 
// Returns:
//   0 - Signature valid
//   1 - Error (BCrypt operation failed)
//   2 - No matching key found in table
//   3 - Invalid signature (BCryptVerifySignature returned STATUS_INVALID_SIGNATURE)
//   4 - Unknown/unsupported hash algorithm
// 
// Supported hash algorithms: SHA1, SHA256, SHA384, SHA512
// Key table: byte_14009F260 with 26 entries, 600 bytes each
__int64 __fastcall VgkVerifyRsaSignature(_BYTE *pSignedData, __int64 cbSignedData, __int64 pszKeyIdentifier)
{
  int nKeyTableIndex; // eax
  __int64 cbSignedDataCopy; // r15
  _BYTE *pSignedDataPtr; // r12
  __int64 nMatchedKeyIndex; // r9
  __int64 nKeyEntryOffset; // rdi
  unsigned __int8 *pKeyIdCompare; // rax
  __int64 v9; // r8
  int chFromInput; // ecx
  int nCompareResult; // edx
  __int64 nKeyEntryBase; // r14
  __int64 pRsaPublicKeyBlob; // rbx
  int nKeyModulusSize; // eax
  unsigned __int8 *pDataEnd; // r10
  unsigned __int8 *pAsn1Parser; // rcx
  unsigned int nAsn1LengthByte; // eax
  unsigned __int8 *pAsn1Data; // rcx
  __int64 cbSequenceLength; // rdx
  __int64 nLengthBytes; // r8
  __int64 nLengthCounter; // r9
  __int64 v22; // rax
  unsigned __int8 *pSequenceEnd; // r15
  unsigned __int8 nAsn1Tag; // al
  unsigned __int8 *pInnerSeq; // rcx
  unsigned int nInnerSeqLen; // eax
  unsigned __int8 *pInnerData; // rcx
  __int64 cbInnerSeqLen; // rdx
  __int64 v29; // r8
  __int64 v30; // r9
  __int64 v31; // rax
  unsigned __int8 *pAlgIdSeq; // rbx
  unsigned __int8 nAlgIdTag; // al
  unsigned __int8 *pAlgIdData; // rbx
  unsigned int nAlgIdLen; // eax
  unsigned __int8 *pAlgIdInner; // rbx
  __int64 cbAlgIdLen; // rcx
  __int64 v38; // rdx
  __int64 v39; // r8
  __int64 v40; // rax
  unsigned __int8 *pAlgIdEnd; // r14
  unsigned __int8 nOidTag; // al
  unsigned __int8 *pOidData; // rbx
  unsigned int nOidLenByte; // eax
  unsigned __int8 *pOidContent; // rbx
  unsigned __int64 cbOidLength; // rsi
  __int64 v47; // rcx
  __int64 v48; // rdx
  __int64 v49; // rax
  unsigned __int8 *pOidEnd; // rdi
  int nOidStrLen; // eax
  int nOidValue; // r8d
  __int64 nOidStrPos; // r13
  unsigned __int64 nOidByteIndex; // r12
  int nSnprintfResult; // eax
  unsigned __int8 *v56; // rdi
  unsigned int v57; // eax
  unsigned __int8 *v58; // rdi
  __int64 v59; // rcx
  __int64 v60; // rdx
  __int64 v61; // r8
  __int64 v62; // rax
  int nHashAlgorithm; // edx
  unsigned __int8 *v64; // rcx
  unsigned int v65; // eax
  unsigned __int8 *v66; // rcx
  __int64 v67; // rdi
  __int64 v68; // r8
  __int64 v69; // r9
  __int64 v70; // rax
  ULONG cbSignature; // edi
  UCHAR *pSignature; // r15
  char v73; // al
  UCHAR *v74; // r10
  __int64 v75; // rcx
  UCHAR *pDataToHash; // r14
  __int64 v77; // r8
  __int64 v78; // r9
  __int64 v79; // rax
  UCHAR *v80; // r9
  UCHAR *v81; // rcx
  unsigned int v82; // eax
  unsigned __int8 *v83; // rcx
  __int64 v84; // rbx
  __int64 v85; // r8
  __int64 v86; // r10
  __int64 v87; // rax
  ULONG cbDataToHash; // ebx
  UCHAR *v89; // rax
  __int64 **p_pszKeyIdCopy; // rdx
  ULONG cbHashDigest; // r9d
  UCHAR *hHashObjectBuffer; // rax
  UCHAR *hSha384Buffer; // rsi
  void *hRsaKeyHandle; // rcx
  NTSTATUS nVerifyResult; // ebx
  UCHAR *v97; // rax
  NTSTATUS nVerifyStatus; // eax
  BCRYPT_ALG_HANDLE hAlgToClose; // rcx
  __int64 nSavedKeyIndex; // [rsp+20h] [rbp-E0h]
  __int64 v101; // [rsp+40h] [rbp-C0h]
  BCRYPT_ALG_HANDLE hSha384AlgHandle; // [rsp+58h] [rbp-A8h] BYREF
  BCRYPT_ALG_HANDLE hSha512AlgHandle; // [rsp+60h] [rbp-A0h] BYREF
  BCRYPT_ALG_HANDLE hSha1AlgHandle; // [rsp+68h] [rbp-98h] BYREF
  BCRYPT_ALG_HANDLE nKeyTableIndexStore; // [rsp+70h] [rbp-90h] BYREF
  int nKeyEntryBaseCopy; // [rsp+78h] [rbp-88h]
  __int64 v109; // [rsp+80h] [rbp-80h]
  ULONG v110; // [rsp+88h] [rbp-78h] BYREF
  ULONG v111; // [rsp+8Ch] [rbp-74h] BYREF
  ULONG v112; // [rsp+90h] [rbp-70h] BYREF
  ULONG hSha1Hash; // [rsp+94h] [rbp-6Ch] BYREF
  __int64 hSha1ObjSize; // [rsp+98h] [rbp-68h] BYREF
  BCRYPT_HASH_HANDLE hSha256ObjSize; // [rsp+A0h] [rbp-60h] BYREF
  __int64 hSha256Hash; // [rsp+A8h] [rbp-58h] BYREF
  BCRYPT_HASH_HANDLE hSha384ObjSize; // [rsp+B0h] [rbp-50h] BYREF
  __int64 hSha384Hash; // [rsp+B8h] [rbp-48h] BYREF
  BCRYPT_HASH_HANDLE hSha512ObjSize; // [rsp+C0h] [rbp-40h] BYREF
  __int64 hSha512Hash; // [rsp+C8h] [rbp-38h] BYREF
  BCRYPT_HASH_HANDLE v121; // [rsp+D0h] [rbp-30h] BYREF
  UCHAR *pSignedDataEnd; // [rsp+D8h] [rbp-28h]
  UCHAR *v123; // [rsp+E0h] [rbp-20h]
  __int64 *v124; // [rsp+E8h] [rbp-18h] BYREF
  __int64 *v125; // [rsp+F0h] [rbp-10h] BYREF
  __int64 *v126; // [rsp+F8h] [rbp-8h] BYREF
  __int64 *pszKeyIdCopy; // [rsp+100h] [rbp+0h] BYREF
  __int64 v128; // [rsp+108h] [rbp+8h]
  __int64 v129; // [rsp+110h] [rbp+10h] BYREF
  wchar_t v130; // [rsp+118h] [rbp+18h]
  __int64 v131; // [rsp+120h] [rbp+20h] BYREF
  int v132; // [rsp+128h] [rbp+28h]
  __int16 v133; // [rsp+12Ch] [rbp+2Ch]
  __int64 v134; // [rsp+130h] [rbp+30h] BYREF
  int v135; // [rsp+138h] [rbp+38h]
  wchar_t v136; // [rsp+13Ch] [rbp+3Ch]
  __int64 v137; // [rsp+140h] [rbp+40h] BYREF
  int v138; // [rsp+148h] [rbp+48h]
  wchar_t hashDigest; // [rsp+14Ch] [rbp+4Ch]
  __int128 v140; // [rsp+150h] [rbp+50h] BYREF
  __int128 v141; // [rsp+160h] [rbp+60h]
  __int128 szOidString; // [rsp+170h] [rbp+70h]
  char v143[64]; // [rsp+190h] [rbp+90h] BYREF

  v128 = pszKeyIdentifier;
  nKeyTableIndex = 0;
  nKeyEntryBaseCopy = 0;
  cbSignedDataCopy = cbSignedData;
  pSignedDataPtr = pSignedData;
  v101 = 0;
  nMatchedKeyIndex = 0;
  while ( 1 )
  {
    nKeyEntryOffset = 600LL * nKeyTableIndex;   // Main loop: Iterate through key table (26 entries, 600 bytes each)
                                                // Compare pszKeyIdentifier with key identifier at offset +1 in each entry
    pKeyIdCompare = &g_RsaKeyTable[nKeyEntryOffset + 1];
    v9 = pszKeyIdentifier - (_QWORD)pKeyIdCompare;
    do
    {
      chFromInput = pKeyIdCompare[v9];
      nCompareResult = *pKeyIdCompare - chFromInput;
      if ( nCompareResult )
        break;
      ++pKeyIdCompare;
    }
    while ( chFromInput );
    if ( !nCompareResult )
    {
      nKeyEntryBase = 600 * nMatchedKeyIndex;
      v109 = 600 * nMatchedKeyIndex;
      if ( !g_RsaKeyTable[600 * nMatchedKeyIndex] )// Check if RSA key is already initialized (flag at offset 0)
                                                // If not initialized, import the RSA public key
      {
        pRsaPublicKeyBlob = VgkAllocatePool(4096);// Allocate 4KB buffer for BCRYPT_RSAKEY_BLOB structure
                                                // Magic: 0x31415352 = 'RSA1' (BCRYPT_RSAPUBLIC_MAGIC)
        *(_DWORD *)pRsaPublicKeyBlob = 826364754;// Set RSA public key blob header:
                                                //   Magic = RSA1 (0x31415352)
                                                //   BitLength = KeySize * 8
                                                //   cbPublicExp = 3 (hardcoded)
                                                //   cbModulus = KeySize
                                                //   Exponent = 65537 (0x10001) - Standard RSA public exponent
        nKeyModulusSize = *(unsigned __int16 *)&g_RsaKeyTable[nKeyEntryBase + 66];
        *(_DWORD *)(pRsaPublicKeyBlob + 8) = 3;
        *(_DWORD *)(pRsaPublicKeyBlob + 4) = 8 * nKeyModulusSize;
        *(_DWORD *)(pRsaPublicKeyBlob + 12) = *(unsigned __int16 *)&g_RsaKeyTable[nKeyEntryBase + 66];
        *(_DWORD *)(pRsaPublicKeyBlob + 24) = 65537;
        VgkMemCopy(
          pRsaPublicKeyBlob + 27,
          &g_RsaKeyTable[nKeyEntryOffset + 68],
          *(unsigned __int16 *)&g_RsaKeyTable[nKeyEntryBase + 66]);
        if ( BCryptOpenAlgorithmProvider(
               (BCRYPT_ALG_HANDLE *)&g_RsaKeyTable[nKeyEntryOffset + 584],
               L"RSA",
               word_14008DAF0,
               0) < 0 )
          goto LABEL_142;                       // BCryptOpenAlgorithmProvider for RSA algorithm
                                                // Provider stored at key entry offset +584
        if ( BCryptImportKeyPair(
               *(BCRYPT_ALG_HANDLE *)&g_RsaKeyTable[nKeyEntryBase + 584],
               0,
               L"RSAPUBLICBLOB",
               (BCRYPT_KEY_HANDLE *)&g_RsaKeyTable[nKeyEntryOffset + 592],
               (PUCHAR)pRsaPublicKeyBlob,
               *(_DWORD *)(pRsaPublicKeyBlob + 12) + 24 + *(_DWORD *)(pRsaPublicKeyBlob + 8),
               0) < 0 )                         // BCryptImportKeyPair with RSAPUBLICBLOB
                                                // Imports the public key, handle stored at offset +592
        {
          BCryptCloseAlgorithmProvider(*(BCRYPT_ALG_HANDLE *)&g_RsaKeyTable[nKeyEntryOffset + 584], 0);
LABEL_142:
          VgkFreePool(pRsaPublicKeyBlob);       // Error path: RSA key import failed
                                                // Cleanup and return error code 1
          return 1;
        }
        g_RsaKeyTable[nKeyEntryBase] = 1;       // Mark key as initialized (set flag byte to 1)
        VgkFreePool(pRsaPublicKeyBlob);
        nMatchedKeyIndex = v101;
      }
      pDataEnd = &pSignedDataPtr[cbSignedDataCopy];
      v123 = &pSignedDataPtr[cbSignedDataCopy];
      if ( pSignedDataPtr < &pSignedDataPtr[cbSignedDataCopy] )
      {
        pAsn1Parser = pSignedDataPtr + 1;
        if ( *pSignedDataPtr == 48 && pAsn1Parser < pDataEnd )
          break;                                // Parse ASN.1 length field
                                                // If high bit set (0x80), length is multi-byte (1-4 bytes)
                                                // Otherwise, length is single byte value
      }
    }
LABEL_139:
    ++nMatchedKeyIndex;
    nKeyTableIndex = nKeyEntryBaseCopy + 1;
    v101 = nMatchedKeyIndex;
    nKeyEntryBaseCopy = nKeyTableIndex;
    if ( nKeyTableIndex >= 26 )
      return 2;
    pszKeyIdentifier = v128;
  }
  nAsn1LengthByte = *pAsn1Parser;
  pAsn1Data = pSignedDataPtr + 2;
  pSignedDataEnd = pSignedDataPtr + 2;
  if ( (nAsn1LengthByte & 0x80u) != 0 )
  {
    nLengthBytes = nAsn1LengthByte & 0x7F;
    if ( (unsigned int)(nLengthBytes - 1) > 3 )
      goto LABEL_139;
    nLengthCounter = nAsn1LengthByte & 0x7F;
    if ( &pAsn1Data[nLengthBytes] > pDataEnd )
      goto LABEL_138;
    cbSequenceLength = 0;
    if ( (nAsn1LengthByte & 0x7F) != 0 )
    {
      do
      {
        v22 = *pAsn1Data++;
        cbSequenceLength = v22 | (cbSequenceLength << 8);
        --nLengthCounter;
      }
      while ( nLengthCounter );
    }
  }
  else
  {
    cbSequenceLength = nAsn1LengthByte;
  }
  pSequenceEnd = &pAsn1Data[cbSequenceLength];
  if ( &pAsn1Data[cbSequenceLength] > pDataEnd )
    goto LABEL_137;
  if ( pAsn1Data >= pSequenceEnd )
    goto LABEL_137;
  nAsn1Tag = *pAsn1Data;
  pInnerSeq = pAsn1Data + 1;
  if ( nAsn1Tag != 48 || pInnerSeq >= pSequenceEnd )
    goto LABEL_137;
  nInnerSeqLen = *pInnerSeq;
  pInnerData = pInnerSeq + 1;
  if ( (nInnerSeqLen & 0x80u) != 0 )
  {
    v29 = nInnerSeqLen & 0x7F;
    if ( (unsigned int)(v29 - 1) > 3 )
      goto LABEL_137;
    v30 = nInnerSeqLen & 0x7F;
    if ( &pInnerData[v29] > pSequenceEnd )
      goto LABEL_137;
    cbInnerSeqLen = 0;
    if ( (nInnerSeqLen & 0x7F) != 0 )           // Parse inner SEQUENCE containing DigestInfo
                                                // This contains AlgorithmIdentifier + digest
    {
      do
      {
        v31 = *pInnerData++;
        cbInnerSeqLen = v31 | (cbInnerSeqLen << 8);
        --v30;
      }
      while ( v30 );
    }
  }
  else
  {
    cbInnerSeqLen = nInnerSeqLen;
  }
  pAlgIdSeq = &pInnerData[cbInnerSeqLen];
  if ( &pInnerData[cbInnerSeqLen] >= pSequenceEnd )
    goto LABEL_137;
  nAlgIdTag = *pAlgIdSeq;
  pAlgIdData = pAlgIdSeq + 1;
  if ( nAlgIdTag != 48 || pAlgIdData >= pSequenceEnd )
    goto LABEL_137;
  nAlgIdLen = *pAlgIdData;
  pAlgIdInner = pAlgIdData + 1;
  if ( (nAlgIdLen & 0x80u) != 0 )
  {
    v38 = nAlgIdLen & 0x7F;
    if ( (unsigned int)(v38 - 1) > 3 )
      goto LABEL_137;                           // Parse AlgorithmIdentifier SEQUENCE
                                                // Contains OID of hash algorithm + optional parameters
    v39 = nAlgIdLen & 0x7F;
    if ( &pAlgIdInner[v38] > pSequenceEnd )
      goto LABEL_137;
    cbAlgIdLen = 0;
    if ( (nAlgIdLen & 0x7F) != 0 )
    {
      do
      {
        v40 = *pAlgIdInner++;
        cbAlgIdLen = v40 | (cbAlgIdLen << 8);
        --v39;
      }
      while ( v39 );
    }
  }
  else
  {
    cbAlgIdLen = nAlgIdLen;
  }
  pAlgIdEnd = &pAlgIdInner[cbAlgIdLen];         // Parse OID (Object Identifier) for hash algorithm
                                                // Tag 0x06 = OID in ASN.1
                                                // Decode OID bytes to string format (e.g., '1.2.840.113549.2.5')
  if ( &pAlgIdInner[cbAlgIdLen] > pSequenceEnd )
    goto LABEL_137;
  if ( pAlgIdInner >= pAlgIdEnd )
    goto LABEL_137;
  nOidTag = *pAlgIdInner;
  pOidData = pAlgIdInner + 1;
  if ( nOidTag != 6 || pOidData >= pAlgIdEnd )
    goto LABEL_137;
  nOidLenByte = *pOidData;
  pOidContent = pOidData + 1;
  if ( (nOidLenByte & 0x80u) != 0 )
  {
    v47 = nOidLenByte & 0x7F;
    if ( (unsigned int)(v47 - 1) > 3 )
      goto LABEL_137;
    v48 = nOidLenByte & 0x7F;
    if ( &pOidContent[v47] > pAlgIdEnd )
      goto LABEL_137;
    cbOidLength = 0;
    if ( (nOidLenByte & 0x7F) != 0 )
    {
      do
      {
        v49 = *pOidContent++;
        cbOidLength = v49 | (cbOidLength << 8);
        --v48;
      }
      while ( v48 );
    }
  }
  else
  {
    cbOidLength = nOidLenByte;
  }
  pOidEnd = &pOidContent[cbOidLength];
  if ( &pOidContent[cbOidLength] > pAlgIdEnd )
    goto LABEL_137;
  if ( !cbOidLength )
    goto LABEL_137;
  nOidStrLen = snprintf_s(v143, 0x40u, 0x40u, "%d.%d", *pOidContent / 0x28u, *pOidContent % 0x28u);
  if ( nOidStrLen < 0 )
    goto LABEL_137;
  nOidValue = 0;
  nOidStrPos = nOidStrLen;
  for ( nOidByteIndex = 1; nOidByteIndex < cbOidLength; ++nOidByteIndex )
  {
    nOidValue = (nOidValue << 7) | pOidContent[nOidByteIndex] & 0x7F;
    if ( (pOidContent[nOidByteIndex] & 0x80u) == 0 )
    {
      LODWORD(nSavedKeyIndex) = nOidValue;
      nSnprintfResult = snprintf_s(&v143[nOidStrPos], 64 - nOidStrPos, 64 - nOidStrPos, byte_14008DAE0, nSavedKeyIndex);
      if ( nSnprintfResult < 0 )
        goto LABEL_136;
      nOidStrPos += nSnprintfResult;
      nOidValue = 0;
    }
  }
  if ( pOidEnd < pAlgIdEnd && (*pOidEnd == 48 || (unsigned __int8)(*pOidEnd - 5) <= 1u) )
  {
    v56 = pOidEnd + 1;
    if ( v56 >= pAlgIdEnd )
      goto LABEL_136;
    v57 = *v56;
    v58 = v56 + 1;
    if ( (v57 & 0x80u) != 0 )
    {
      v60 = v57 & 0x7F;
      if ( (unsigned int)(v60 - 1) > 3 )
        goto LABEL_136;
      v61 = v57 & 0x7F;
      if ( &v58[v60] > pAlgIdEnd )
        goto LABEL_136;
      v59 = 0;
      if ( (v57 & 0x7F) != 0 )
      {
        do
        {
          v62 = *v58++;
          v59 = v62 | (v59 << 8);
          --v61;
        }
        while ( v61 );
      }
    }
    else
    {
      v59 = v57;
    }
    if ( &v58[v59] > pAlgIdEnd )
    {
LABEL_136:
      pSignedDataPtr = pSignedData;             // Check for STATUS_INVALID_SIGNATURE (0xC000A000)
                                                // Return 3 if signature doesn't match
      goto LABEL_137;
    }
  }
  if ( !strcmp(v143, "1.2.840.113549.1.1.5") )
  {
    nHashAlgorithm = 1;
  }
  else if ( !strcmp(v143, "1.2.840.113549.1.1.11") )
  {
    nHashAlgorithm = 2;
  }
  else if ( !strcmp(v143, "1.2.840.113549.1.1.12") )
  {
    nHashAlgorithm = 3;                         // Handle optional AlgorithmIdentifier parameters
                                                // Tag 0x30=SEQUENCE, 0x05=NULL, 0x06=OID
  }
  else
  {
    nHashAlgorithm = strcmp(v143, "1.2.840.113549.1.1.13") == 0 ? 4 : 0;
  }
  if ( pAlgIdEnd >= pSequenceEnd )
    goto LABEL_136;
  v64 = pAlgIdEnd + 1;
  if ( *pAlgIdEnd != 3 || v64 >= pSequenceEnd )
    goto LABEL_136;
  v65 = *v64;
  v66 = pAlgIdEnd + 2;
  if ( (v65 & 0x80u) != 0 )
  {
    v68 = v65 & 0x7F;
    if ( (unsigned int)(v68 - 1) <= 3 )
    {
      v69 = v65 & 0x7F;
      if ( &v66[v68] <= pSequenceEnd )
      {
        v67 = 0;
        if ( (v65 & 0x7F) != 0 )
        {
          do
          {
            v70 = *v66++;
            v67 = v70 | (v67 << 8);
            --v69;
          }
          while ( v69 );
        }
        goto LABEL_83;
      }
    }
    goto LABEL_136;
  }
  v67 = v65;
LABEL_83:
  pSignedDataPtr = pSignedData;
  if ( &v66[v67] > pSequenceEnd )
    goto LABEL_137;
  if ( !v67 )
    goto LABEL_137;
  cbSignature = v67 - 1;
  pSignature = v66 + 1;
  if ( *pSignedData != 48 )
    goto LABEL_137;
  v73 = pSignedData[1];
  if ( v73 < 0 )
  {
    v77 = v73 & 0x7F;
    if ( (unsigned int)(v77 - 1) > 3 )
      goto LABEL_137;
    pDataToHash = pSignedDataEnd;
    v74 = v123;
    v78 = v73 & 0x7F;
    if ( &pSignedDataEnd[v77] > v123 )
      goto LABEL_137;
    v75 = 0;
    if ( (v73 & 0x7F) != 0 )
    {
      do
      {
        v79 = *pDataToHash++;
        v75 = v79 | (v75 << 8);
        --v78;
      }
      while ( v78 );
    }
  }
  else
  {
    v74 = v123;                                 // Extract signature bytes location
                                                // Points to the actual RSA signature value
    v75 = (unsigned __int8)pSignedData[1];
    pDataToHash = pSignedDataEnd;
  }
  v80 = &pDataToHash[v75];
  if ( &pDataToHash[v75] > v74 )
    goto LABEL_137;
  if ( pDataToHash >= v80 )
    goto LABEL_137;
  v81 = pDataToHash + 1;
  if ( *pDataToHash != 48 || v81 >= v80 )
    goto LABEL_137;
  v82 = *v81;
  v83 = pDataToHash + 2;
  if ( (v82 & 0x80u) != 0 )
  {
    v85 = v82 & 0x7F;
    if ( (unsigned int)(v85 - 1) > 3 )
      goto LABEL_137;
    v86 = v82 & 0x7F;
    if ( &v83[v85] > v80 )
      goto LABEL_137;
    v84 = 0;
    if ( (v82 & 0x7F) != 0 )
    {
      do
      {
        v87 = *v83++;
        v84 = v87 | (v84 << 8);
        --v86;
      }
      while ( v86 );
    }
  }
  else
  {
    v84 = v82;
  }
  if ( &v83[v84] > v80 )
  {
LABEL_137:
    cbSignedDataCopy = cbSignedData;
LABEL_138:
    nMatchedKeyIndex = v101;
    goto LABEL_139;
  }
  cbDataToHash = (_DWORD)v83 + v84 - (_DWORD)pDataToHash;
  if ( nHashAlgorithm == 1 )
  {
    if ( BCryptOpenAlgorithmProvider(&nKeyTableIndexStore, L"SHA1", word_14008DAF0, 0) < 0 )
      return 1;                                 // Map OID string to internal hash algorithm ID:
                                                //   '1.3.14.3.2.26' or similar -> SHA1 (1)
                                                //   '2.16.840.1.101.3.4.2.1' -> SHA256 (2)
                                                //   '2.16.840.1.101.3.4.2.2' -> SHA384 (3)
                                                //   '2.16.840.1.101.3.4.2.3' -> SHA512 (4)
    hSha1ObjSize = 0;
    v110 = 0;
    if ( BCryptGetProperty(nKeyTableIndexStore, L"ObjectLength", (PUCHAR)&hSha1ObjSize, 8u, &v110, 0) < 0
      || (v140 = 0,
          LODWORD(v141) = 0,
          v89 = (UCHAR *)VgkAllocatePool(hSha1ObjSize),
          BCryptCreateHash(nKeyTableIndexStore, &hSha256ObjSize, v89, hSha1ObjSize, 0, 0, 0) < 0)
      || BCryptHashData(hSha256ObjSize, pDataToHash, cbDataToHash, 0) < 0
      || BCryptFinishHash(hSha256ObjSize, (PUCHAR)&v140, 0x14u, 0) < 0 )// Determine hash algorithm from parsed OID string
                                                //   nHashAlgorithm = 1 -> SHA1 (20 bytes)
                                                //   nHashAlgorithm = 2 -> SHA256 (32 bytes)
                                                //   nHashAlgorithm = 3 -> SHA384 (48 bytes)
                                                //   nHashAlgorithm = 4 -> SHA512 (64 bytes)
    {
      hAlgToClose = nKeyTableIndexStore;
      goto LABEL_145;
    }
    BCryptDestroyHash(hSha256ObjSize);          // SHA1 path: BCryptOpenAlgorithmProvider(SHA1)
                                                // Create hash, hash data, finalize to 20-byte digest
    BCryptCloseAlgorithmProvider(nKeyTableIndexStore, 0);
    p_pszKeyIdCopy = &v124;
    v130 = aSha1[4];
    cbHashDigest = 20;
    v129 = *(_QWORD *)L"SHA1";
    v124 = &v129;
    goto LABEL_133;
  }
  if ( nHashAlgorithm != 2 )
  {
    if ( nHashAlgorithm != 3 )
    {
      if ( nHashAlgorithm != 4 )
        return 4;                               // Unknown hash algorithm - return error 4
      if ( BCryptOpenAlgorithmProvider(&hSha1AlgHandle, L"SHA512", word_14008DAF0, 0) < 0 )
        return 1;                               // SHA512 path: BCryptOpenAlgorithmProvider(SHA512)
                                                // Create hash, hash data, finalize to 64-byte digest
      hSha512Hash = 0;
      hSha1Hash = 0;
      if ( BCryptGetProperty(hSha1AlgHandle, L"ObjectLength", (PUCHAR)&hSha512Hash, 8u, &hSha1Hash, 0) < 0
        || (sub_14008D780(&v140, 0, 64),
            v97 = (UCHAR *)VgkAllocatePool(hSha512Hash),
            BCryptCreateHash(hSha1AlgHandle, &v121, v97, hSha512Hash, 0, 0, 0) < 0)
        || BCryptHashData(v121, pDataToHash, cbDataToHash, 0) < 0
        || BCryptFinishHash(v121, (PUCHAR)&v140, 0x40u, 0) < 0 )
      {
        hAlgToClose = hSha1AlgHandle;
        goto LABEL_145;
      }
      BCryptDestroyHash(v121);
      BCryptCloseAlgorithmProvider(hSha1AlgHandle, 0);
      p_pszKeyIdCopy = &pszKeyIdCopy;
      v138 = *(_DWORD *)L"12";
      cbHashDigest = 64;
      hashDigest = aSha512[6];
      pszKeyIdCopy = &v137;
      v137 = *(_QWORD *)L"SHA512";
      goto LABEL_133;
    }
    if ( BCryptOpenAlgorithmProvider(&hSha512AlgHandle, L"SHA384", word_14008DAF0, 0) < 0 )
      return 1;                                 // SHA384 path: BCryptOpenAlgorithmProvider(SHA384)
                                                // Create hash, hash data, finalize to 48-byte digest
    hSha384Hash = 0;
    v112 = 0;
    if ( BCryptGetProperty(hSha512AlgHandle, L"ObjectLength", (PUCHAR)&hSha384Hash, 8u, &v112, 0) < 0 )
    {
      hAlgToClose = hSha512AlgHandle;
      goto LABEL_145;
    }
    v140 = 0;
    v141 = 0;
    szOidString = 0;
    hSha384Buffer = (UCHAR *)VgkAllocatePool(hSha384Hash);
    if ( BCryptCreateHash(hSha512AlgHandle, &hSha512ObjSize, hSha384Buffer, hSha384Hash, 0, 0, 0) < 0
      || BCryptHashData(hSha512ObjSize, pDataToHash, cbDataToHash, 0) < 0
      || BCryptFinishHash(hSha512ObjSize, (PUCHAR)&v140, 0x30u, 0) < 0 )
    {
      BCryptCloseAlgorithmProvider(hSha512AlgHandle, 0);
      return 1;
    }
    BCryptDestroyHash(hSha512ObjSize);
    BCryptCloseAlgorithmProvider(hSha512AlgHandle, 0);
    v135 = *(_DWORD *)L"84";
    v136 = aSha384[6];
    v126 = &v134;
    hRsaKeyHandle = *(void **)&g_RsaKeyTable[v109 + 592];
    v134 = *(_QWORD *)L"SHA384";
    nVerifyResult = BCryptVerifySignature(hRsaKeyHandle, &v126, (PUCHAR)&v140, 0x30u, pSignature, cbSignature, 2u);// BCryptVerifySignature for SHA384 case
                                                // Padding info contains algorithm identifier string
    VgkFreePool(hSha384Buffer);
    if ( !nVerifyResult )
      return 0;
    if ( nVerifyResult == -1073700864 )
      return 3;
    goto LABEL_137;
  }
  if ( BCryptOpenAlgorithmProvider(&hSha384AlgHandle, aSha2, word_14008DAF0, 0) < 0 )
    return 1;
  hSha256Hash = 0;
  v111 = 0;
  if ( BCryptGetProperty(hSha384AlgHandle, L"ObjectLength", (PUCHAR)&hSha256Hash, 8u, &v111, 0) >= 0 )// SHA256 path: BCryptOpenAlgorithmProvider(SHA256)
                                                // Create hash, hash data, finalize to 32-byte digest
  {
    v140 = 0;
    v141 = 0;
    hHashObjectBuffer = (UCHAR *)VgkAllocatePool(hSha256Hash);
    if ( BCryptCreateHash(hSha384AlgHandle, &hSha384ObjSize, hHashObjectBuffer, hSha256Hash, 0, 0, 0) >= 0
      && BCryptHashData(hSha384ObjSize, pDataToHash, cbDataToHash, 0) >= 0
      && BCryptFinishHash(hSha384ObjSize, (PUCHAR)&v140, 0x20u, 0) >= 0 )
    {
      BCryptDestroyHash(hSha384ObjSize);
      BCryptCloseAlgorithmProvider(hSha384AlgHandle, 0);
      p_pszKeyIdCopy = &v125;
      v132 = 3538997;
      cbHashDigest = 32;
      v133 = 0;
      v125 = &v131;
      v131 = *(_QWORD *)aSha2;
LABEL_133:
      nVerifyStatus = BCryptVerifySignature(
                        *(BCRYPT_KEY_HANDLE *)&g_RsaKeyTable[v109 + 592],
                        p_pszKeyIdCopy,
                        (PUCHAR)&v140,
                        cbHashDigest,
                        pSignature,
                        cbSignature,
                        2u);                    // BCryptVerifySignature with BCRYPT_PAD_PKCS1 (flag=2)
                                                // Verifies RSA signature using PKCS#1 v1.5 padding
                                                // Returns 0 on success, STATUS_INVALID_SIGNATURE (0xC000A000) on failure
      if ( !nVerifyStatus )
        return 0;
      if ( nVerifyStatus == -1073700864 )
        return 3;                               // Return 0: Signature verification succeeded
      goto LABEL_137;
    }
  }
  hAlgToClose = hSha384AlgHandle;
LABEL_145:
  BCryptCloseAlgorithmProvider(hAlgToClose, 0);
  return 1;
}
