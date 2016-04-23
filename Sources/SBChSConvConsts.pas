(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SBChSUnicode.inc}

unit SBChSConvConsts;

interface


resourcestring
  SEncodingError = '%s ecoding error: %s';
  SDecodingError = '%s decoding error: %s';

  SIllegalCharacter = 'Illegal character';

  SUnicodeCategory = 'Unicode';

  SArabicCategory = 'Arabic';
  SBalticCategory = 'Baltic';
  SCelticCategory = 'Celtic';
  SCyrillicCategory = 'Cyrillic';
  SGreekCategory = 'Greek';
  SHebrewCategory = 'Hebrew';
  SNordicCategory = 'Nordic';
  SIcelandicCategory = 'Icelandic';
  STurkishCategory = 'Turkish';
  SRomanianCategory = 'Romanian';
  SVietnameseCategory = 'Vietnamese';
  SGeorgianCategory = 'Georgian';
  SArmenianCategory = 'Armenian';
  STajikCategory = 'Tajik';
  SThaiCategory = 'Thai';

  SUSCategory = 'United States';

  SCentralEuropeanCategory = 'Central European';
  SSouthEuropeanCategory = 'South European';
  SWesternEuropeanCategory = 'Western European';

  SChineseCategory = 'Chinese';
  SJapaneseCategory = 'Japanese';
  SKoreanCategory = 'Korean';

  SUTF32 = 'Unicode (UTF-32)';
  SUTF32BE = 'Unicode (UTF-32 Big Endian)';
  SUTF16 = 'Unicode (UTF-16)';
  SUTF16BE = 'Unicode (UTF-16 Big Endian)';
  SUTF8 = 'Unicode (UTF-8)';
  SUTF7 = 'Unicode (UTF-7)';

  SUS_ASCII = 'US-ASCII (7 bit)';
  SISO_8859_1 = 'Western European (ISO-8859-1)';

implementation

end.
