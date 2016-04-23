(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SBChSUnicode.inc}

unit SBChSConvCharsets;

interface

{$define _USE_CHARSETS_EXPLICITLY_}

{$ifdef SB_WINRT}
{$define _USE_CHARSETS_EXPLICITLY_}
 {$endif}

{$ifdef NET_CF}
{$define _USE_CHARSETS_EXPLICITLY_}
 {$endif}

uses
  {$ifndef SB_REDUCED_CHARSETS}
  {$ifdef _USE_CHARSETS_EXPLICITLY_}
  csISO_8859_2,
  csISO_8859_3,
  csISO_8859_4,
  csISO_8859_5,
  csISO_8859_6,
  csISO_8859_7,
  csISO_8859_8,
  csISO_8859_8i,
  csISO_8859_9,
  csISO_8859_10,
  csISO_8859_11,
  csISO_8859_13,
  csISO_8859_14,
  csISO_8859_15,
  csISO_8859_16,

  csCP1250,
  csCP1251,
  csCP1252,
  csCP1253,
  csCP1254,
  csCP1255,
  csCP1256,
  csCP1257,
  csCP1258,

  csCP437,
  csCP500,
  csCP737,
  csCP775,
  csCP850,
  csCP852,
  csCP857,
  csCP861,
  csCP862,
  csCP866,
  csCP869,
  csCP874,
  //csCP950Data,

  csCP037,
  csCP424,
  csCP853,
  csCP855,
  csCP856,
  csCP860,
  csCP863,
  csCP864,
  csCP865,
  csCP875,
  csCP1006,
  csCP1131,
  csCP1133,

  csKOI8R,
  csKOI8U,
  csKOI8RU,
  csKOI8T,
  csBigFive,
  csGeorgianAcademy,
  csGeorgianPS,
  csGEOSTD8,
  csARMSCII_8,
  csVISCII,
  csAtariST,
  csHPRoman8,
  csNextStep,

  csMacCeltic,
  csMacCentralEuropean,
  csMacCroatian,
  csMacCyrillic,
  csMacGaelic,
  csMacGreek,
  csMacHebrew,
  csMacIcelandic,
  csMacRoman,
  csMacRomanian,
  csMacThai,
  csMacTurkish,
   {$endif}
   {$endif}
  SBChSConv,
  
  SBChSConvBase
  ;



implementation


end.
