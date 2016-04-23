{$I SecBbox.inc}

{$UNDEF _MAKE_RESOURCES_}
{$UNDEF _USED_RESOURCES_}
{$UNDEF _USES_RESOURCES_}
{$UNDEF _RESNET_SERIALIZABLE_}
{$UNDEF _STRING_RESOURCES_}

{$IFDEF SB_NET}
  {$DEFINE _USED_RESOURCES_} // Include Charsets Resources.
  {$IFDEF NET_CF}
    {.$DEFINE _STRING_RESOURCES_}
  {$ENDIF}
  {$IFDEF SB_WINRT}
    {$DEFINE _STRING_RESOURCES_}
  {$ENDIF}
  // .Net Serialization option:
  {.$DEFINE _RESNET_SERIALIZABLE_} // Not recommended it option (Resources are dependent from current assembly (project name, etc) ).
{$ELSE}
  {.$DEFINE _USED_RESOURCES_} // Include Charsets Resources. Not recommended it options for not .Net platform.
{$ENDIF}

{$IFDEF SB_JAVA}
  {$DEFINE _USED_RESOURCES_}
  //{$DEFINE _MAKE_RESOURCES_}
{$ENDIF}

// Developer Options begin:
// ***********************
{$IFNDEF _USED_RESOURCES_}

  {.$DEFINE _MAKE_RESOURCES_}
  (*

    // Delphi 4,5,6,7
    // For generation Resource File ".res" need call procedure: "SerializeRegisteredCharsets()"
    --- compile resource bath file "Compile_rc.bat" ---
    @echo off
    call make_prj.bat 7 ?
    BRCC32.EXE SecureBlackbox.Unicode.rc
    if %ERRORLEVEL% == 0 goto L_OK
    echo ERROR: (%ERRORLEVEL%)
    goto L_EXIT
    :L_OK
    echo Done.
    :L_EXIT
    exit
    ---------------------------------------------------
    >Compile_rc.bat

    // .Net:
    //
    // For generation XML Resource File ".resx" need call procedure: "SerializeRegisteredCharsets()"
    -- compile resource bath file "Compile_ResX.bat" --
    @echo off
    set DOT_NET_SDK_ROOT_DIR=H:\PROGRAMs\DEV\Miscrosoft\VS.NET.2003\SDK\v1.1
    set path=%DOT_NET_SDK_ROOT_DIR%\Bin;%path%

    resGen.exe EldoS.SecureBlackbox.Unicode.struct.resx
    ---------------------------------------------------

    >Compile_ResX.bat

  *)
  {$UNDEF _MAKE_RESOURCES_BINARY_}
  {$IFDEF _MAKE_RESOURCES_}
    // todo: do not correctly generated binary resource
    {.$DEFINE _MAKE_RESOURCES_BINARY_} // For generation binary resource ".resources"
  {$ENDIF}

{$ENDIF IFNDEF _USED_RESOURCES_}
// Developer Options end.
// ***********************

{$ifdef SB_CHARSET_BUILDER}
  {$UNDEF _USED_RESOURCES_}
  {$define _MAKE_RESOURCES_}
{$endif}

{$ifdef _MAKE_RESOURCES_}
  {$ifdef NET_CF_RESOURCES}
    {$define _STRING_RESOURCES_}
  {$endif}
{$endif}

{$IFDEF _MAKE_RESOURCES_}
  {$DEFINE _USES_RESOURCES_}
{$ENDIF}
{$IFDEF _USED_RESOURCES_}
  {$DEFINE _USES_RESOURCES_}
{$ENDIF}

{$ifdef SB_REDUCED_CHARSETS}
  {$undef _USED_RESOURCES_}
{$endif}

{$ifndef SB_JAVA}
{$ifndef SB_NET}
{$J-,B-}
{$endif}
{$endif}