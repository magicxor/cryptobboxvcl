// This define tells the compiler that we are building CryptoBlackbox

{$define SB_CRYPTOPKG}

(****************************************

Compiler- and platform-specific defines

****************************************)

{$ifdef cpujvm} 
  {$ifndef SB_JAVA} 
    {$define SB_JAVA}
  {$endif}
{$endif}

{$ifndef CHROME}
	{$ifdef OXYGENE}
		{$define CHROME}
	{$endif}
	{$ifdef PRISM}
		{$define CHROME}
	{$endif}
{$endif}

{$ifdef CHROME}
	{$ifndef CLR}
		{$define CLR}
	{$endif}

	{.$ifdef OXYGENE52}
		{$define SB_NO_CLASS_VARS}
		{$define SB_NO_NET_TYPEARRAYDIMENSIONS}
	{.$endif}
{$endif}

{$ifdef CLR}
    {$DEFINE DELPHI_NET}
    {$define SB_NO_COMPONENT}  // Removes TComponent dependency in some units
    {$DEFINE NET_registered}
    {$define SB_NET_DESKTOP}
    {$define SB_NET}
{$endif}

{$ifdef MONO}
  {$undef SB_NET_DESKTOP}
{$endif}

{$ifdef NET_CF}
  {$undef SB_NET_DESKTOP}
  {$define SB_WINDOWS}
{$endif}

{$ifdef SILVERLIGHT}
  {$undef SB_NET_DESKTOP}
  {$define SB_WINDOWS}
{$endif}

{$ifdef MAC}
  {$define MACOS}
{$endif}

{$ifdef DARWIN}
  {$define MACOS}
{$endif}

{$ifndef SB_NET}
  {$ifndef WIN32}
    {$ifndef LINUX}
      {$ifndef MACOS}
        {$ifndef ANDROID}
          {$define WIN32}
          {$define SB_WINDOWS}
        {$endif}
      {$endif}
    {$endif}
  {$endif}
{$endif}

{$ifdef LINUX}
  {$undef WIN32}
  {$undef WIN64}
  {$undef SB_WINDOWS}
{$endif}

{$ifdef ANDROID}
  {$undef WIN32}
  {$undef WIN64}
  {$undef SB_WINDOWS}
{$endif}

{$ifdef MACOS}
    {$undef WIN32}
    {$undef SB_WINDOWS}
{$endif}

{$ifdef CHROME}
	{$ifndef SB_NET}
		{$define SB_NET}
	{$endif}
{$endif}

{$ifdef WIN32}
  {$define SB_X86ASM}
{$endif}

// by default we are on 32-bit CPU
{$define SB_CPU32}

{$ifdef WIN64}
  {$define CPU64}
{$endif}

{$ifdef CPU64}
  {$define SB_CPU64}
  {$undef SB_CPU32}
  {$undef SB_X86ASM}
{$endif}

{$ifdef CPUX64}
  {$define SB_CPU64}
  {$undef SB_CPU32}
  {$undef SB_X86ASM}
{$endif}

{$ifdef SB_WINCE}
  {$define SB_CPUARM}
  {$undef SB_CPU32}
  {$undef SB_X86ASM}
{$endif}

{$IFDEF FPC} // set mode only with FreePascal, since Delphi doesn't know it
  {$MODE DELPHI}
  {$IFNDEF SB_JAVA}
    {$DEFINE VER140}
  {$ENDIF}
{$ENDIF FPC}

{$ifdef LINUX}
  {$define KYLIX_USED}
  {$define CLX_USED}
{$endif}

{$ifndef FPC}
{$ifdef WIN32}
{$define HAS_WCTOMB}
{$endif}
{$endif}

// re-define platform indicators

{$ifdef WIN32}
  {$define SB_WINDOWS}
{$endif}

{$ifdef SB_NET_DESKTOP}
  {$define SB_WINDOWS}
{$endif}

{$ifdef LINUX}
  {$define SB_POSIX}
  {$define SB_LINUX}
  {$define SB_UNIX} 
{$endif}

{$ifdef MACOS}
  {$define SB_POSIX}
  {$define SB_UNIX} 
  {$define SB_MACOS}
  {$ifndef FPC}
    {$define DELPHI_MAC}
    {$define SB_DELPHI_POSIX}
  {$endif}
{$endif}


{$ifdef LINUX}
{$ifdef FPC}
  {$define FPC_UNIX}
  {$define FPC_POSIX}
{$endif}
{$endif}

{$ifdef SB_MACOS}
{$ifdef FPC}
  {$define FPC_POSIX}
  {$ifdef cpuarm}
    {$define FPC_iOS}
      {$define SB_iOS}
  {$endif}
  {$endif}
{$endif}

{$ifdef ANDROID}
  {$ifndef SB_JAVA}
  {$ifdef FPC}
    {$define FPC_UNIX}
    {$define FPC_POSIX}
    {$define FPC_ANDROID}
 
    {$define SB_ANDROID}
    {$define SB_POSIX}
    {$define SB_UNIX}
    {$define SB_LINUX}
  {$endif}
  {$endif}
{$endif}

{$ifdef DCC} // At least Delphi XE4 defines it
  {$ifdef IOS}
    {$define SB_iOS}
    {$define SB_DELPHI_IOS}
    {$define SB_DELPHI_MOBILE}
    {$define SB_DELPHI_POSIX}
    {$define SB_POSIX}
    {$define SB_UNIX}
    {$undef FPC_iOS}
  {$endif}

  {$ifdef ANDROID}
    {$define SB_ANDROID}
    {$define SB_DELPHI_ANDROID}
    {$define SB_DELPHI_MOBILE}
    {$define SB_DELPHI_POSIX}
    {$define SB_POSIX}
    {$define SB_UNIX}
    {$define SB_LINUX}
    {$undef FPC_ANDROID}
  {$endif}
{$endif}

{$ifdef SB_WINDOWS}
  {$define SB_WINDOWS_DESKTOP}
  {$define SB_WINDOWS_OR_NET}
  {$define SB_WINDOWS_OR_NET_OR_JAVA}
{$endif}

{$ifdef SB_WINCE}
  {$define SB_CONSTRAINED_DEVICE}
  {$undef SB_X86ASM}
  {$undef SB_WINDOWS_DESKTOP}
{$endif}


{$ifdef SB_NET}
  {$define SB_WINDOWS_OR_NET}
  {$define SB_WINDOWS_OR_NET_OR_JAVA}
{$endif}

{$ifdef SB_JAVA}
  {$define SB_WINDOWS_OR_NET_OR_JAVA}
{$endif}

{$ifdef android} // FPC defines this one
  {$define SB_ANDROID}

  {$ifdef SB_JAVA}
    {$define SB_ANDROID_JAVA}
  {$endif}
{$endif}



(****************************************

VCL version checks

****************************************)

{$ifndef SB_JAVA}// FPC compiler seems to define some VER constants

{$IFDEF VER120}
  {$DEFINE D_3_UP}
  {$DEFINE D_4_UP}
  {$DEFINE VCL40}
  {$define SB_WINDOWS}
{$ENDIF}

{$IFDEF VER125}
  {$DEFINE B_3_UP}
  {$DEFINE B_4_UP}
  {$DEFINE B_4}
  {$DEFINE VCL40}
  {$DEFINE BUILDER_USED}
  {$define SB_WINDOWS}
{$ENDIF}

{$IFDEF VER130}
    {$IFDEF BCB}
		{$DEFINE B_3_UP}
		{$DEFINE B_4_UP}
		{$DEFINE B_5_UP}
		{$DEFINE B_5}
		{$DEFINE VCL40}
		{$DEFINE VCL50}
		{$DEFINE BUILDER_USED}
    {$ELSE}
		{$DEFINE D_3_UP}
		{$DEFINE D_4_UP}
		{$DEFINE D_5_UP}
		{$DEFINE VCL40}
		{$DEFINE VCL50}
		{.DEFINE USEADO}
    {$ENDIF}
    {$define SB_WINDOWS}
{$ENDIF}

{$IFDEF VER140}
    {$IFDEF BCB}
		{$DEFINE B_3_UP}
		{$DEFINE B_4_UP}
		{$DEFINE B_5_UP}
		{$DEFINE B_6_UP}
		{$DEFINE B_6}
		{$DEFINE VCL40}
		{$DEFINE VCL50}
		{$DEFINE VCL60}
		{$DEFINE BUILDER_USED}
    {$ELSE}
		{$DEFINE D_3_UP}
		{$DEFINE D_4_UP}
		{$DEFINE D_5_UP}
		{$DEFINE D_6_UP}
		{$DEFINE D_6}
		{$DEFINE VCL40}
		{$DEFINE VCL50}
		{$DEFINE VCL60}
		{.DEFINE USEADO}
    {$ENDIF}
{$ENDIF}

{$IFDEF VER150}
    {$IFNDEF BCB}
		{$DEFINE D_3_UP}
		{$DEFINE D_4_UP}
		{$DEFINE D_5_UP}
		{$DEFINE D_6_UP}
		{$DEFINE D_7_UP}
		{$DEFINE D_7}
		{$DEFINE VCL40}
		{$DEFINE VCL50}
		{$DEFINE VCL60}
		{$DEFINE VCL70}
		{.DEFINE USEADO}
    {$ENDIF}
{$ENDIF}

{$IFDEF VER160}
    {$DEFINE D_3_UP}
    {$DEFINE D_4_UP}
    {$DEFINE D_5_UP}
    {$DEFINE D_6_UP}
    {$DEFINE D_7_UP}
    {$DEFINE D_8_UP}
    {$DEFINE D_8}
    {$DEFINE VCL40}
    {$DEFINE VCL50}
    {$DEFINE VCL60}
    {$DEFINE VCL70}
    {$DEFINE VCL80}
    {.$DEFINE USE_NAME_SPACE} // Optional !!!
{$ENDIF}

{$IFDEF VER170}
    {$DEFINE D_3_UP}
    {$DEFINE D_4_UP}
    {$DEFINE D_5_UP}
    {$DEFINE D_6_UP}
    {$DEFINE D_7_UP}
    {$DEFINE D_8_UP}
    {$DEFINE D_9_UP}
    {$DEFINE D_9}
    {$DEFINE VCL40}
    {$DEFINE VCL50}
    {$DEFINE VCL60}
    {$DEFINE VCL70}
    {$DEFINE VCL80}
    {$DEFINE VCL90}
    {.$DEFINE USE_NAME_SPACE} // Optional !!!
{$ENDIF}

{$IFDEF VER180}
  {$ifndef VER185}
    {$DEFINE D_3_UP}
    {$DEFINE D_4_UP}
    {$DEFINE D_5_UP}
    {$DEFINE D_6_UP}
    {$DEFINE D_7_UP}
    {$DEFINE D_8_UP}
    {$DEFINE D_9_UP}
    {$DEFINE D_X_UP}
    {$DEFINE D_X}
    {$DEFINE VCL40}
    {$DEFINE VCL50}
    {$DEFINE VCL60}
    {$DEFINE VCL70}
    {$DEFINE VCL80}
    {$DEFINE VCL90}
    {$DEFINE VCL100}

    {$DEFINE B_3_UP}
    {$DEFINE B_4_UP}
    {$DEFINE B_5_UP}
    {$DEFINE B_6_UP}
    {$DEFINE B_X_UP}
    {$DEFINE B_X}
    {$ifndef SB_NET}
    {$DEFINE BUILDER_USED}
    {$endif}
   {$endif}   
{$ENDIF}

{$IFDEF VER185}
    {$DEFINE D_3_UP}
    {$DEFINE D_4_UP}
    {$DEFINE D_5_UP}
    {$DEFINE D_6_UP}
    {$DEFINE D_7_UP}
    {$DEFINE D_8_UP}
    {$DEFINE D_9_UP}
    {$DEFINE D_X_UP}
    {$DEFINE D_11_UP}
    {$DEFINE D_11}
    {$DEFINE VCL40}
    {$DEFINE VCL50}
    {$DEFINE VCL60}
    {$DEFINE VCL70}
    {$DEFINE VCL80}
    {$DEFINE VCL90}
    {$DEFINE VCL100}
    {$DEFINE VCL110}
  {$IFDEF BCB}
    {$DEFINE B_3_UP}
    {$DEFINE B_4_UP}
    {$DEFINE B_5_UP}
    {$DEFINE B_6_UP}
    {$DEFINE B_X_UP}
    {$DEFINE B_11_UP}
    {$DEFINE B_11}
    {$ifndef SB_NET}
    {$DEFINE BUILDER_USED}
    {$endif}
  {$ENDIF}
{$ENDIF}

{$IFDEF VER200}
{$ifndef CHROME}
    {$DEFINE D_3_UP}
    {$DEFINE D_4_UP}
    {$DEFINE D_5_UP}
    {$DEFINE D_6_UP}
    {$DEFINE D_7_UP}
    {$DEFINE D_8_UP}
    {$DEFINE D_9_UP}
    {$DEFINE D_X_UP}
    {$DEFINE D_11_UP}
    {$DEFINE D_12_UP}
    {$DEFINE D_12}
    {$DEFINE VCL40}
    {$DEFINE VCL50}
    {$DEFINE VCL60}
    {$DEFINE VCL70}
    {$DEFINE VCL80}
    {$DEFINE VCL90}
    {$DEFINE VCL100}
    {$DEFINE VCL110}
    {$DEFINE VCL120}
  {$IFDEF BCB}
    {$DEFINE B_3_UP}
    {$DEFINE B_4_UP}
    {$DEFINE B_5_UP}
    {$DEFINE B_6_UP}
    {$DEFINE B_X_UP}
    {$DEFINE B_11_UP}
    {$DEFINE B_12_UP}
    {$DEFINE B_12}
    {$ifndef SB_NET}
    {$DEFINE BUILDER_USED}
    {$define SB_EXCLUDE_EL_ALIASES}
    {$endif}
  {$ENDIF}

  {$ifdef UNICODE}
    {$define SB_UNICODE_VCL}
  {$endif}
{$endif}
{$ENDIF}

{$IFDEF VER210}
    {$DEFINE D_3_UP}
    {$DEFINE D_4_UP}
    {$DEFINE D_5_UP}
    {$DEFINE D_6_UP}
    {$DEFINE D_7_UP}
    {$DEFINE D_8_UP}
    {$DEFINE D_9_UP}
    {$DEFINE D_X_UP}
    {$DEFINE D_11_UP}
    {$DEFINE D_12_UP}
    {$DEFINE D_14_UP}
    {$DEFINE D_14}
    {$DEFINE VCL40}
    {$DEFINE VCL50}
    {$DEFINE VCL60}
    {$DEFINE VCL70}
    {$DEFINE VCL80}
    {$DEFINE VCL90}
    {$DEFINE VCL100}
    {$DEFINE VCL110}
    {$DEFINE VCL120}
    {$DEFINE VCL130}
    {$DEFINE VCL140}
  {$IFDEF BCB}
    {$DEFINE B_3_UP}
    {$DEFINE B_4_UP}
    {$DEFINE B_5_UP}
    {$DEFINE B_6_UP}
    {$DEFINE B_X_UP}
    {$DEFINE B_11_UP}
    {$DEFINE B_12_UP}
    {$DEFINE B_14_UP}
    {$DEFINE B_14}
    {$ifndef SB_NET}
    {$DEFINE BUILDER_USED}
    {$define SB_EXCLUDE_EL_ALIASES}
    {$endif}
  {$ENDIF}
  {$ifdef UNICODE}
    {$define SB_UNICODE_VCL}
  {$endif}
{$ENDIF}

{$IFDEF VER220}
    {$DEFINE D_3_UP}
    {$DEFINE D_4_UP}
    {$DEFINE D_5_UP}
    {$DEFINE D_6_UP}
    {$DEFINE D_7_UP}
    {$DEFINE D_8_UP}
    {$DEFINE D_9_UP}
    {$DEFINE D_X_UP}
    {$DEFINE D_11_UP}
    {$DEFINE D_12_UP}
    {$DEFINE D_14_UP}
    {$DEFINE D_15_UP}
    {$DEFINE D_15}
    {$DEFINE VCL40}
    {$DEFINE VCL50}
    {$DEFINE VCL60}
    {$DEFINE VCL70}
    {$DEFINE VCL80}
    {$DEFINE VCL90}
    {$DEFINE VCL100}
    {$DEFINE VCL110}
    {$DEFINE VCL120}
    {$DEFINE VCL140}
    {$DEFINE VCL150}
  {$IFDEF BCB}
    {$DEFINE B_3_UP}
    {$DEFINE B_4_UP}
    {$DEFINE B_5_UP}
    {$DEFINE B_6_UP}
    {$DEFINE B_X_UP}
    {$DEFINE B_11_UP}
    {$DEFINE B_12_UP}
    {$DEFINE B_14_UP}
    {$DEFINE B_15_UP}
    {$DEFINE B_15}
    {$ifndef SB_NET}
    {$DEFINE BUILDER_USED}
    {$define SB_EXCLUDE_EL_ALIASES}
    {$endif}
  {$ENDIF}
  {$ifdef UNICODE}
    {$define SB_UNICODE_VCL}
  {$endif}
{$ENDIF}

{$IFDEF VER230}
    {$DEFINE D_3_UP}
    {$DEFINE D_4_UP}
    {$DEFINE D_5_UP}
    {$DEFINE D_6_UP}
    {$DEFINE D_7_UP}
    {$DEFINE D_8_UP}
    {$DEFINE D_9_UP}
    {$DEFINE D_X_UP}
    {$DEFINE D_11_UP}
    {$DEFINE D_12_UP}
    {$DEFINE D_14_UP}
    {$DEFINE D_15_UP}
    {$DEFINE D_16_UP}
    {$DEFINE D_16}
    {$DEFINE VCL40}
    {$DEFINE VCL50}
    {$DEFINE VCL60}
    {$DEFINE VCL70}
    {$DEFINE VCL80}
    {$DEFINE VCL90}
    {$DEFINE VCL100}
    {$DEFINE VCL110}
    {$DEFINE VCL120}
    {$DEFINE VCL140}
    {$DEFINE VCL150}
    {$DEFINE VCL160}
  {$IFDEF BCB}
    {$DEFINE B_3_UP}
    {$DEFINE B_4_UP}
    {$DEFINE B_5_UP}
    {$DEFINE B_6_UP}
    {$DEFINE B_X_UP}
    {$DEFINE B_11_UP}
    {$DEFINE B_12_UP}
    {$DEFINE B_14_UP}
    {$DEFINE B_15_UP}
    {$DEFINE B_16_UP}
    {$DEFINE B_16}
    {$ifndef SB_NET}
    {$DEFINE BUILDER_USED}
    {$define SB_EXCLUDE_EL_ALIASES}
    {$endif}
  {$ENDIF}
  {$ifdef UNICODE}
    {$define SB_UNICODE_VCL}
  {$endif}
{$ENDIF}

{$IFDEF VER240}
    {$DEFINE D_3_UP}
    {$DEFINE D_4_UP}
    {$DEFINE D_5_UP}
    {$DEFINE D_6_UP}
    {$DEFINE D_7_UP}
    {$DEFINE D_8_UP}
    {$DEFINE D_9_UP}
    {$DEFINE D_X_UP}
    {$DEFINE D_11_UP}
    {$DEFINE D_12_UP}
    {$DEFINE D_14_UP}
    {$DEFINE D_15_UP}
    {$DEFINE D_16_UP}
    {$DEFINE D_17_UP}
    {$DEFINE D_17}
    {$DEFINE VCL40}
    {$DEFINE VCL50}
    {$DEFINE VCL60}
    {$DEFINE VCL70}
    {$DEFINE VCL80}
    {$DEFINE VCL90}
    {$DEFINE VCL100}
    {$DEFINE VCL110}
    {$DEFINE VCL120}
    {$DEFINE VCL140}
    {$DEFINE VCL150}
    {$DEFINE VCL160}
    {$DEFINE VCL170}
  {$IFDEF BCB}
    {$DEFINE B_3_UP}
    {$DEFINE B_4_UP}
    {$DEFINE B_5_UP}
    {$DEFINE B_6_UP}
    {$DEFINE B_X_UP}
    {$DEFINE B_11_UP}
    {$DEFINE B_12_UP}
    {$DEFINE B_14_UP}
    {$DEFINE B_15_UP}
    {$DEFINE B_16_UP}
    {$DEFINE B_17_UP}
    {$DEFINE B_17}
    {$ifndef SB_NET}
    {$DEFINE BUILDER_USED}
    {$define SB_EXCLUDE_EL_ALIASES}
    {$endif}
  {$ENDIF}
  {$ifdef UNICODE}
    {$define SB_UNICODE_VCL}
  {$endif}
{$ENDIF}

{$IFDEF VER250}
    {$DEFINE D_3_UP}
    {$DEFINE D_4_UP}
    {$DEFINE D_5_UP}
    {$DEFINE D_6_UP}
    {$DEFINE D_7_UP}
    {$DEFINE D_8_UP}
    {$DEFINE D_9_UP}
    {$DEFINE D_X_UP}
    {$DEFINE D_11_UP}
    {$DEFINE D_12_UP}
    {$DEFINE D_14_UP}
    {$DEFINE D_15_UP}
    {$DEFINE D_16_UP}
    {$DEFINE D_17_UP}
    {$DEFINE D_18_UP}
    {$DEFINE D_18}
    {$DEFINE VCL40}
    {$DEFINE VCL50}
    {$DEFINE VCL60}
    {$DEFINE VCL70}
    {$DEFINE VCL80}
    {$DEFINE VCL90}
    {$DEFINE VCL100}
    {$DEFINE VCL110}
    {$DEFINE VCL120}
    {$DEFINE VCL140}
    {$DEFINE VCL150}
    {$DEFINE VCL160}
    {$DEFINE VCL170}
    {$DEFINE VCL180}
  {$IFDEF BCB}
    {$DEFINE B_3_UP}
    {$DEFINE B_4_UP}
    {$DEFINE B_5_UP}
    {$DEFINE B_6_UP}
    {$DEFINE B_X_UP}
    {$DEFINE B_11_UP}
    {$DEFINE B_12_UP}
    {$DEFINE B_14_UP}
    {$DEFINE B_15_UP}
    {$DEFINE B_16_UP}
    {$DEFINE B_17_UP}
    {$DEFINE B_18_UP}
    {$DEFINE B_18}
    {$ifndef SB_NET}
    {$DEFINE BUILDER_USED}
    {$define SB_EXCLUDE_EL_ALIASES}
    {$endif}
  {$ENDIF}

  {$ifdef UNICODE}
    {$define SB_UNICODE_VCL}
  {$endif}
{$ENDIF}

{$IFDEF VER260}
    {$DEFINE D_3_UP}
    {$DEFINE D_4_UP}
    {$DEFINE D_5_UP}
    {$DEFINE D_6_UP}
    {$DEFINE D_7_UP}
    {$DEFINE D_8_UP}
    {$DEFINE D_9_UP}
    {$DEFINE D_X_UP}
    {$DEFINE D_11_UP}
    {$DEFINE D_12_UP}
    {$DEFINE D_14_UP}
    {$DEFINE D_15_UP}
    {$DEFINE D_16_UP}
    {$DEFINE D_17_UP}
    {$DEFINE D_18_UP}
    {$DEFINE D_19_UP}
    {$DEFINE D_19}
    {$DEFINE VCL40}
    {$DEFINE VCL50}
    {$DEFINE VCL60}
    {$DEFINE VCL70}
    {$DEFINE VCL80}
    {$DEFINE VCL90}
    {$DEFINE VCL100}
    {$DEFINE VCL110}
    {$DEFINE VCL120}
    {$DEFINE VCL140}
    {$DEFINE VCL150}
    {$DEFINE VCL160}
    {$DEFINE VCL170}
    {$DEFINE VCL180}
    {$DEFINE VCL190}
  {$IFDEF BCB}
    {$DEFINE B_3_UP}
    {$DEFINE B_4_UP}
    {$DEFINE B_5_UP}
    {$DEFINE B_6_UP}
    {$DEFINE B_X_UP}
    {$DEFINE B_11_UP}
    {$DEFINE B_12_UP}
    {$DEFINE B_14_UP}
    {$DEFINE B_15_UP}
    {$DEFINE B_16_UP}
    {$DEFINE B_17_UP}
    {$DEFINE B_18_UP}
    {$DEFINE B_19_UP}
    {$DEFINE B_19}
    {$ifndef SB_NET}
    {$DEFINE BUILDER_USED}
    {$define SB_EXCLUDE_EL_ALIASES}
    {$endif}
  {$ENDIF}

  {$ifdef UNICODE}
    {$define SB_UNICODE_VCL}
  {$endif}
{$ENDIF}

{$IFDEF VER290}
    {$DEFINE D_3_UP}
    {$DEFINE D_4_UP}
    {$DEFINE D_5_UP}
    {$DEFINE D_6_UP}
    {$DEFINE D_7_UP}
    {$DEFINE D_8_UP}
    {$DEFINE D_9_UP}
    {$DEFINE D_X_UP}
    {$DEFINE D_11_UP}
    {$DEFINE D_12_UP}
    {$DEFINE D_14_UP}
    {$DEFINE D_15_UP}
    {$DEFINE D_16_UP}
    {$DEFINE D_17_UP}
    {$DEFINE D_18_UP}
    {$DEFINE D_19_UP}
    {$DEFINE D_20_UP}
    {$DEFINE D_20}
    {$DEFINE VCL40}
    {$DEFINE VCL50}
    {$DEFINE VCL60}
    {$DEFINE VCL70}
    {$DEFINE VCL80}
    {$DEFINE VCL90}
    {$DEFINE VCL100}
    {$DEFINE VCL110}
    {$DEFINE VCL120}
    {$DEFINE VCL140}
    {$DEFINE VCL150}
    {$DEFINE VCL160}
    {$DEFINE VCL170}
    {$DEFINE VCL180}
    {$DEFINE VCL190}
    {$DEFINE VCL200}
  {$IFDEF BCB}
    {$DEFINE B_3_UP}
    {$DEFINE B_4_UP}
    {$DEFINE B_5_UP}
    {$DEFINE B_6_UP}
    {$DEFINE B_X_UP}
    {$DEFINE B_11_UP}
    {$DEFINE B_12_UP}
    {$DEFINE B_14_UP}
    {$DEFINE B_15_UP}
    {$DEFINE B_16_UP}
    {$DEFINE B_17_UP}
    {$DEFINE B_18_UP}
    {$DEFINE B_19_UP}
    {$DEFINE B_20_UP}
    {$DEFINE B_20}
    {$ifndef SB_NET}
    {$DEFINE BUILDER_USED}
    {$define SB_EXCLUDE_EL_ALIASES}
    {$endif}
  {$ENDIF}

  {$ifdef UNICODE}
    {$define SB_UNICODE_VCL}
  {$endif}
{$ENDIF}


{$endif} // ifndef SB_JAVA

{$IFDEF D_7_UP}
  {$WARN UNSAFE_CODE OFF}
  {$WARN UNSAFE_TYPE OFF}
  {$WARN UNSAFE_CAST OFF}
{$ENDIF}

{$ifdef BUILDER_USED}
  {$OBJEXPORTALL ON}
{$endif}

{$ifdef VCL40}
	{$define SB_VCL}
{$endif}

{$ifdef VCL50}
	{$define SB_VCL}
{$endif}

{$ifdef VCL60}
	{$define SB_VCL}
{$endif}

{$ifdef VCL70}
  {$define SB_VCL}
{$endif}

{$ifdef SB_VCL}

  {$ifdef SB_DELPHI_MOBILE}
    {$define SB_UNICODE}
    {$HIGHCHARUNICODE ON}
  {$endif}

  {$ifndef SB_UNICODE_VCL}
    {$define SB_ANSI_VCL}
    {$define SB_ANSI}
  {$endif}

  {$ifdef SB_UNICODE_VCL}
    {$define SB_UNICODE_WINAPI}
  {$endif}

  {$define SB_PASCAL_STRINGS} // Specifies that 1-based pascal strings are used

  {$ifdef BCB}
    {$define SB_NO_DEFAULT_BYTEARRAY_PARAMS}
  {$endif}

{$endif}

{$ifdef SB_JAVA}
  {$define SB_PASCAL_STRINGS} // Specifies that 1-based pascal strings are used
{$endif}

(****************************************

SecureBlackbox defines

****************************************)

{.$DEFINE SECURE_BLACKBOX_DEBUG}

// Deflate64 compression algorithm support
{$define SB_DEFLATE64}

{$ifndef SB_NO_NTLM_SUPPORT}
{$DEFINE SB_NTLM_SUPPORT}
{$endif}

// GOST cryptoalgorithm support
{$define SB_HAS_GOST}

// ECC cryptoalgorithm support
{$define SB_HAS_ECC}

// support for CJK and other complex charsets
{$DEFINE COMPLEXENCODING_SUPPORT} 

// XML must use Charset library
{$ifndef SB_NO_CHARSETS}
	{$define SB_XML_USE_CHARSETS}
{$endif}

// include ability to create self-extractable pgp-encrypted files
{$define SB_PGPSFX}

// the following must be defined ONLY WHILE a stub for pgp sfx is being built
// this is supported for Win32 platform only
{.$define SB_PGPSFX_STUB}

// include IPv6 support
{$define SB_IPv6}

// include DNSSEC support
{$ifndef SB_NO_DNSSEC}
{$define SB_DNSSEC}
{$endif}

// include GSSAPI
{$define SB_GSSAPI}

// include CryptoAPI and Windows Certificate Storage
{$define SB_HAS_WINCRYPT}

// include CryptUI
{$define SB_HAS_CRYPTUI}

// DC components included
{$ifndef SB_NO_DC}
{$define SB_HAS_DC}
{$endif}

// HTTPAuth module is included. So far only digest auth. is supported in Java, MacOS X and Linux
{$define SB_HAS_HTTPAUTH}

{$ifndef SB_HAS_HTTPAUTH}
{$undef SB_NTLM_SUPPORT}
{$endif}

// OAuth is used in HTTP client
{$define SB_HAS_OAUTH}

// default parameters enabled
{$define HAS_DEF_PARAMS}
 
// CNG support on Windows Vista and later
{$define SB_HAS_CNG}

// optional defines to exclude certain algorithms
{.$define SB_NO_BZIP}
{.$define SB_NO_DES}
{.$define SB_NO_RC2}
{.$define SB_NO_RC4}
{.$define SB_NO_IDEA}
{.$define SB_NO_CAMELLIA}
{.$define SB_NO_SEED}
{.$define SB_NO_SRP}
{.$define SB_EXCL_XADES_INTF}

// this define controls language-specific problem with nested arrays of arrays
{$undef TriDES_KEY_AS_REC}

// include SSH Server shell handler
{$define SB_WINDOWS_SHELL}

{$define SB_BUFFERTYPE_IS_BYTEARRAY}

{$ifdef SB_JAVA}
  {$define SB_NO_BYTEARRAY_CONST_ARRAYS}
{$endif}

{$ifdef SB_VCL}
  {$define SB_NO_BYTEARRAY_CONST_ARRAYS}
{$endif}

{$ifndef SB_JAVA}
  {$ifdef SB_VCL}
    {$define SB_SSH_PUBKEYAGENT}
  {$else}
    {$ifdef SB_NET_DESKTOP}
      {$define SB_SSH_PUBKEYAGENT}
    {$endif}
  {$endif}  
{$endif}

{$ifdef SB_DELPHI_MOBILE}
  {$define SB_CONSTRAINED_DEVICE}
  {$undef SB_PASCAL_STRINGS}
  {$undef SB_SSH_PUBKEYAGENT}
  {$undef SB_GSSAPI}
  {$ifdef VCL200}
  {$define SB_NO_CHAR_VARIANTS}
  {$endif}
{$endif}

{$ifdef NET_2_0_UP}
	{$define SB_HAS_X509CERTIFICATE2}
{$endif}

{$ifdef SB_EXCL_XADES}
  {$define SB_EXCL_XADES_INTF}
{$endif}

{$ifdef SB_NET}
  // define support for Regex in .NET
  {$define SB_REGEX}
  // IIS intergration support for WebDAV server
  {$define SB_IIS_SUPPORT}
  // use the workaround for UNC paths in DiskFSAdapter
  {$define SB_NET_UNC_WORKAROUND}
{$endif}

// define support for Regex in Delphi XE and later
{$ifdef D_15_UP}
  {$define SB_REGEX}
{$endif}

{$IFDEF VER185}
  {.$define SB_NO_ARRAYPROPS}
{$ENDIF}

{$IFDEF BUILDER_USED}
  {$define SB_NO_ARRAYPROPS}
{$ENDIF}


{$ifdef SB_VCL}
{.$hints off}
{.$warnings off}
  {$ifdef VCL120}
  {$WARN DUPLICATE_CTOR_DTOR OFF}
  {$ifdef SB_DELPHI_MOBILE}
    {$WARN SYMBOL_DEPRECATED OFF}
    {$WARN SYMBOL_PLATFORM OFF}
  {$endif}
  {$endif}
{$endif} 


(****************************************

Platform-specific exclusions

****************************************)

{$ifdef SB_VCL}
  {.$undef SB_HAS_CNG}

  {$ifndef FPC}
    {$Q-,R-,I-,J-}
  {$endif}

{$endif}

{$define SB_USE_NAMED_EVENTS}

{$ifdef SB_ANDROID}
  {$define SB_CONSTRAINED_DEVICE}
{$endif}

{$ifdef SB_WINCE}
  {$define SB_CONSTRAINED_DEVICE}  
  {$define SB_UNICODE_WINAPI}
  {$define SB_NO_PGPSFX_STUB}

  {$undef SB_NTLM_SUPPORT}
  {$undef SB_DNSSEC}
  {.$undef SB_GSSAPI}
  {$undef SB_SSH_PUBKEYAGENT}
  {$undef SB_PGPSFX}
  {$undef SB_PGPSFX_STUB}
  {$undef SB_WINDOWS_SHELL}
{$endif}

{$ifdef NET_1_0}
  {$undef SB_HAS_CNG}
  {$undef SB_IIS_SUPPORT}
{$endif}

{$ifdef NET_CF}

  {.$define SB_NO_PKCS11}
  {$define SB_NO_VS_TOOLBOX}
  {$define SB_NO_NET_REFLECTION}
  {$define SB_NO_NET_DESIGN}
  {$define SB_NO_NET_RWLOCK}
  {$define SB_NO_NET_MARSHALBYREF}
  {$define SB_NO_NET_WINDOWSFORMS}
  {$define SB_NO_NET_BROWSABLE}
  {$define SB_NO_NET_THREADRESUME}
  {$define SB_NO_NET_SERIALIZABLE}
  {$define SB_NO_NET_EXPOBJCONV}
  {$define SB_NO_NET_RECORDFIELDALIGNMENT}
  {$define SB_NO_NET_UNSAFEADDROFPINNEDARRAYELEMENT}
  {$define SB_NO_NET_COM_STRINGS}
  {$define SB_NO_NET_ANSI_CHARSET}
  {$define SB_NO_NET_DESCRIPTION}
  {$define SB_NO_NET_SHORTENED_ENCODING_GETSTRING}

  {.$undef SB_NTLM_SUPPORT}
  {$undef SB_PGPSFX}

  {$undef SB_WINDOWS_SHELL}
  {$undef SB_NET_DESKTOP}
  {$undef SB_IIS_SUPPORT}
  {$undef SB_HAS_CRYPTUI}
  {$undef SB_HAS_CNG}
  {$undef SB_NET_UNC_WORKAROUND}

  {$ifdef NET_CF_1_0}
    {$define TriDES_KEY_AS_REC}
    {$undef SB_IPv6}
    {$undef SB_DNSSEC}
    {$define SB_NO_NET_STATICARRAYS}
    {$define SB_NO_NET_COM_MEMORY_ALLOC}
    {$define SB_NO_NET_DATETIME_OADATE}
  {$endif}

  {$define SB_CONSTRAINED_DEVICE}
{$endif}

// Windows phone-specific defines

// Silverlight-specific defines
{$ifdef SILVERLIGHT}
  {$define SB_NO_PKCS11}
  {$define SB_NO_VS_TOOLBOX}
  {$define SB_NO_NET_REFLECTION}
  {$define SB_NO_NET_DESIGN}
  {$define SB_NO_NET_RWLOCK}
  {$define SB_NO_NET_MARSHALBYREF}
  {$define SB_NO_NET_WINDOWSFORMS}
  {$define SB_NO_NET_COMPONENT}
  {$define SB_NO_THREADPRIORITY}
  {$define SB_NO_NET_ARRAYLIST}
  {$define SB_NO_NET_BROWSABLE}
  {$define SB_NO_NET_ASCII_ENCODING}
  {$define SB_NO_NET_INTEROP}
  {$define SB_NO_NET_THREADRESUME}
  {$define SB_NO_REGISTRY}
  {$define SB_NO_NET_SERIALIZABLE}
  {$define SB_NO_NET_EXPOBJCONV}
  {$define SB_NO_NET_COM_MEMORY_ALLOC}
  {$define SB_NO_NET_PINVOKE}
  {$define SB_NO_NET_ARRAYLIST}
  {$define SB_NO_NET_DEFAULTENCODING}
  {$define SB_NO_NET_HASHTABLE}
  {$define SB_NO_NET_MICROSOFT_WIN32}

  {$define SB_SILVERLIGHT_SOCKETS}
  {$define SB_IMPORT_COLLECTIONS_GENERIC}
  {$define SB_NO_NET_LEGACY_STRINGCOMPARE}
  {$define SB_NO_NET_EXITCONTEXT_WAITONE}
  {$define SB_NO_NET_UTF32_ENCODING}
  {$define SB_NO_NET_ENCODING_CODES}
  {$define SB_NO_NET_CREATESPECIFICCULTURE}
  {$define SB_NO_NET_TIMEZONE}
  {$define SB_NO_NET_ARRAYLIST_TO_ARRAY}
  {$define SB_NO_SSPI}

  {.$undef SB_HAS_GOST}
  {$undef SB_HAS_WINCRYPT}
  {$undef SB_HAS_CRYPTUI}
  {$undef SB_PGPSFX}
  {$undef SB_GSSAPI}
  {$undef SB_NTLM_SUPPORT}
  {$undef SB_HAS_HTTPAUTH}
  {$undef SB_IPv6}
  {$undef SB_NET_DESKTOP}
  {$undef SB_DNSSEC}
  {$undef SB_WINDOWS_SHELL}
  {$undef SB_HAS_CNG}
  {$undef SB_IIS_SUPPORT}
  {$undef SB_NET_UNC_WORKAROUND}

  {$ifdef SILVERLIGHT40}
    {$define SB_NO_NET_DIRECTORY_BROWSING}
  {$endif}

  {$ifdef SILVERLIGHT50_WINDOWS}
    {$undef SB_NO_NET_PINVOKE}
    {$undef SB_NO_NET_INTEROP}
    {$undef SB_NO_PKCS11}
    {$undef SB_NO_SSPI}

    {$define SB_NTLM_SUPPORT}
    {$define SB_HAS_HTTPAUTH}
    {$define SB_HAS_WINCRYPT}

    {$define SB_NO_NET_COM_STRINGS}
    {$define SB_NO_NET_UNSAFEADDROFPINNEDARRAYELEMENT}
  {$endif}

  {$ifdef SILVERLIGHT50_XPLATFORM}
    {$undef SB_HAS_WINCRYPT}
  {$endif}

{$endif}

{$ifdef NET_4_5_UP}
  {.$define SB_NO_SYSTEM_SECURITY_PERMISSIONS}

  {.$define SB_NO_NET_MICROSOFT_WIN32}
  {.$define SB_NO_SYSTEM_SECURITY_CRYPTOGRAPHY}
  {.$undef SB_HAS_X509CERTIFICATE2}

  {.$define SB_NO_DNSSEC}
  {.$undef SB_DNSSEC}

  {.$define SB_NO_NET_COMPONENT}
  {.$define SB_NO_NET_ARRAYLIST}
  {.$define SB_NO_NET_MARSHALBYREF}
  {.$define SB_NO_NET_WINDOWSFORMS}
  {.$define SB_NO_NET_DESIGN}
  {.$define SB_NO_NET_ICOMPARERTPL}
  {.$define SB_NO_FILESTREAM}
  {.$define SB_NO_NET_SERIALIZABLE}
  {.$define SB_NO_NET_HASHTABLE}
  {.$define SB_NO_NET_THREADS}

  //{$define SB_NO_NET_TYPEARRAYDIMENSIONS}
  {$define SB_NO_OPENARRAY_SET_ASSIGNMENT}
{$endif}

{$ifdef SB_WINRT}
  {$define SB_NO_SYSTEM_SECURITY_PERMISSIONS}

  {$define SB_NO_NET_MICROSOFT_WIN32}
  {$define SB_NO_SYSTEM_SECURITY_CRYPTOGRAPHY}
  {$undef SB_HAS_X509CERTIFICATE2}

  {$define SB_NO_DNSSEC}
  {$undef SB_DNSSEC}
 
  {$undef SB_NTLM_SUPPORT}
  {$undef SB_NET_UNC_WORKAROUND}

  {$define SB_NO_VS_TOOLBOX}
  {$define SB_NO_REGISTRY}
  {$define SB_NO_NET_COMPONENT}
  {$define SB_NO_NET_ARRAYLIST}
  {$define SB_NO_NET_MARSHALBYREF}
  {$define SB_NO_NET_WINDOWSFORMS}
  {$define SB_NO_NET_DESIGN}
  {$define SB_NO_FILESTREAM}
  {$define SB_NO_NET_SERIALIZABLE}
  {$define SB_NO_NET_HASHTABLE}
  {$define SB_NO_NET_THREADS}
  {$define SB_NO_NET_REFLECTION}
  {$define SB_NO_THREADPRIORITY}
  {$define SB_NO_NET_RWLOCK}
  {$define SB_NO_NET_BROWSABLE}
  {$define SB_NO_NET_DESCRIPTION}
  {$define SB_NO_NET_PINVOKEAUTOCHARSET}
  {$define SB_NO_NET_DEFAULTENCODING}
  {$define SB_NO_NET_ASCII_ENCODING}
  {$define SB_NO_NET_LEGACY_STRINGCOMPARE}
  {$define SB_NO_NET_DATETIME_OADATE}
  {$define SB_NO_NET_CONSOLE}
  {$define SB_NO_NET_ICOMPARER_SORT}
  {$define SB_NO_NET_STREAM_CLOSE}
  {$define NO_STRING_COMPARISON}
  {$define SB_NO_NET_EXITCONTEXT_WAITONE}
  {$define SB_NO_NET_UTF32_ENCODING}
  {$define SB_NO_SYSTEM_SECURITY_PERMISSIONS}
  {$define SB_NO_NET_SHORTENED_ENCODING_GETSTRING}

  {$ifdef SB_WINSTORE}
	{$undef SB_HAS_WINCRYPT}
    {$undef SB_HAS_HTTPAUTH}
	{$undef SB_GSSAPI}

	{$define SB_NO_PKCS11}
	{$define SB_NO_SSPI}
	{$define SB_NO_NET_PINVOKE}
  {$endif}

  //{$define SB_NO_NET_SOCKETS}
  {$define SB_WINRT_SOCKETS}

  {$define SB_NO_WITH_CLAUSE}
  {$define SB_NO_NET_ENCODING_CODES}
  {$define SB_NO_NET_STRING_COPY}
  {$define SB_NO_NET_CREATESPECIFICCULTURE}
  //{$define SB_SILVERLIGHT_SOCKETS}
  {$define SB_NO_NET_EXPOBJCONV}
  {$define SB_NO_NET_TIMEZONE}
  {$define SB_NO_NET_ARRAYLIST_TO_ARRAY}
  {$define SB_NO_NET_THREADRESUME}

  {$undef SB_NET_DESKTOP}
  {$undef SB_PGPSFX}
  {$undef SB_WINDOWS_SHELL}
  {$undef SB_SSH_PUBKEYAGENT}
{$endif}

{$ifdef WP}
  {$define SB_NO_NET_SOCKETS}
  {$define SB_NO_NET_RECORDFIELDALIGNMENT}
  {$define SB_NO_NET_STATICARRAYS}
  {$define SB_NO_BOOLEAN_VAR_PARAMS}
  {$define SB_NO_WITH_CLAUSE}
  {$ifdef WP75}
    {$undef SB_NO_NET_SOCKETS}
    {$undef SB_NO_NET_INTEROP}
    {$undef SB_NO_NET_DIRECTORY_BROWSING}
    {$define SB_NO_NET_COM_STRINGS}
    {$define SB_NO_NET_UNSAFEADDROFPINNEDARRAYELEMENT}
    {$define SB_NO_NET_ANSI_CHARSET}
  {$endif}
  {$define SB_CONSTRAINED_DEVICE}
  {$undef SB_IIS_SUPPORT}
  {$undef SB_HAS_CRYPTUI}
  {$undef SB_NET_UNC_WORKAROUND}

  {$define SB_WP7_OR_WP8}
{$endif}

{$ifdef WP8}
  {$define SB_WINRT_SOCKETS}
  {$define SB_NO_BOOLEAN_VAR_PARAMS}
  {$define SB_NO_WITH_CLAUSE}
  {$undef SB_NO_NET_INTEROP}
  {$undef SB_NO_NET_DIRECTORY_BROWSING}
  //{$define SB_NO_NET_COM_STRINGS}
  //{$define SB_NO_NET_UNSAFEADDROFPINNEDARRAYELEMENT}
  //{$define SB_NO_NET_ANSI_CHARSET}
  {$define SB_CONSTRAINED_DEVICE}
  {$undef SB_IIS_SUPPORT}
  {$undef SB_HAS_CRYPTUI}

  //{$define SB_NO_SYSTEM_SECURITY_PERMISSIONS}

  {$define SB_NO_NET_MICROSOFT_WIN32}
  {$define SB_NO_SYSTEM_SECURITY_CRYPTOGRAPHY}
  {$undef SB_HAS_X509CERTIFICATE2}

  {$define SB_NO_DNSSEC}
  {$undef SB_DNSSEC}
  
  {$undef SB_NTLM_SUPPORT}

  {$undef SB_NET_UNC_WORKAROUND}

  {$define SB_NO_VS_TOOLBOX}
  {$define SB_NO_REGISTRY}
  {$define SB_NO_NET_COMPONENT}
  {$define SB_NO_NET_ARRAYLIST}
  {$define SB_NO_NET_MARSHALBYREF}
  {$define SB_NO_NET_WINDOWSFORMS}
  {$define SB_NO_NET_DESIGN}
  //{$define SB_NO_FILESTREAM}
  {$define SB_NO_NET_SERIALIZABLE}
  {$define SB_NO_NET_HASHTABLE}
  //{$define SB_NO_NET_THREADS}
  {$define SB_NO_NET_REFLECTION}
  {$define SB_NO_THREADPRIORITY}
  {$define SB_NO_NET_RWLOCK}
  //{$define SB_NO_NET_BROWSABLE}
  //{$define SB_NO_NET_DESCRIPTION}
  //{$define SB_NO_NET_PINVOKEAUTOCHARSET}
  {$define SB_NO_NET_DEFAULTENCODING}
  {$define SB_NO_NET_ASCII_ENCODING}
  {$define SB_NO_NET_LEGACY_STRINGCOMPARE}
  //{$define SB_NO_NET_DATETIME_OADATE}
  //{$define SB_NO_NET_CONSOLE}
  //{$define SB_NO_NET_ICOMPARER_SORT}
  //{$define SB_NO_NET_STREAM_CLOSE}
  //{$define NO_STRING_COMPARISON}
  {$define SB_NO_NET_EXITCONTEXT_WAITONE}
  {$define SB_NO_NET_UTF32_ENCODING}
  //{$define SB_NO_SYSTEM_SECURITY_PERMISSIONS}
  {$define SB_NO_NET_SHORTENED_ENCODING_GETSTRING}

  {$undef SB_HAS_WINCRYPT}
  {$undef SB_HAS_HTTPAUTH}
  {$undef SB_GSSAPI}

  {$define SB_NO_PKCS11}
  {$define SB_NO_SSPI}
  {$define SB_NO_NET_PINVOKE}

  //{$define SB_NO_WITH_CLAUSE}
  {$define SB_NO_NET_ENCODING_CODES}
  //{$define SB_NO_NET_STRING_COPY}
  //{$define SB_NO_NET_CREATESPECIFICCULTURE}
  {$define SB_NO_NET_EXPOBJCONV}
  {$define SB_NO_NET_TIMEZONE}
  {$define SB_NO_NET_ARRAYLIST_TO_ARRAY}
  {$define SB_NO_NET_THREADRESUME}

  {$undef SB_NET_DESKTOP}
  {$undef SB_PGPSFX}
  {$undef SB_WINDOWS_SHELL}
  {$undef SB_SSH_PUBKEYAGENT}
  {$define SB_WP7_OR_WP8}
{$endif}

{$ifdef SB_LINUX}
  {$define SB_NO_REGISTRY}
  {$define SB_HAS_MSGNOSIGNAL}

  {$undef SB_NTLM_SUPPORT}
  {$undef SB_HAS_WINCRYPT}
  {$undef SB_IPv6}
  {$undef SB_DNSSEC}
  {.$undef SB_GSSAPI}
  {$undef SB_PGPSFX}

  {$undef SB_WINDOWS_SHELL}
{$endif}

{$ifdef SB_FREEBSD}
  {$define SB_NO_REGISTRY}
  {$define SB_HAS_MSGNOSIGNAL}

  {$undef SB_NTLM_SUPPORT}
  {$undef SB_HAS_WINCRYPT}
  {$undef SB_IPv6}
  {$undef SB_DNSSEC}
  {.$undef SB_GSSAPI}
  {$undef SB_PGPSFX}

  {$undef SB_WINDOWS_SHELL}
{$endif}

{$ifdef SB_MACOS}
  {$define SB_NO_REGISTRY}

  {$undef SB_NTLM_SUPPORT}
  {$undef SB_HAS_WINCRYPT}
  {$undef SB_IPv6}
  {$undef SB_DNSSEC}
  {.$undef SB_GSSAPI}
  {$undef SB_PGPSFX}

  {$undef SB_WINDOWS_SHELL}
  {$undef SB_HAS_CNG}
{$endif}


{$ifdef MONO}
  {$define SB_NO_PKCS11}
  {$define TriDES_KEY_AS_REC}
  {$define SB_NO_NET_MICROSOFT_WIN32}
  {$define SB_NO_REGISTRY}

  {$undef SB_HAS_WINCRYPT}
  {$undef SB_WINDOWS_SHELL}
  {$undef SB_NTLM_SUPPORT}
  {$undef SB_HAS_CNG}
  {$undef SB_HAS_X509CERTIFICATE2}
  {$undef SB_IIS_SUPPORT}
  {$undef SB_SSH_PUBKEYAGENT}
  {$undef SB_PGPSFX}
  {$undef SB_NET_UNC_WORKAROUND}
{$endif}

{$ifdef NET_XAMARIN_ANDROID} // .NET code compiled with Xamarin.Android
  {$undef SB_HAS_WINCRYPT}
  {$define SB_NO_PKCS11}
  {$define SB_NO_NET_REFLECTION}
  {$define SB_NO_NET_RWLOCK}
  {$define SB_NO_NET_MARSHALBYREF}
  {$define SB_NO_NET_WINDOWSFORMS}
  {$define SB_NO_NET_PINVOKE}
  {$define SB_NO_REGISTRY}
  {$define SB_NO_NET_MICROSOFT_WIN32}

  {$undef SB_NET_DESKTOP}
  {$undef SB_NTLM_SUPPORT}
  {$define TriDES_KEY_AS_REC}
  {$undef SB_PGPSFX}
  {$undef SB_HAS_HTTPAUTH}
  {$undef SB_WINDOWS_SHELL}
  {$undef SB_HAS_X509CERTIFICATE2}
  {$undef SB_HAS_CNG}
  {$define SB_CONSTRAINED_DEVICE}
  {$undef SB_IIS_SUPPORT}
  {$undef SB_SSH_PUBKEYAGENT}
  {$undef SB_NET_UNC_WORKAROUND}
{$endif}

{$ifdef NET_XAMARIN_IOS} // .NET code compiled with Xamarin.iOS
  {$undef SB_HAS_WINCRYPT}
  {$define SB_NO_PKCS11}
  {$define SB_NO_NET_REFLECTION}
  {$define SB_NO_NET_RWLOCK}
  {$define SB_NO_NET_MARSHALBYREF}
  {$define SB_NO_NET_WINDOWSFORMS}
  {$define SB_NO_NET_PINVOKE}
  {$define SB_NO_REGISTRY}
  {$define SB_NO_NET_MICROSOFT_WIN32}

  {$undef SB_NET_DESKTOP}
  {$undef SB_NTLM_SUPPORT}
  {$define TriDES_KEY_AS_REC}
  {$undef SB_PGPSFX}
  {$undef SB_HAS_HTTPAUTH}
  {$undef SB_WINDOWS_SHELL}
  {$undef SB_HAS_X509CERTIFICATE2}
  {$undef SB_HAS_CNG}
  {$define SB_CONSTRAINED_DEVICE}
  {$undef SB_IIS_SUPPORT}
  {$undef SB_SSH_PUBKEYAGENT}
  {$undef SB_NET_UNC_WORKAROUND}
{$endif}

{$ifdef PCL} // .NET code compiled for Portable Class Library
  {$undef SB_HAS_WINCRYPT}
  {$define SB_NO_PKCS11}
  {$define SB_NO_NET_REFLECTION}
  {$define SB_NO_NET_RWLOCK}
  {$define SB_NO_NET_MARSHALBYREF}
  {$define SB_NO_NET_SOCKETS}
  {$define SB_NO_NET_WINDOWSFORMS}
  {$define SB_NO_NET_PINVOKE}
  {$define SB_NO_REGISTRY}
  {$define SB_NO_NET_MICROSOFT_WIN32}
  {$define SB_NO_SYSTEM_SECURITY_CRYPTOGRAPHY}

  {$undef SB_NET_DESKTOP}
  {$undef SB_NTLM_SUPPORT}
  {$define TriDES_KEY_AS_REC}
  {$undef SB_PGPSFX}
  {$undef SB_HAS_HTTPAUTH}
  {$undef SB_WINDOWS_SHELL}
  {$undef SB_HAS_X509CERTIFICATE2}
  {$undef SB_HAS_CNG}
  {$define SB_CONSTRAINED_DEVICE}
  {$undef SB_IIS_SUPPORT}
  {$undef SB_SSH_PUBKEYAGENT}
  {$undef SB_NET_UNC_WORKAROUND}
{$endif}

{$ifdef SB_ANDROID} // Pascal code compiled for Android with FPC
  {$define SB_NO_NET_REFLECTION}
  {$define SB_NO_NET_MARSHALBYREF}
  {$define SB_NO_NET_WINDOWSFORMS}
  {$define SB_NO_NET_PINVOKE}
  {$define SB_NO_REGISTRY}

  {$define TriDES_KEY_AS_REC}
  {$define SB_CONSTRAINED_DEVICE}

  {$undef SB_NTLM_SUPPORT}
  {$undef SB_HAS_WINCRYPT}
  {.$undef SB_GSSAPI}
  {$undef SB_PGPSFX}
  {$undef SB_HAS_HTTPAUTH}
  {$undef SB_WINDOWS_SHELL}
  {$undef SB_HAS_CNG}
  {$undef SB_IIS_SUPPORT}
  {$undef SB_SSH_PUBKEYAGENT}
  {$undef SB_USE_NAMED_EVENTS}
{$endif}

{$ifdef FPC}
  {$ifndef WIN32}
    {$undef SB_HAS_WINCRYPT}
    {.$define SB_NO_PKCS11}
    {$undef SB_WINDOWS_SHELL}
  {$endif}
  {.$undef SB_NTLM_SUPPORT}
{$endif}

{$ifdef DELPHI_MAC}
  {$undef SB_HAS_WINCRYPT}
  {$undef SB_WINDOWS_SHELL}
  {$define SB_NO_REGISTRY}
  {.$define SB_NO_PKCS11}
  {$undef SB_DNSSEC}
  {$define SB_NO_THREADPRIORITY}
  {$undef SB_USE_NAMED_EVENTS}
{$endif}

{$ifdef SB_PGPSFX_STUB}
  {$define SB_NO_RC2}
  {$define SB_NO_RC4}
  {$define SB_NO_DH}
  {$define SB_NO_X509} // no need for certificates in PGP stub  
  {$define SB_NO_CAMELLIA}
  {$define SB_NO_SEED}
  {$define SB_NO_SRP}
  {$define SB_NO_RABBIT}
  {$define SB_NO_PKCS11}
  {$define SB_NO_SERPENT}
  {$define SB_NO_UMAC}
  {$define SB_NO_MD2}
  {$define SB_NO_PKIASYNC}
  {$define SB_NO_CHARSETS}
  {$define SB_NO_COMPRESSION} // removes compression from ZLib (decompression left)
  {$define SB_NO_FSADAPTER} // removes file system adapter from OpenPGP
  {.$undef SB_HAS_ECC}
  {$undef SB_HAS_GOST}
  {$undef SB_HAS_WINCRYPT}
  {$undef SB_PGPSFX}
  {$undef SB_GSSAPI}
  {$undef SB_HAS_CNG}
  {$undef SB_IIS_SUPPORT}
{$endif}

{$ifdef NET_4_0_UP}
  {$define SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
{$endif}

{$ifdef SILVERLIGHT50_WINDOWS}
  {$define SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
{$endif}

{$ifdef SB_JAVA} // Pascal code compiled for Java with FPC/JVM
  {$define JAVA_registered}  
  {$modeswitch unicodestrings}
  
  {$define SB_NO_COMPONENT}
  {$define SB_NO_REGISTRY}
  {$define SB_NO_VS_TOOLBOX}

  {$undef SB_WINDOWS}
  {$undef SB_WINDOWS_SHELL}
  {$undef SB_NTLM_SUPPORT}
  {$undef SB_GSSAPI}
  {$undef SB_PGPSFX}
  {$undef SB_X86ASM}
  {$undef TriDES_KEY_AS_REC}
  
  {$ifndef java}
    {$ifndef SB_ANDROID}
      {$define SB_ANDROID}
    {$endif}
  {$endif}
  
  {$ifdef java}
    {$define SB_WINDOWS}
    {$define SB_HAS_WINCRYPT}
  {$else}
    {$undef SB_HAS_WINCRYPT}
    {$undef SB_HAS_CRYPTUI}
  {$endif}

  {$ifdef SB_ANDROID}
    {$define SB_HAS_MEMORY_MANAGER}
  {$endif}
{$endif}

{$ifdef SB_FPC_GEN}
  {$define SB_SKIP_PLATFORM_SPECIFIC_CODE}
{$endif}

{$ifdef SB_WINRT_SOCKETS}
{$define SB_NO_SERVER_SOCKETS}
{$define SB_NO_DATAGRAM_SOCKETS}
{$define SB_ASYNC_SOCKETS}
{$endif}

{$ifdef SB_SILVERLIGHT_SOCKETS}
{$define SB_NO_SERVER_SOCKETS}
{$define SB_NO_DATAGRAM_SOCKETS}
{$define SB_ASYNC_SOCKETS}
{$endif}

{$ifdef SBPKCS11ProxyDriver}
  {.$define SB_NO_RC2}
  {.$define SB_NO_RC4}
  {.$define SB_NO_DH}
  {$define SB_NO_CAMELLIA}
  {$define SB_NO_SEED}
  {$define SB_NO_SRP}
  {$define SB_NO_IDEA}
  {$define SB_NO_RABBIT}
  {$define SB_NO_SERPENT}
  {$define SB_NO_UMAC}
  {$define SB_NO_MD2}
  {$define SB_NO_PKIASYNC}
  {$define SB_REDUCED_CHARSETS}
  {$define SB_NO_COMPRESSION} 
  {$define SB_NO_FSADAPTER} // removes file system adapter
  {$define SB_NO_OCSP}

  {.$undef SB_HAS_ECC}
  {$undef SB_HAS_GOST}
  {$undef SB_HAS_WINCRYPT}
  {$undef SB_PGPSFX}
  {$undef SB_GSSAPI}
  {$undef SB_HAS_CNG}
{$endif}

{$ifdef SB_CRYPTOPKG}
  {$define SB_REDUCED_CHARSETS}
  {$undef SB_HAS_OAUTH}
  {$undef SB_NTLM_SUPPORT}
  {$undef SB_DNSSEC}
  {$undef SB_GSSAPI}
  {$undef SB_PGPSFX}
  {$undef SB_HAS_DC}
{$endif}

{$ifdef SB_iOS}
  {$define SB_STATIC_PKCS11}
{$endif}{$ifdef SB_VCL}
  {$hints off}
  {$warnings off}
{$endif} 
