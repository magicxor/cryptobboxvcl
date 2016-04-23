(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBWhirlpool;

interface

uses
  SBTypes;

type

  TWhirlpoolContext =  packed   record
    BitsHashed: ByteArray;  // 256-bit counter
    Buffer: ByteArray;      // 64 bytes
    BufferSize: Cardinal;   // number of bytes contained in the buffer
    State: Int64Array;  // 8 elements
  end;

procedure InitializeWhirlpool(var Context: TWhirlpoolContext); 
procedure HashWhirlpool(var Context: TWhirlpoolContext; Chunk: Pointer; ChunkSize: Cardinal);  overload ;
procedure HashWhirlpool(var Context: TWhirlpoolContext; Chunk: ByteArray; ChunkOffset, ChunkSize: Cardinal);  overload ;
function FinalizeWhirlpool(var Context: TWhirlpoolContext): TMessageDigest512; 

implementation

uses
  SBUtils;

const
  C0: array [0..255] of Int64 =  ( 
    Int64($18186018c07830d8), Int64($23238c2305af4626), Int64($c6c63fc67ef991b8), Int64($e8e887e8136fcdfb),
    Int64($878726874ca113cb), Int64($b8b8dab8a9626d11), Int64($0101040108050209), Int64($4f4f214f426e9e0d),
    Int64($3636d836adee6c9b), Int64($a6a6a2a6590451ff), Int64($d2d26fd2debdb90c), Int64($f5f5f3f5fb06f70e),
    Int64($7979f979ef80f296), Int64($6f6fa16f5fcede30), Int64($91917e91fcef3f6d), Int64($52525552aa07a4f8),
    Int64($60609d6027fdc047), Int64($bcbccabc89766535), Int64($9b9b569baccd2b37), Int64($8e8e028e048c018a),
    Int64($a3a3b6a371155bd2), Int64($0c0c300c603c186c), Int64($7b7bf17bff8af684), Int64($3535d435b5e16a80),
    Int64($1d1d741de8693af5), Int64($e0e0a7e05347ddb3), Int64($d7d77bd7f6acb321), Int64($c2c22fc25eed999c),
    Int64($2e2eb82e6d965c43), Int64($4b4b314b627a9629), Int64($fefedffea321e15d), Int64($575741578216aed5),
    Int64($15155415a8412abd), Int64($7777c1779fb6eee8), Int64($3737dc37a5eb6e92), Int64($e5e5b3e57b56d79e),
    Int64($9f9f469f8cd92313), Int64($f0f0e7f0d317fd23), Int64($4a4a354a6a7f9420), Int64($dada4fda9e95a944),
    Int64($58587d58fa25b0a2), Int64($c9c903c906ca8fcf), Int64($2929a429558d527c), Int64($0a0a280a5022145a),
    Int64($b1b1feb1e14f7f50), Int64($a0a0baa0691a5dc9), Int64($6b6bb16b7fdad614), Int64($85852e855cab17d9),
    Int64($bdbdcebd8173673c), Int64($5d5d695dd234ba8f), Int64($1010401080502090), Int64($f4f4f7f4f303f507),
    Int64($cbcb0bcb16c08bdd), Int64($3e3ef83eedc67cd3), Int64($0505140528110a2d), Int64($676781671fe6ce78),
    Int64($e4e4b7e47353d597), Int64($27279c2725bb4e02), Int64($4141194132588273), Int64($8b8b168b2c9d0ba7),
    Int64($a7a7a6a7510153f6), Int64($7d7de97dcf94fab2), Int64($95956e95dcfb3749), Int64($d8d847d88e9fad56),
    Int64($fbfbcbfb8b30eb70), Int64($eeee9fee2371c1cd), Int64($7c7ced7cc791f8bb), Int64($6666856617e3cc71),
    Int64($dddd53dda68ea77b), Int64($17175c17b84b2eaf), Int64($4747014702468e45), Int64($9e9e429e84dc211a),
    Int64($caca0fca1ec589d4), Int64($2d2db42d75995a58), Int64($bfbfc6bf9179632e), Int64($07071c07381b0e3f),
    Int64($adad8ead012347ac), Int64($5a5a755aea2fb4b0), Int64($838336836cb51bef), Int64($3333cc3385ff66b6),
    Int64($636391633ff2c65c), Int64($02020802100a0412), Int64($aaaa92aa39384993), Int64($7171d971afa8e2de),
    Int64($c8c807c80ecf8dc6), Int64($19196419c87d32d1), Int64($494939497270923b), Int64($d9d943d9869aaf5f),
    Int64($f2f2eff2c31df931), Int64($e3e3abe34b48dba8), Int64($5b5b715be22ab6b9), Int64($88881a8834920dbc),
    Int64($9a9a529aa4c8293e), Int64($262698262dbe4c0b), Int64($3232c8328dfa64bf), Int64($b0b0fab0e94a7d59),
    Int64($e9e983e91b6acff2), Int64($0f0f3c0f78331e77), Int64($d5d573d5e6a6b733), Int64($80803a8074ba1df4),
    Int64($bebec2be997c6127), Int64($cdcd13cd26de87eb), Int64($3434d034bde46889), Int64($48483d487a759032),
    Int64($ffffdbffab24e354), Int64($7a7af57af78ff48d), Int64($90907a90f4ea3d64), Int64($5f5f615fc23ebe9d),
    Int64($202080201da0403d), Int64($6868bd6867d5d00f), Int64($1a1a681ad07234ca), Int64($aeae82ae192c41b7),
    Int64($b4b4eab4c95e757d), Int64($54544d549a19a8ce), Int64($93937693ece53b7f), Int64($222288220daa442f),
    Int64($64648d6407e9c863), Int64($f1f1e3f1db12ff2a), Int64($7373d173bfa2e6cc), Int64($12124812905a2482),
    Int64($40401d403a5d807a), Int64($0808200840281048), Int64($c3c32bc356e89b95), Int64($ecec97ec337bc5df),
    Int64($dbdb4bdb9690ab4d), Int64($a1a1bea1611f5fc0), Int64($8d8d0e8d1c830791), Int64($3d3df43df5c97ac8),
    Int64($97976697ccf1335b), Int64($0000000000000000), Int64($cfcf1bcf36d483f9), Int64($2b2bac2b4587566e),
    Int64($7676c57697b3ece1), Int64($8282328264b019e6), Int64($d6d67fd6fea9b128), Int64($1b1b6c1bd87736c3),
    Int64($b5b5eeb5c15b7774), Int64($afaf86af112943be), Int64($6a6ab56a77dfd41d), Int64($50505d50ba0da0ea),
    Int64($45450945124c8a57), Int64($f3f3ebf3cb18fb38), Int64($3030c0309df060ad), Int64($efef9bef2b74c3c4),
    Int64($3f3ffc3fe5c37eda), Int64($55554955921caac7), Int64($a2a2b2a2791059db), Int64($eaea8fea0365c9e9),
    Int64($656589650fecca6a), Int64($babad2bab9686903), Int64($2f2fbc2f65935e4a), Int64($c0c027c04ee79d8e),
    Int64($dede5fdebe81a160), Int64($1c1c701ce06c38fc), Int64($fdfdd3fdbb2ee746), Int64($4d4d294d52649a1f),
    Int64($92927292e4e03976), Int64($7575c9758fbceafa), Int64($06061806301e0c36), Int64($8a8a128a249809ae),
    Int64($b2b2f2b2f940794b), Int64($e6e6bfe66359d185), Int64($0e0e380e70361c7e), Int64($1f1f7c1ff8633ee7),
    Int64($6262956237f7c455), Int64($d4d477d4eea3b53a), Int64($a8a89aa829324d81), Int64($96966296c4f43152),
    Int64($f9f9c3f99b3aef62), Int64($c5c533c566f697a3), Int64($2525942535b14a10), Int64($59597959f220b2ab),
    Int64($84842a8454ae15d0), Int64($7272d572b7a7e4c5), Int64($3939e439d5dd72ec), Int64($4c4c2d4c5a619816),
    Int64($5e5e655eca3bbc94), Int64($7878fd78e785f09f), Int64($3838e038ddd870e5), Int64($8c8c0a8c14860598),
    Int64($d1d163d1c6b2bf17), Int64($a5a5aea5410b57e4), Int64($e2e2afe2434dd9a1), Int64($616199612ff8c24e),
    Int64($b3b3f6b3f1457b42), Int64($2121842115a54234), Int64($9c9c4a9c94d62508), Int64($1e1e781ef0663cee),
    Int64($4343114322528661), Int64($c7c73bc776fc93b1), Int64($fcfcd7fcb32be54f), Int64($0404100420140824),
    Int64($51515951b208a2e3), Int64($99995e99bcc72f25), Int64($6d6da96d4fc4da22), Int64($0d0d340d68391a65),
    Int64($fafacffa8335e979), Int64($dfdf5bdfb684a369), Int64($7e7ee57ed79bfca9), Int64($242490243db44819),
    Int64($3b3bec3bc5d776fe), Int64($abab96ab313d4b9a), Int64($cece1fce3ed181f0), Int64($1111441188552299),
    Int64($8f8f068f0c890383), Int64($4e4e254e4a6b9c04), Int64($b7b7e6b7d1517366), Int64($ebeb8beb0b60cbe0),
    Int64($3c3cf03cfdcc78c1), Int64($81813e817cbf1ffd), Int64($94946a94d4fe3540), Int64($f7f7fbf7eb0cf31c),
    Int64($b9b9deb9a1676f18), Int64($13134c13985f268b), Int64($2c2cb02c7d9c5851), Int64($d3d36bd3d6b8bb05),
    Int64($e7e7bbe76b5cd38c), Int64($6e6ea56e57cbdc39), Int64($c4c437c46ef395aa), Int64($03030c03180f061b),
    Int64($565645568a13acdc), Int64($44440d441a49885e), Int64($7f7fe17fdf9efea0), Int64($a9a99ea921374f88),
    Int64($2a2aa82a4d825467), Int64($bbbbd6bbb16d6b0a), Int64($c1c123c146e29f87), Int64($53535153a202a6f1),
    Int64($dcdc57dcae8ba572), Int64($0b0b2c0b58271653), Int64($9d9d4e9d9cd32701), Int64($6c6cad6c47c1d82b),
    Int64($3131c43195f562a4), Int64($7474cd7487b9e8f3), Int64($f6f6fff6e309f115), Int64($464605460a438c4c),
    Int64($acac8aac092645a5), Int64($89891e893c970fb5), Int64($14145014a04428b4), Int64($e1e1a3e15b42dfba),
    Int64($16165816b04e2ca6), Int64($3a3ae83acdd274f7), Int64($6969b9696fd0d206), Int64($09092409482d1241),
    Int64($7070dd70a7ade0d7), Int64($b6b6e2b6d954716f), Int64($d0d067d0ceb7bd1e), Int64($eded93ed3b7ec7d6),
    Int64($cccc17cc2edb85e2), Int64($424215422a578468), Int64($98985a98b4c22d2c), Int64($a4a4aaa4490e55ed),
    Int64($2828a0285d885075), Int64($5c5c6d5cda31b886), Int64($f8f8c7f8933fed6b), Int64($8686228644a411c2)
   ) ;

  C1: array [0..255] of Int64 =  ( 
    Int64($d818186018c07830), Int64($2623238c2305af46), Int64($b8c6c63fc67ef991), Int64($fbe8e887e8136fcd),
    Int64($cb878726874ca113), Int64($11b8b8dab8a9626d), Int64($0901010401080502), Int64($0d4f4f214f426e9e),
    Int64($9b3636d836adee6c), Int64($ffa6a6a2a6590451), Int64($0cd2d26fd2debdb9), Int64($0ef5f5f3f5fb06f7),
    Int64($967979f979ef80f2), Int64($306f6fa16f5fcede), Int64($6d91917e91fcef3f), Int64($f852525552aa07a4),
    Int64($4760609d6027fdc0), Int64($35bcbccabc897665), Int64($379b9b569baccd2b), Int64($8a8e8e028e048c01),
    Int64($d2a3a3b6a371155b), Int64($6c0c0c300c603c18), Int64($847b7bf17bff8af6), Int64($803535d435b5e16a),
    Int64($f51d1d741de8693a), Int64($b3e0e0a7e05347dd), Int64($21d7d77bd7f6acb3), Int64($9cc2c22fc25eed99),
    Int64($432e2eb82e6d965c), Int64($294b4b314b627a96), Int64($5dfefedffea321e1), Int64($d5575741578216ae),
    Int64($bd15155415a8412a), Int64($e87777c1779fb6ee), Int64($923737dc37a5eb6e), Int64($9ee5e5b3e57b56d7),
    Int64($139f9f469f8cd923), Int64($23f0f0e7f0d317fd), Int64($204a4a354a6a7f94), Int64($44dada4fda9e95a9),
    Int64($a258587d58fa25b0), Int64($cfc9c903c906ca8f), Int64($7c2929a429558d52), Int64($5a0a0a280a502214),
    Int64($50b1b1feb1e14f7f), Int64($c9a0a0baa0691a5d), Int64($146b6bb16b7fdad6), Int64($d985852e855cab17),
    Int64($3cbdbdcebd817367), Int64($8f5d5d695dd234ba), Int64($9010104010805020), Int64($07f4f4f7f4f303f5),
    Int64($ddcbcb0bcb16c08b), Int64($d33e3ef83eedc67c), Int64($2d0505140528110a), Int64($78676781671fe6ce),
    Int64($97e4e4b7e47353d5), Int64($0227279c2725bb4e), Int64($7341411941325882), Int64($a78b8b168b2c9d0b),
    Int64($f6a7a7a6a7510153), Int64($b27d7de97dcf94fa), Int64($4995956e95dcfb37), Int64($56d8d847d88e9fad),
    Int64($70fbfbcbfb8b30eb), Int64($cdeeee9fee2371c1), Int64($bb7c7ced7cc791f8), Int64($716666856617e3cc),
    Int64($7bdddd53dda68ea7), Int64($af17175c17b84b2e), Int64($454747014702468e), Int64($1a9e9e429e84dc21),
    Int64($d4caca0fca1ec589), Int64($582d2db42d75995a), Int64($2ebfbfc6bf917963), Int64($3f07071c07381b0e),
    Int64($acadad8ead012347), Int64($b05a5a755aea2fb4), Int64($ef838336836cb51b), Int64($b63333cc3385ff66),
    Int64($5c636391633ff2c6), Int64($1202020802100a04), Int64($93aaaa92aa393849), Int64($de7171d971afa8e2),
    Int64($c6c8c807c80ecf8d), Int64($d119196419c87d32), Int64($3b49493949727092), Int64($5fd9d943d9869aaf),
    Int64($31f2f2eff2c31df9), Int64($a8e3e3abe34b48db), Int64($b95b5b715be22ab6), Int64($bc88881a8834920d),
    Int64($3e9a9a529aa4c829), Int64($0b262698262dbe4c), Int64($bf3232c8328dfa64), Int64($59b0b0fab0e94a7d),
    Int64($f2e9e983e91b6acf), Int64($770f0f3c0f78331e), Int64($33d5d573d5e6a6b7), Int64($f480803a8074ba1d),
    Int64($27bebec2be997c61), Int64($ebcdcd13cd26de87), Int64($893434d034bde468), Int64($3248483d487a7590),
    Int64($54ffffdbffab24e3), Int64($8d7a7af57af78ff4), Int64($6490907a90f4ea3d), Int64($9d5f5f615fc23ebe),
    Int64($3d202080201da040), Int64($0f6868bd6867d5d0), Int64($ca1a1a681ad07234), Int64($b7aeae82ae192c41),
    Int64($7db4b4eab4c95e75), Int64($ce54544d549a19a8), Int64($7f93937693ece53b), Int64($2f222288220daa44),
    Int64($6364648d6407e9c8), Int64($2af1f1e3f1db12ff), Int64($cc7373d173bfa2e6), Int64($8212124812905a24),
    Int64($7a40401d403a5d80), Int64($4808082008402810), Int64($95c3c32bc356e89b), Int64($dfecec97ec337bc5),
    Int64($4ddbdb4bdb9690ab), Int64($c0a1a1bea1611f5f), Int64($918d8d0e8d1c8307), Int64($c83d3df43df5c97a),
    Int64($5b97976697ccf133), Int64($0000000000000000), Int64($f9cfcf1bcf36d483), Int64($6e2b2bac2b458756),
    Int64($e17676c57697b3ec), Int64($e68282328264b019), Int64($28d6d67fd6fea9b1), Int64($c31b1b6c1bd87736),
    Int64($74b5b5eeb5c15b77), Int64($beafaf86af112943), Int64($1d6a6ab56a77dfd4), Int64($ea50505d50ba0da0),
    Int64($5745450945124c8a), Int64($38f3f3ebf3cb18fb), Int64($ad3030c0309df060), Int64($c4efef9bef2b74c3),
    Int64($da3f3ffc3fe5c37e), Int64($c755554955921caa), Int64($dba2a2b2a2791059), Int64($e9eaea8fea0365c9),
    Int64($6a656589650fecca), Int64($03babad2bab96869), Int64($4a2f2fbc2f65935e), Int64($8ec0c027c04ee79d),
    Int64($60dede5fdebe81a1), Int64($fc1c1c701ce06c38), Int64($46fdfdd3fdbb2ee7), Int64($1f4d4d294d52649a),
    Int64($7692927292e4e039), Int64($fa7575c9758fbcea), Int64($3606061806301e0c), Int64($ae8a8a128a249809),
    Int64($4bb2b2f2b2f94079), Int64($85e6e6bfe66359d1), Int64($7e0e0e380e70361c), Int64($e71f1f7c1ff8633e),
    Int64($556262956237f7c4), Int64($3ad4d477d4eea3b5), Int64($81a8a89aa829324d), Int64($5296966296c4f431),
    Int64($62f9f9c3f99b3aef), Int64($a3c5c533c566f697), Int64($102525942535b14a), Int64($ab59597959f220b2),
    Int64($d084842a8454ae15), Int64($c57272d572b7a7e4), Int64($ec3939e439d5dd72), Int64($164c4c2d4c5a6198),
    Int64($945e5e655eca3bbc), Int64($9f7878fd78e785f0), Int64($e53838e038ddd870), Int64($988c8c0a8c148605),
    Int64($17d1d163d1c6b2bf), Int64($e4a5a5aea5410b57), Int64($a1e2e2afe2434dd9), Int64($4e616199612ff8c2),
    Int64($42b3b3f6b3f1457b), Int64($342121842115a542), Int64($089c9c4a9c94d625), Int64($ee1e1e781ef0663c),
    Int64($6143431143225286), Int64($b1c7c73bc776fc93), Int64($4ffcfcd7fcb32be5), Int64($2404041004201408),
    Int64($e351515951b208a2), Int64($2599995e99bcc72f), Int64($226d6da96d4fc4da), Int64($650d0d340d68391a),
    Int64($79fafacffa8335e9), Int64($69dfdf5bdfb684a3), Int64($a97e7ee57ed79bfc), Int64($19242490243db448),
    Int64($fe3b3bec3bc5d776), Int64($9aabab96ab313d4b), Int64($f0cece1fce3ed181), Int64($9911114411885522),
    Int64($838f8f068f0c8903), Int64($044e4e254e4a6b9c), Int64($66b7b7e6b7d15173), Int64($e0ebeb8beb0b60cb),
    Int64($c13c3cf03cfdcc78), Int64($fd81813e817cbf1f), Int64($4094946a94d4fe35), Int64($1cf7f7fbf7eb0cf3),
    Int64($18b9b9deb9a1676f), Int64($8b13134c13985f26), Int64($512c2cb02c7d9c58), Int64($05d3d36bd3d6b8bb),
    Int64($8ce7e7bbe76b5cd3), Int64($396e6ea56e57cbdc), Int64($aac4c437c46ef395), Int64($1b03030c03180f06),
    Int64($dc565645568a13ac), Int64($5e44440d441a4988), Int64($a07f7fe17fdf9efe), Int64($88a9a99ea921374f),
    Int64($672a2aa82a4d8254), Int64($0abbbbd6bbb16d6b), Int64($87c1c123c146e29f), Int64($f153535153a202a6),
    Int64($72dcdc57dcae8ba5), Int64($530b0b2c0b582716), Int64($019d9d4e9d9cd327), Int64($2b6c6cad6c47c1d8),
    Int64($a43131c43195f562), Int64($f37474cd7487b9e8), Int64($15f6f6fff6e309f1), Int64($4c464605460a438c),
    Int64($a5acac8aac092645), Int64($b589891e893c970f), Int64($b414145014a04428), Int64($bae1e1a3e15b42df),
    Int64($a616165816b04e2c), Int64($f73a3ae83acdd274), Int64($066969b9696fd0d2), Int64($4109092409482d12),
    Int64($d77070dd70a7ade0), Int64($6fb6b6e2b6d95471), Int64($1ed0d067d0ceb7bd), Int64($d6eded93ed3b7ec7),
    Int64($e2cccc17cc2edb85), Int64($68424215422a5784), Int64($2c98985a98b4c22d), Int64($eda4a4aaa4490e55),
    Int64($752828a0285d8850), Int64($865c5c6d5cda31b8), Int64($6bf8f8c7f8933fed), Int64($c28686228644a411)
   ) ;

  C2: array [0..255] of Int64 =  ( 
    Int64($30d818186018c078), Int64($462623238c2305af), Int64($91b8c6c63fc67ef9), Int64($cdfbe8e887e8136f),
    Int64($13cb878726874ca1), Int64($6d11b8b8dab8a962), Int64($0209010104010805), Int64($9e0d4f4f214f426e),
    Int64($6c9b3636d836adee), Int64($51ffa6a6a2a65904), Int64($b90cd2d26fd2debd), Int64($f70ef5f5f3f5fb06),
    Int64($f2967979f979ef80), Int64($de306f6fa16f5fce), Int64($3f6d91917e91fcef), Int64($a4f852525552aa07),
    Int64($c04760609d6027fd), Int64($6535bcbccabc8976), Int64($2b379b9b569baccd), Int64($018a8e8e028e048c),
    Int64($5bd2a3a3b6a37115), Int64($186c0c0c300c603c), Int64($f6847b7bf17bff8a), Int64($6a803535d435b5e1),
    Int64($3af51d1d741de869), Int64($ddb3e0e0a7e05347), Int64($b321d7d77bd7f6ac), Int64($999cc2c22fc25eed),
    Int64($5c432e2eb82e6d96), Int64($96294b4b314b627a), Int64($e15dfefedffea321), Int64($aed5575741578216),
    Int64($2abd15155415a841), Int64($eee87777c1779fb6), Int64($6e923737dc37a5eb), Int64($d79ee5e5b3e57b56),
    Int64($23139f9f469f8cd9), Int64($fd23f0f0e7f0d317), Int64($94204a4a354a6a7f), Int64($a944dada4fda9e95),
    Int64($b0a258587d58fa25), Int64($8fcfc9c903c906ca), Int64($527c2929a429558d), Int64($145a0a0a280a5022),
    Int64($7f50b1b1feb1e14f), Int64($5dc9a0a0baa0691a), Int64($d6146b6bb16b7fda), Int64($17d985852e855cab),
    Int64($673cbdbdcebd8173), Int64($ba8f5d5d695dd234), Int64($2090101040108050), Int64($f507f4f4f7f4f303),
    Int64($8bddcbcb0bcb16c0), Int64($7cd33e3ef83eedc6), Int64($0a2d050514052811), Int64($ce78676781671fe6),
    Int64($d597e4e4b7e47353), Int64($4e0227279c2725bb), Int64($8273414119413258), Int64($0ba78b8b168b2c9d),
    Int64($53f6a7a7a6a75101), Int64($fab27d7de97dcf94), Int64($374995956e95dcfb), Int64($ad56d8d847d88e9f),
    Int64($eb70fbfbcbfb8b30), Int64($c1cdeeee9fee2371), Int64($f8bb7c7ced7cc791), Int64($cc716666856617e3),
    Int64($a77bdddd53dda68e), Int64($2eaf17175c17b84b), Int64($8e45474701470246), Int64($211a9e9e429e84dc),
    Int64($89d4caca0fca1ec5), Int64($5a582d2db42d7599), Int64($632ebfbfc6bf9179), Int64($0e3f07071c07381b),
    Int64($47acadad8ead0123), Int64($b4b05a5a755aea2f), Int64($1bef838336836cb5), Int64($66b63333cc3385ff),
    Int64($c65c636391633ff2), Int64($041202020802100a), Int64($4993aaaa92aa3938), Int64($e2de7171d971afa8),
    Int64($8dc6c8c807c80ecf), Int64($32d119196419c87d), Int64($923b494939497270), Int64($af5fd9d943d9869a),
    Int64($f931f2f2eff2c31d), Int64($dba8e3e3abe34b48), Int64($b6b95b5b715be22a), Int64($0dbc88881a883492),
    Int64($293e9a9a529aa4c8), Int64($4c0b262698262dbe), Int64($64bf3232c8328dfa), Int64($7d59b0b0fab0e94a),
    Int64($cff2e9e983e91b6a), Int64($1e770f0f3c0f7833), Int64($b733d5d573d5e6a6), Int64($1df480803a8074ba),
    Int64($6127bebec2be997c), Int64($87ebcdcd13cd26de), Int64($68893434d034bde4), Int64($903248483d487a75),
    Int64($e354ffffdbffab24), Int64($f48d7a7af57af78f), Int64($3d6490907a90f4ea), Int64($be9d5f5f615fc23e),
    Int64($403d202080201da0), Int64($d00f6868bd6867d5), Int64($34ca1a1a681ad072), Int64($41b7aeae82ae192c),
    Int64($757db4b4eab4c95e), Int64($a8ce54544d549a19), Int64($3b7f93937693ece5), Int64($442f222288220daa),
    Int64($c86364648d6407e9), Int64($ff2af1f1e3f1db12), Int64($e6cc7373d173bfa2), Int64($248212124812905a),
    Int64($807a40401d403a5d), Int64($1048080820084028), Int64($9b95c3c32bc356e8), Int64($c5dfecec97ec337b),
    Int64($ab4ddbdb4bdb9690), Int64($5fc0a1a1bea1611f), Int64($07918d8d0e8d1c83), Int64($7ac83d3df43df5c9),
    Int64($335b97976697ccf1), Int64($0000000000000000), Int64($83f9cfcf1bcf36d4), Int64($566e2b2bac2b4587),
    Int64($ece17676c57697b3), Int64($19e68282328264b0), Int64($b128d6d67fd6fea9), Int64($36c31b1b6c1bd877),
    Int64($7774b5b5eeb5c15b), Int64($43beafaf86af1129), Int64($d41d6a6ab56a77df), Int64($a0ea50505d50ba0d),
    Int64($8a5745450945124c), Int64($fb38f3f3ebf3cb18), Int64($60ad3030c0309df0), Int64($c3c4efef9bef2b74),
    Int64($7eda3f3ffc3fe5c3), Int64($aac755554955921c), Int64($59dba2a2b2a27910), Int64($c9e9eaea8fea0365),
    Int64($ca6a656589650fec), Int64($6903babad2bab968), Int64($5e4a2f2fbc2f6593), Int64($9d8ec0c027c04ee7),
    Int64($a160dede5fdebe81), Int64($38fc1c1c701ce06c), Int64($e746fdfdd3fdbb2e), Int64($9a1f4d4d294d5264),
    Int64($397692927292e4e0), Int64($eafa7575c9758fbc), Int64($0c3606061806301e), Int64($09ae8a8a128a2498),
    Int64($794bb2b2f2b2f940), Int64($d185e6e6bfe66359), Int64($1c7e0e0e380e7036), Int64($3ee71f1f7c1ff863),
    Int64($c4556262956237f7), Int64($b53ad4d477d4eea3), Int64($4d81a8a89aa82932), Int64($315296966296c4f4),
    Int64($ef62f9f9c3f99b3a), Int64($97a3c5c533c566f6), Int64($4a102525942535b1), Int64($b2ab59597959f220),
    Int64($15d084842a8454ae), Int64($e4c57272d572b7a7), Int64($72ec3939e439d5dd), Int64($98164c4c2d4c5a61),
    Int64($bc945e5e655eca3b), Int64($f09f7878fd78e785), Int64($70e53838e038ddd8), Int64($05988c8c0a8c1486),
    Int64($bf17d1d163d1c6b2), Int64($57e4a5a5aea5410b), Int64($d9a1e2e2afe2434d), Int64($c24e616199612ff8),
    Int64($7b42b3b3f6b3f145), Int64($42342121842115a5), Int64($25089c9c4a9c94d6), Int64($3cee1e1e781ef066),
    Int64($8661434311432252), Int64($93b1c7c73bc776fc), Int64($e54ffcfcd7fcb32b), Int64($0824040410042014),
    Int64($a2e351515951b208), Int64($2f2599995e99bcc7), Int64($da226d6da96d4fc4), Int64($1a650d0d340d6839),
    Int64($e979fafacffa8335), Int64($a369dfdf5bdfb684), Int64($fca97e7ee57ed79b), Int64($4819242490243db4),
    Int64($76fe3b3bec3bc5d7), Int64($4b9aabab96ab313d), Int64($81f0cece1fce3ed1), Int64($2299111144118855),
    Int64($03838f8f068f0c89), Int64($9c044e4e254e4a6b), Int64($7366b7b7e6b7d151), Int64($cbe0ebeb8beb0b60),
    Int64($78c13c3cf03cfdcc), Int64($1ffd81813e817cbf), Int64($354094946a94d4fe), Int64($f31cf7f7fbf7eb0c),
    Int64($6f18b9b9deb9a167), Int64($268b13134c13985f), Int64($58512c2cb02c7d9c), Int64($bb05d3d36bd3d6b8),
    Int64($d38ce7e7bbe76b5c), Int64($dc396e6ea56e57cb), Int64($95aac4c437c46ef3), Int64($061b03030c03180f),
    Int64($acdc565645568a13), Int64($885e44440d441a49), Int64($fea07f7fe17fdf9e), Int64($4f88a9a99ea92137),
    Int64($54672a2aa82a4d82), Int64($6b0abbbbd6bbb16d), Int64($9f87c1c123c146e2), Int64($a6f153535153a202),
    Int64($a572dcdc57dcae8b), Int64($16530b0b2c0b5827), Int64($27019d9d4e9d9cd3), Int64($d82b6c6cad6c47c1),
    Int64($62a43131c43195f5), Int64($e8f37474cd7487b9), Int64($f115f6f6fff6e309), Int64($8c4c464605460a43),
    Int64($45a5acac8aac0926), Int64($0fb589891e893c97), Int64($28b414145014a044), Int64($dfbae1e1a3e15b42),
    Int64($2ca616165816b04e), Int64($74f73a3ae83acdd2), Int64($d2066969b9696fd0), Int64($124109092409482d),
    Int64($e0d77070dd70a7ad), Int64($716fb6b6e2b6d954), Int64($bd1ed0d067d0ceb7), Int64($c7d6eded93ed3b7e),
    Int64($85e2cccc17cc2edb), Int64($8468424215422a57), Int64($2d2c98985a98b4c2), Int64($55eda4a4aaa4490e),
    Int64($50752828a0285d88), Int64($b8865c5c6d5cda31), Int64($ed6bf8f8c7f8933f), Int64($11c28686228644a4)
   ) ;

  C3: array [0..255] of Int64 =  ( 
    Int64($7830d818186018c0), Int64($af462623238c2305), Int64($f991b8c6c63fc67e), Int64($6fcdfbe8e887e813),
    Int64($a113cb878726874c), Int64($626d11b8b8dab8a9), Int64($0502090101040108), Int64($6e9e0d4f4f214f42),
    Int64($ee6c9b3636d836ad), Int64($0451ffa6a6a2a659), Int64($bdb90cd2d26fd2de), Int64($06f70ef5f5f3f5fb),
    Int64($80f2967979f979ef), Int64($cede306f6fa16f5f), Int64($ef3f6d91917e91fc), Int64($07a4f852525552aa),
    Int64($fdc04760609d6027), Int64($766535bcbccabc89), Int64($cd2b379b9b569bac), Int64($8c018a8e8e028e04),
    Int64($155bd2a3a3b6a371), Int64($3c186c0c0c300c60), Int64($8af6847b7bf17bff), Int64($e16a803535d435b5),
    Int64($693af51d1d741de8), Int64($47ddb3e0e0a7e053), Int64($acb321d7d77bd7f6), Int64($ed999cc2c22fc25e),
    Int64($965c432e2eb82e6d), Int64($7a96294b4b314b62), Int64($21e15dfefedffea3), Int64($16aed55757415782),
    Int64($412abd15155415a8), Int64($b6eee87777c1779f), Int64($eb6e923737dc37a5), Int64($56d79ee5e5b3e57b),
    Int64($d923139f9f469f8c), Int64($17fd23f0f0e7f0d3), Int64($7f94204a4a354a6a), Int64($95a944dada4fda9e),
    Int64($25b0a258587d58fa), Int64($ca8fcfc9c903c906), Int64($8d527c2929a42955), Int64($22145a0a0a280a50),
    Int64($4f7f50b1b1feb1e1), Int64($1a5dc9a0a0baa069), Int64($dad6146b6bb16b7f), Int64($ab17d985852e855c),
    Int64($73673cbdbdcebd81), Int64($34ba8f5d5d695dd2), Int64($5020901010401080), Int64($03f507f4f4f7f4f3),
    Int64($c08bddcbcb0bcb16), Int64($c67cd33e3ef83eed), Int64($110a2d0505140528), Int64($e6ce78676781671f),
    Int64($53d597e4e4b7e473), Int64($bb4e0227279c2725), Int64($5882734141194132), Int64($9d0ba78b8b168b2c),
    Int64($0153f6a7a7a6a751), Int64($94fab27d7de97dcf), Int64($fb374995956e95dc), Int64($9fad56d8d847d88e),
    Int64($30eb70fbfbcbfb8b), Int64($71c1cdeeee9fee23), Int64($91f8bb7c7ced7cc7), Int64($e3cc716666856617),
    Int64($8ea77bdddd53dda6), Int64($4b2eaf17175c17b8), Int64($468e454747014702), Int64($dc211a9e9e429e84),
    Int64($c589d4caca0fca1e), Int64($995a582d2db42d75), Int64($79632ebfbfc6bf91), Int64($1b0e3f07071c0738),
    Int64($2347acadad8ead01), Int64($2fb4b05a5a755aea), Int64($b51bef838336836c), Int64($ff66b63333cc3385),
    Int64($f2c65c636391633f), Int64($0a04120202080210), Int64($384993aaaa92aa39), Int64($a8e2de7171d971af),
    Int64($cf8dc6c8c807c80e), Int64($7d32d119196419c8), Int64($70923b4949394972), Int64($9aaf5fd9d943d986),
    Int64($1df931f2f2eff2c3), Int64($48dba8e3e3abe34b), Int64($2ab6b95b5b715be2), Int64($920dbc88881a8834),
    Int64($c8293e9a9a529aa4), Int64($be4c0b262698262d), Int64($fa64bf3232c8328d), Int64($4a7d59b0b0fab0e9),
    Int64($6acff2e9e983e91b), Int64($331e770f0f3c0f78), Int64($a6b733d5d573d5e6), Int64($ba1df480803a8074),
    Int64($7c6127bebec2be99), Int64($de87ebcdcd13cd26), Int64($e468893434d034bd), Int64($75903248483d487a),
    Int64($24e354ffffdbffab), Int64($8ff48d7a7af57af7), Int64($ea3d6490907a90f4), Int64($3ebe9d5f5f615fc2),
    Int64($a0403d202080201d), Int64($d5d00f6868bd6867), Int64($7234ca1a1a681ad0), Int64($2c41b7aeae82ae19),
    Int64($5e757db4b4eab4c9), Int64($19a8ce54544d549a), Int64($e53b7f93937693ec), Int64($aa442f222288220d),
    Int64($e9c86364648d6407), Int64($12ff2af1f1e3f1db), Int64($a2e6cc7373d173bf), Int64($5a24821212481290),
    Int64($5d807a40401d403a), Int64($2810480808200840), Int64($e89b95c3c32bc356), Int64($7bc5dfecec97ec33),
    Int64($90ab4ddbdb4bdb96), Int64($1f5fc0a1a1bea161), Int64($8307918d8d0e8d1c), Int64($c97ac83d3df43df5),
    Int64($f1335b97976697cc), Int64($0000000000000000), Int64($d483f9cfcf1bcf36), Int64($87566e2b2bac2b45),
    Int64($b3ece17676c57697), Int64($b019e68282328264), Int64($a9b128d6d67fd6fe), Int64($7736c31b1b6c1bd8),
    Int64($5b7774b5b5eeb5c1), Int64($2943beafaf86af11), Int64($dfd41d6a6ab56a77), Int64($0da0ea50505d50ba),
    Int64($4c8a574545094512), Int64($18fb38f3f3ebf3cb), Int64($f060ad3030c0309d), Int64($74c3c4efef9bef2b),
    Int64($c37eda3f3ffc3fe5), Int64($1caac75555495592), Int64($1059dba2a2b2a279), Int64($65c9e9eaea8fea03),
    Int64($ecca6a656589650f), Int64($686903babad2bab9), Int64($935e4a2f2fbc2f65), Int64($e79d8ec0c027c04e),
    Int64($81a160dede5fdebe), Int64($6c38fc1c1c701ce0), Int64($2ee746fdfdd3fdbb), Int64($649a1f4d4d294d52),
    Int64($e0397692927292e4), Int64($bceafa7575c9758f), Int64($1e0c360606180630), Int64($9809ae8a8a128a24),
    Int64($40794bb2b2f2b2f9), Int64($59d185e6e6bfe663), Int64($361c7e0e0e380e70), Int64($633ee71f1f7c1ff8),
    Int64($f7c4556262956237), Int64($a3b53ad4d477d4ee), Int64($324d81a8a89aa829), Int64($f4315296966296c4),
    Int64($3aef62f9f9c3f99b), Int64($f697a3c5c533c566), Int64($b14a102525942535), Int64($20b2ab59597959f2),
    Int64($ae15d084842a8454), Int64($a7e4c57272d572b7), Int64($dd72ec3939e439d5), Int64($6198164c4c2d4c5a),
    Int64($3bbc945e5e655eca), Int64($85f09f7878fd78e7), Int64($d870e53838e038dd), Int64($8605988c8c0a8c14),
    Int64($b2bf17d1d163d1c6), Int64($0b57e4a5a5aea541), Int64($4dd9a1e2e2afe243), Int64($f8c24e616199612f),
    Int64($457b42b3b3f6b3f1), Int64($a542342121842115), Int64($d625089c9c4a9c94), Int64($663cee1e1e781ef0),
    Int64($5286614343114322), Int64($fc93b1c7c73bc776), Int64($2be54ffcfcd7fcb3), Int64($1408240404100420),
    Int64($08a2e351515951b2), Int64($c72f2599995e99bc), Int64($c4da226d6da96d4f), Int64($391a650d0d340d68),
    Int64($35e979fafacffa83), Int64($84a369dfdf5bdfb6), Int64($9bfca97e7ee57ed7), Int64($b44819242490243d),
    Int64($d776fe3b3bec3bc5), Int64($3d4b9aabab96ab31), Int64($d181f0cece1fce3e), Int64($5522991111441188),
    Int64($8903838f8f068f0c), Int64($6b9c044e4e254e4a), Int64($517366b7b7e6b7d1), Int64($60cbe0ebeb8beb0b),
    Int64($cc78c13c3cf03cfd), Int64($bf1ffd81813e817c), Int64($fe354094946a94d4), Int64($0cf31cf7f7fbf7eb),
    Int64($676f18b9b9deb9a1), Int64($5f268b13134c1398), Int64($9c58512c2cb02c7d), Int64($b8bb05d3d36bd3d6),
    Int64($5cd38ce7e7bbe76b), Int64($cbdc396e6ea56e57), Int64($f395aac4c437c46e), Int64($0f061b03030c0318),
    Int64($13acdc565645568a), Int64($49885e44440d441a), Int64($9efea07f7fe17fdf), Int64($374f88a9a99ea921),
    Int64($8254672a2aa82a4d), Int64($6d6b0abbbbd6bbb1), Int64($e29f87c1c123c146), Int64($02a6f153535153a2),
    Int64($8ba572dcdc57dcae), Int64($2716530b0b2c0b58), Int64($d327019d9d4e9d9c), Int64($c1d82b6c6cad6c47),
    Int64($f562a43131c43195), Int64($b9e8f37474cd7487), Int64($09f115f6f6fff6e3), Int64($438c4c464605460a),
    Int64($2645a5acac8aac09), Int64($970fb589891e893c), Int64($4428b414145014a0), Int64($42dfbae1e1a3e15b),
    Int64($4e2ca616165816b0), Int64($d274f73a3ae83acd), Int64($d0d2066969b9696f), Int64($2d12410909240948),
    Int64($ade0d77070dd70a7), Int64($54716fb6b6e2b6d9), Int64($b7bd1ed0d067d0ce), Int64($7ec7d6eded93ed3b),
    Int64($db85e2cccc17cc2e), Int64($578468424215422a), Int64($c22d2c98985a98b4), Int64($0e55eda4a4aaa449),
    Int64($8850752828a0285d), Int64($31b8865c5c6d5cda), Int64($3fed6bf8f8c7f893), Int64($a411c28686228644)
   ) ;

  C4: array [0..255] of Int64 =  ( 
    Int64($c07830d818186018), Int64($05af462623238c23), Int64($7ef991b8c6c63fc6), Int64($136fcdfbe8e887e8),
    Int64($4ca113cb87872687), Int64($a9626d11b8b8dab8), Int64($0805020901010401), Int64($426e9e0d4f4f214f),
    Int64($adee6c9b3636d836), Int64($590451ffa6a6a2a6), Int64($debdb90cd2d26fd2), Int64($fb06f70ef5f5f3f5),
    Int64($ef80f2967979f979), Int64($5fcede306f6fa16f), Int64($fcef3f6d91917e91), Int64($aa07a4f852525552),
    Int64($27fdc04760609d60), Int64($89766535bcbccabc), Int64($accd2b379b9b569b), Int64($048c018a8e8e028e),
    Int64($71155bd2a3a3b6a3), Int64($603c186c0c0c300c), Int64($ff8af6847b7bf17b), Int64($b5e16a803535d435),
    Int64($e8693af51d1d741d), Int64($5347ddb3e0e0a7e0), Int64($f6acb321d7d77bd7), Int64($5eed999cc2c22fc2),
    Int64($6d965c432e2eb82e), Int64($627a96294b4b314b), Int64($a321e15dfefedffe), Int64($8216aed557574157),
    Int64($a8412abd15155415), Int64($9fb6eee87777c177), Int64($a5eb6e923737dc37), Int64($7b56d79ee5e5b3e5),
    Int64($8cd923139f9f469f), Int64($d317fd23f0f0e7f0), Int64($6a7f94204a4a354a), Int64($9e95a944dada4fda),
    Int64($fa25b0a258587d58), Int64($06ca8fcfc9c903c9), Int64($558d527c2929a429), Int64($5022145a0a0a280a),
    Int64($e14f7f50b1b1feb1), Int64($691a5dc9a0a0baa0), Int64($7fdad6146b6bb16b), Int64($5cab17d985852e85),
    Int64($8173673cbdbdcebd), Int64($d234ba8f5d5d695d), Int64($8050209010104010), Int64($f303f507f4f4f7f4),
    Int64($16c08bddcbcb0bcb), Int64($edc67cd33e3ef83e), Int64($28110a2d05051405), Int64($1fe6ce7867678167),
    Int64($7353d597e4e4b7e4), Int64($25bb4e0227279c27), Int64($3258827341411941), Int64($2c9d0ba78b8b168b),
    Int64($510153f6a7a7a6a7), Int64($cf94fab27d7de97d), Int64($dcfb374995956e95), Int64($8e9fad56d8d847d8),
    Int64($8b30eb70fbfbcbfb), Int64($2371c1cdeeee9fee), Int64($c791f8bb7c7ced7c), Int64($17e3cc7166668566),
    Int64($a68ea77bdddd53dd), Int64($b84b2eaf17175c17), Int64($02468e4547470147), Int64($84dc211a9e9e429e),
    Int64($1ec589d4caca0fca), Int64($75995a582d2db42d), Int64($9179632ebfbfc6bf), Int64($381b0e3f07071c07),
    Int64($012347acadad8ead), Int64($ea2fb4b05a5a755a), Int64($6cb51bef83833683), Int64($85ff66b63333cc33),
    Int64($3ff2c65c63639163), Int64($100a041202020802), Int64($39384993aaaa92aa), Int64($afa8e2de7171d971),
    Int64($0ecf8dc6c8c807c8), Int64($c87d32d119196419), Int64($7270923b49493949), Int64($869aaf5fd9d943d9),
    Int64($c31df931f2f2eff2), Int64($4b48dba8e3e3abe3), Int64($e22ab6b95b5b715b), Int64($34920dbc88881a88),
    Int64($a4c8293e9a9a529a), Int64($2dbe4c0b26269826), Int64($8dfa64bf3232c832), Int64($e94a7d59b0b0fab0),
    Int64($1b6acff2e9e983e9), Int64($78331e770f0f3c0f), Int64($e6a6b733d5d573d5), Int64($74ba1df480803a80),
    Int64($997c6127bebec2be), Int64($26de87ebcdcd13cd), Int64($bde468893434d034), Int64($7a75903248483d48),
    Int64($ab24e354ffffdbff), Int64($f78ff48d7a7af57a), Int64($f4ea3d6490907a90), Int64($c23ebe9d5f5f615f),
    Int64($1da0403d20208020), Int64($67d5d00f6868bd68), Int64($d07234ca1a1a681a), Int64($192c41b7aeae82ae),
    Int64($c95e757db4b4eab4), Int64($9a19a8ce54544d54), Int64($ece53b7f93937693), Int64($0daa442f22228822),
    Int64($07e9c86364648d64), Int64($db12ff2af1f1e3f1), Int64($bfa2e6cc7373d173), Int64($905a248212124812),
    Int64($3a5d807a40401d40), Int64($4028104808082008), Int64($56e89b95c3c32bc3), Int64($337bc5dfecec97ec),
    Int64($9690ab4ddbdb4bdb), Int64($611f5fc0a1a1bea1), Int64($1c8307918d8d0e8d), Int64($f5c97ac83d3df43d),
    Int64($ccf1335b97976697), Int64($0000000000000000), Int64($36d483f9cfcf1bcf), Int64($4587566e2b2bac2b),
    Int64($97b3ece17676c576), Int64($64b019e682823282), Int64($fea9b128d6d67fd6), Int64($d87736c31b1b6c1b),
    Int64($c15b7774b5b5eeb5), Int64($112943beafaf86af), Int64($77dfd41d6a6ab56a), Int64($ba0da0ea50505d50),
    Int64($124c8a5745450945), Int64($cb18fb38f3f3ebf3), Int64($9df060ad3030c030), Int64($2b74c3c4efef9bef),
    Int64($e5c37eda3f3ffc3f), Int64($921caac755554955), Int64($791059dba2a2b2a2), Int64($0365c9e9eaea8fea),
    Int64($0fecca6a65658965), Int64($b9686903babad2ba), Int64($65935e4a2f2fbc2f), Int64($4ee79d8ec0c027c0),
    Int64($be81a160dede5fde), Int64($e06c38fc1c1c701c), Int64($bb2ee746fdfdd3fd), Int64($52649a1f4d4d294d),
    Int64($e4e0397692927292), Int64($8fbceafa7575c975), Int64($301e0c3606061806), Int64($249809ae8a8a128a),
    Int64($f940794bb2b2f2b2), Int64($6359d185e6e6bfe6), Int64($70361c7e0e0e380e), Int64($f8633ee71f1f7c1f),
    Int64($37f7c45562629562), Int64($eea3b53ad4d477d4), Int64($29324d81a8a89aa8), Int64($c4f4315296966296),
    Int64($9b3aef62f9f9c3f9), Int64($66f697a3c5c533c5), Int64($35b14a1025259425), Int64($f220b2ab59597959),
    Int64($54ae15d084842a84), Int64($b7a7e4c57272d572), Int64($d5dd72ec3939e439), Int64($5a6198164c4c2d4c),
    Int64($ca3bbc945e5e655e), Int64($e785f09f7878fd78), Int64($ddd870e53838e038), Int64($148605988c8c0a8c),
    Int64($c6b2bf17d1d163d1), Int64($410b57e4a5a5aea5), Int64($434dd9a1e2e2afe2), Int64($2ff8c24e61619961),
    Int64($f1457b42b3b3f6b3), Int64($15a5423421218421), Int64($94d625089c9c4a9c), Int64($f0663cee1e1e781e),
    Int64($2252866143431143), Int64($76fc93b1c7c73bc7), Int64($b32be54ffcfcd7fc), Int64($2014082404041004),
    Int64($b208a2e351515951), Int64($bcc72f2599995e99), Int64($4fc4da226d6da96d), Int64($68391a650d0d340d),
    Int64($8335e979fafacffa), Int64($b684a369dfdf5bdf), Int64($d79bfca97e7ee57e), Int64($3db4481924249024),
    Int64($c5d776fe3b3bec3b), Int64($313d4b9aabab96ab), Int64($3ed181f0cece1fce), Int64($8855229911114411),
    Int64($0c8903838f8f068f), Int64($4a6b9c044e4e254e), Int64($d1517366b7b7e6b7), Int64($0b60cbe0ebeb8beb),
    Int64($fdcc78c13c3cf03c), Int64($7cbf1ffd81813e81), Int64($d4fe354094946a94), Int64($eb0cf31cf7f7fbf7),
    Int64($a1676f18b9b9deb9), Int64($985f268b13134c13), Int64($7d9c58512c2cb02c), Int64($d6b8bb05d3d36bd3),
    Int64($6b5cd38ce7e7bbe7), Int64($57cbdc396e6ea56e), Int64($6ef395aac4c437c4), Int64($180f061b03030c03),
    Int64($8a13acdc56564556), Int64($1a49885e44440d44), Int64($df9efea07f7fe17f), Int64($21374f88a9a99ea9),
    Int64($4d8254672a2aa82a), Int64($b16d6b0abbbbd6bb), Int64($46e29f87c1c123c1), Int64($a202a6f153535153),
    Int64($ae8ba572dcdc57dc), Int64($582716530b0b2c0b), Int64($9cd327019d9d4e9d), Int64($47c1d82b6c6cad6c),
    Int64($95f562a43131c431), Int64($87b9e8f37474cd74), Int64($e309f115f6f6fff6), Int64($0a438c4c46460546),
    Int64($092645a5acac8aac), Int64($3c970fb589891e89), Int64($a04428b414145014), Int64($5b42dfbae1e1a3e1),
    Int64($b04e2ca616165816), Int64($cdd274f73a3ae83a), Int64($6fd0d2066969b969), Int64($482d124109092409),
    Int64($a7ade0d77070dd70), Int64($d954716fb6b6e2b6), Int64($ceb7bd1ed0d067d0), Int64($3b7ec7d6eded93ed),
    Int64($2edb85e2cccc17cc), Int64($2a57846842421542), Int64($b4c22d2c98985a98), Int64($490e55eda4a4aaa4),
    Int64($5d8850752828a028), Int64($da31b8865c5c6d5c), Int64($933fed6bf8f8c7f8), Int64($44a411c286862286)
   ) ;

  C5: array [0..255] of Int64 =  ( 
    Int64($18c07830d8181860), Int64($2305af462623238c), Int64($c67ef991b8c6c63f), Int64($e8136fcdfbe8e887),
    Int64($874ca113cb878726), Int64($b8a9626d11b8b8da), Int64($0108050209010104), Int64($4f426e9e0d4f4f21),
    Int64($36adee6c9b3636d8), Int64($a6590451ffa6a6a2), Int64($d2debdb90cd2d26f), Int64($f5fb06f70ef5f5f3),
    Int64($79ef80f2967979f9), Int64($6f5fcede306f6fa1), Int64($91fcef3f6d91917e), Int64($52aa07a4f8525255),
    Int64($6027fdc04760609d), Int64($bc89766535bcbcca), Int64($9baccd2b379b9b56), Int64($8e048c018a8e8e02),
    Int64($a371155bd2a3a3b6), Int64($0c603c186c0c0c30), Int64($7bff8af6847b7bf1), Int64($35b5e16a803535d4),
    Int64($1de8693af51d1d74), Int64($e05347ddb3e0e0a7), Int64($d7f6acb321d7d77b), Int64($c25eed999cc2c22f),
    Int64($2e6d965c432e2eb8), Int64($4b627a96294b4b31), Int64($fea321e15dfefedf), Int64($578216aed5575741),
    Int64($15a8412abd151554), Int64($779fb6eee87777c1), Int64($37a5eb6e923737dc), Int64($e57b56d79ee5e5b3),
    Int64($9f8cd923139f9f46), Int64($f0d317fd23f0f0e7), Int64($4a6a7f94204a4a35), Int64($da9e95a944dada4f),
    Int64($58fa25b0a258587d), Int64($c906ca8fcfc9c903), Int64($29558d527c2929a4), Int64($0a5022145a0a0a28),
    Int64($b1e14f7f50b1b1fe), Int64($a0691a5dc9a0a0ba), Int64($6b7fdad6146b6bb1), Int64($855cab17d985852e),
    Int64($bd8173673cbdbdce), Int64($5dd234ba8f5d5d69), Int64($1080502090101040), Int64($f4f303f507f4f4f7),
    Int64($cb16c08bddcbcb0b), Int64($3eedc67cd33e3ef8), Int64($0528110a2d050514), Int64($671fe6ce78676781),
    Int64($e47353d597e4e4b7), Int64($2725bb4e0227279c), Int64($4132588273414119), Int64($8b2c9d0ba78b8b16),
    Int64($a7510153f6a7a7a6), Int64($7dcf94fab27d7de9), Int64($95dcfb374995956e), Int64($d88e9fad56d8d847),
    Int64($fb8b30eb70fbfbcb), Int64($ee2371c1cdeeee9f), Int64($7cc791f8bb7c7ced), Int64($6617e3cc71666685),
    Int64($dda68ea77bdddd53), Int64($17b84b2eaf17175c), Int64($4702468e45474701), Int64($9e84dc211a9e9e42),
    Int64($ca1ec589d4caca0f), Int64($2d75995a582d2db4), Int64($bf9179632ebfbfc6), Int64($07381b0e3f07071c),
    Int64($ad012347acadad8e), Int64($5aea2fb4b05a5a75), Int64($836cb51bef838336), Int64($3385ff66b63333cc),
    Int64($633ff2c65c636391), Int64($02100a0412020208), Int64($aa39384993aaaa92), Int64($71afa8e2de7171d9),
    Int64($c80ecf8dc6c8c807), Int64($19c87d32d1191964), Int64($497270923b494939), Int64($d9869aaf5fd9d943),
    Int64($f2c31df931f2f2ef), Int64($e34b48dba8e3e3ab), Int64($5be22ab6b95b5b71), Int64($8834920dbc88881a),
    Int64($9aa4c8293e9a9a52), Int64($262dbe4c0b262698), Int64($328dfa64bf3232c8), Int64($b0e94a7d59b0b0fa),
    Int64($e91b6acff2e9e983), Int64($0f78331e770f0f3c), Int64($d5e6a6b733d5d573), Int64($8074ba1df480803a),
    Int64($be997c6127bebec2), Int64($cd26de87ebcdcd13), Int64($34bde468893434d0), Int64($487a75903248483d),
    Int64($ffab24e354ffffdb), Int64($7af78ff48d7a7af5), Int64($90f4ea3d6490907a), Int64($5fc23ebe9d5f5f61),
    Int64($201da0403d202080), Int64($6867d5d00f6868bd), Int64($1ad07234ca1a1a68), Int64($ae192c41b7aeae82),
    Int64($b4c95e757db4b4ea), Int64($549a19a8ce54544d), Int64($93ece53b7f939376), Int64($220daa442f222288),
    Int64($6407e9c86364648d), Int64($f1db12ff2af1f1e3), Int64($73bfa2e6cc7373d1), Int64($12905a2482121248),
    Int64($403a5d807a40401d), Int64($0840281048080820), Int64($c356e89b95c3c32b), Int64($ec337bc5dfecec97),
    Int64($db9690ab4ddbdb4b), Int64($a1611f5fc0a1a1be), Int64($8d1c8307918d8d0e), Int64($3df5c97ac83d3df4),
    Int64($97ccf1335b979766), Int64($0000000000000000), Int64($cf36d483f9cfcf1b), Int64($2b4587566e2b2bac),
    Int64($7697b3ece17676c5), Int64($8264b019e6828232), Int64($d6fea9b128d6d67f), Int64($1bd87736c31b1b6c),
    Int64($b5c15b7774b5b5ee), Int64($af112943beafaf86), Int64($6a77dfd41d6a6ab5), Int64($50ba0da0ea50505d),
    Int64($45124c8a57454509), Int64($f3cb18fb38f3f3eb), Int64($309df060ad3030c0), Int64($ef2b74c3c4efef9b),
    Int64($3fe5c37eda3f3ffc), Int64($55921caac7555549), Int64($a2791059dba2a2b2), Int64($ea0365c9e9eaea8f),
    Int64($650fecca6a656589), Int64($bab9686903babad2), Int64($2f65935e4a2f2fbc), Int64($c04ee79d8ec0c027),
    Int64($debe81a160dede5f), Int64($1ce06c38fc1c1c70), Int64($fdbb2ee746fdfdd3), Int64($4d52649a1f4d4d29),
    Int64($92e4e03976929272), Int64($758fbceafa7575c9), Int64($06301e0c36060618), Int64($8a249809ae8a8a12),
    Int64($b2f940794bb2b2f2), Int64($e66359d185e6e6bf), Int64($0e70361c7e0e0e38), Int64($1ff8633ee71f1f7c),
    Int64($6237f7c455626295), Int64($d4eea3b53ad4d477), Int64($a829324d81a8a89a), Int64($96c4f43152969662),
    Int64($f99b3aef62f9f9c3), Int64($c566f697a3c5c533), Int64($2535b14a10252594), Int64($59f220b2ab595979),
    Int64($8454ae15d084842a), Int64($72b7a7e4c57272d5), Int64($39d5dd72ec3939e4), Int64($4c5a6198164c4c2d),
    Int64($5eca3bbc945e5e65), Int64($78e785f09f7878fd), Int64($38ddd870e53838e0), Int64($8c148605988c8c0a),
    Int64($d1c6b2bf17d1d163), Int64($a5410b57e4a5a5ae), Int64($e2434dd9a1e2e2af), Int64($612ff8c24e616199),
    Int64($b3f1457b42b3b3f6), Int64($2115a54234212184), Int64($9c94d625089c9c4a), Int64($1ef0663cee1e1e78),
    Int64($4322528661434311), Int64($c776fc93b1c7c73b), Int64($fcb32be54ffcfcd7), Int64($0420140824040410),
    Int64($51b208a2e3515159), Int64($99bcc72f2599995e), Int64($6d4fc4da226d6da9), Int64($0d68391a650d0d34),
    Int64($fa8335e979fafacf), Int64($dfb684a369dfdf5b), Int64($7ed79bfca97e7ee5), Int64($243db44819242490),
    Int64($3bc5d776fe3b3bec), Int64($ab313d4b9aabab96), Int64($ce3ed181f0cece1f), Int64($1188552299111144),
    Int64($8f0c8903838f8f06), Int64($4e4a6b9c044e4e25), Int64($b7d1517366b7b7e6), Int64($eb0b60cbe0ebeb8b),
    Int64($3cfdcc78c13c3cf0), Int64($817cbf1ffd81813e), Int64($94d4fe354094946a), Int64($f7eb0cf31cf7f7fb),
    Int64($b9a1676f18b9b9de), Int64($13985f268b13134c), Int64($2c7d9c58512c2cb0), Int64($d3d6b8bb05d3d36b),
    Int64($e76b5cd38ce7e7bb), Int64($6e57cbdc396e6ea5), Int64($c46ef395aac4c437), Int64($03180f061b03030c),
    Int64($568a13acdc565645), Int64($441a49885e44440d), Int64($7fdf9efea07f7fe1), Int64($a921374f88a9a99e),
    Int64($2a4d8254672a2aa8), Int64($bbb16d6b0abbbbd6), Int64($c146e29f87c1c123), Int64($53a202a6f1535351),
    Int64($dcae8ba572dcdc57), Int64($0b582716530b0b2c), Int64($9d9cd327019d9d4e), Int64($6c47c1d82b6c6cad),
    Int64($3195f562a43131c4), Int64($7487b9e8f37474cd), Int64($f6e309f115f6f6ff), Int64($460a438c4c464605),
    Int64($ac092645a5acac8a), Int64($893c970fb589891e), Int64($14a04428b4141450), Int64($e15b42dfbae1e1a3),
    Int64($16b04e2ca6161658), Int64($3acdd274f73a3ae8), Int64($696fd0d2066969b9), Int64($09482d1241090924),
    Int64($70a7ade0d77070dd), Int64($b6d954716fb6b6e2), Int64($d0ceb7bd1ed0d067), Int64($ed3b7ec7d6eded93),
    Int64($cc2edb85e2cccc17), Int64($422a578468424215), Int64($98b4c22d2c98985a), Int64($a4490e55eda4a4aa),
    Int64($285d8850752828a0), Int64($5cda31b8865c5c6d), Int64($f8933fed6bf8f8c7), Int64($8644a411c2868622)
   ) ;

  C6: array [0..255] of Int64 =  ( 
    Int64($6018c07830d81818), Int64($8c2305af46262323), Int64($3fc67ef991b8c6c6), Int64($87e8136fcdfbe8e8),
    Int64($26874ca113cb8787), Int64($dab8a9626d11b8b8), Int64($0401080502090101), Int64($214f426e9e0d4f4f),
    Int64($d836adee6c9b3636), Int64($a2a6590451ffa6a6), Int64($6fd2debdb90cd2d2), Int64($f3f5fb06f70ef5f5),
    Int64($f979ef80f2967979), Int64($a16f5fcede306f6f), Int64($7e91fcef3f6d9191), Int64($5552aa07a4f85252),
    Int64($9d6027fdc0476060), Int64($cabc89766535bcbc), Int64($569baccd2b379b9b), Int64($028e048c018a8e8e),
    Int64($b6a371155bd2a3a3), Int64($300c603c186c0c0c), Int64($f17bff8af6847b7b), Int64($d435b5e16a803535),
    Int64($741de8693af51d1d), Int64($a7e05347ddb3e0e0), Int64($7bd7f6acb321d7d7), Int64($2fc25eed999cc2c2),
    Int64($b82e6d965c432e2e), Int64($314b627a96294b4b), Int64($dffea321e15dfefe), Int64($41578216aed55757),
    Int64($5415a8412abd1515), Int64($c1779fb6eee87777), Int64($dc37a5eb6e923737), Int64($b3e57b56d79ee5e5),
    Int64($469f8cd923139f9f), Int64($e7f0d317fd23f0f0), Int64($354a6a7f94204a4a), Int64($4fda9e95a944dada),
    Int64($7d58fa25b0a25858), Int64($03c906ca8fcfc9c9), Int64($a429558d527c2929), Int64($280a5022145a0a0a),
    Int64($feb1e14f7f50b1b1), Int64($baa0691a5dc9a0a0), Int64($b16b7fdad6146b6b), Int64($2e855cab17d98585),
    Int64($cebd8173673cbdbd), Int64($695dd234ba8f5d5d), Int64($4010805020901010), Int64($f7f4f303f507f4f4),
    Int64($0bcb16c08bddcbcb), Int64($f83eedc67cd33e3e), Int64($140528110a2d0505), Int64($81671fe6ce786767),
    Int64($b7e47353d597e4e4), Int64($9c2725bb4e022727), Int64($1941325882734141), Int64($168b2c9d0ba78b8b),
    Int64($a6a7510153f6a7a7), Int64($e97dcf94fab27d7d), Int64($6e95dcfb37499595), Int64($47d88e9fad56d8d8),
    Int64($cbfb8b30eb70fbfb), Int64($9fee2371c1cdeeee), Int64($ed7cc791f8bb7c7c), Int64($856617e3cc716666),
    Int64($53dda68ea77bdddd), Int64($5c17b84b2eaf1717), Int64($014702468e454747), Int64($429e84dc211a9e9e),
    Int64($0fca1ec589d4caca), Int64($b42d75995a582d2d), Int64($c6bf9179632ebfbf), Int64($1c07381b0e3f0707),
    Int64($8ead012347acadad), Int64($755aea2fb4b05a5a), Int64($36836cb51bef8383), Int64($cc3385ff66b63333),
    Int64($91633ff2c65c6363), Int64($0802100a04120202), Int64($92aa39384993aaaa), Int64($d971afa8e2de7171),
    Int64($07c80ecf8dc6c8c8), Int64($6419c87d32d11919), Int64($39497270923b4949), Int64($43d9869aaf5fd9d9),
    Int64($eff2c31df931f2f2), Int64($abe34b48dba8e3e3), Int64($715be22ab6b95b5b), Int64($1a8834920dbc8888),
    Int64($529aa4c8293e9a9a), Int64($98262dbe4c0b2626), Int64($c8328dfa64bf3232), Int64($fab0e94a7d59b0b0),
    Int64($83e91b6acff2e9e9), Int64($3c0f78331e770f0f), Int64($73d5e6a6b733d5d5), Int64($3a8074ba1df48080),
    Int64($c2be997c6127bebe), Int64($13cd26de87ebcdcd), Int64($d034bde468893434), Int64($3d487a7590324848),
    Int64($dbffab24e354ffff), Int64($f57af78ff48d7a7a), Int64($7a90f4ea3d649090), Int64($615fc23ebe9d5f5f),
    Int64($80201da0403d2020), Int64($bd6867d5d00f6868), Int64($681ad07234ca1a1a), Int64($82ae192c41b7aeae),
    Int64($eab4c95e757db4b4), Int64($4d549a19a8ce5454), Int64($7693ece53b7f9393), Int64($88220daa442f2222),
    Int64($8d6407e9c8636464), Int64($e3f1db12ff2af1f1), Int64($d173bfa2e6cc7373), Int64($4812905a24821212),
    Int64($1d403a5d807a4040), Int64($2008402810480808), Int64($2bc356e89b95c3c3), Int64($97ec337bc5dfecec),
    Int64($4bdb9690ab4ddbdb), Int64($bea1611f5fc0a1a1), Int64($0e8d1c8307918d8d), Int64($f43df5c97ac83d3d),
    Int64($6697ccf1335b9797), Int64($0000000000000000), Int64($1bcf36d483f9cfcf), Int64($ac2b4587566e2b2b),
    Int64($c57697b3ece17676), Int64($328264b019e68282), Int64($7fd6fea9b128d6d6), Int64($6c1bd87736c31b1b),
    Int64($eeb5c15b7774b5b5), Int64($86af112943beafaf), Int64($b56a77dfd41d6a6a), Int64($5d50ba0da0ea5050),
    Int64($0945124c8a574545), Int64($ebf3cb18fb38f3f3), Int64($c0309df060ad3030), Int64($9bef2b74c3c4efef),
    Int64($fc3fe5c37eda3f3f), Int64($4955921caac75555), Int64($b2a2791059dba2a2), Int64($8fea0365c9e9eaea),
    Int64($89650fecca6a6565), Int64($d2bab9686903baba), Int64($bc2f65935e4a2f2f), Int64($27c04ee79d8ec0c0),
    Int64($5fdebe81a160dede), Int64($701ce06c38fc1c1c), Int64($d3fdbb2ee746fdfd), Int64($294d52649a1f4d4d),
    Int64($7292e4e039769292), Int64($c9758fbceafa7575), Int64($1806301e0c360606), Int64($128a249809ae8a8a),
    Int64($f2b2f940794bb2b2), Int64($bfe66359d185e6e6), Int64($380e70361c7e0e0e), Int64($7c1ff8633ee71f1f),
    Int64($956237f7c4556262), Int64($77d4eea3b53ad4d4), Int64($9aa829324d81a8a8), Int64($6296c4f431529696),
    Int64($c3f99b3aef62f9f9), Int64($33c566f697a3c5c5), Int64($942535b14a102525), Int64($7959f220b2ab5959),
    Int64($2a8454ae15d08484), Int64($d572b7a7e4c57272), Int64($e439d5dd72ec3939), Int64($2d4c5a6198164c4c),
    Int64($655eca3bbc945e5e), Int64($fd78e785f09f7878), Int64($e038ddd870e53838), Int64($0a8c148605988c8c),
    Int64($63d1c6b2bf17d1d1), Int64($aea5410b57e4a5a5), Int64($afe2434dd9a1e2e2), Int64($99612ff8c24e6161),
    Int64($f6b3f1457b42b3b3), Int64($842115a542342121), Int64($4a9c94d625089c9c), Int64($781ef0663cee1e1e),
    Int64($1143225286614343), Int64($3bc776fc93b1c7c7), Int64($d7fcb32be54ffcfc), Int64($1004201408240404),
    Int64($5951b208a2e35151), Int64($5e99bcc72f259999), Int64($a96d4fc4da226d6d), Int64($340d68391a650d0d),
    Int64($cffa8335e979fafa), Int64($5bdfb684a369dfdf), Int64($e57ed79bfca97e7e), Int64($90243db448192424),
    Int64($ec3bc5d776fe3b3b), Int64($96ab313d4b9aabab), Int64($1fce3ed181f0cece), Int64($4411885522991111),
    Int64($068f0c8903838f8f), Int64($254e4a6b9c044e4e), Int64($e6b7d1517366b7b7), Int64($8beb0b60cbe0ebeb),
    Int64($f03cfdcc78c13c3c), Int64($3e817cbf1ffd8181), Int64($6a94d4fe35409494), Int64($fbf7eb0cf31cf7f7),
    Int64($deb9a1676f18b9b9), Int64($4c13985f268b1313), Int64($b02c7d9c58512c2c), Int64($6bd3d6b8bb05d3d3),
    Int64($bbe76b5cd38ce7e7), Int64($a56e57cbdc396e6e), Int64($37c46ef395aac4c4), Int64($0c03180f061b0303),
    Int64($45568a13acdc5656), Int64($0d441a49885e4444), Int64($e17fdf9efea07f7f), Int64($9ea921374f88a9a9),
    Int64($a82a4d8254672a2a), Int64($d6bbb16d6b0abbbb), Int64($23c146e29f87c1c1), Int64($5153a202a6f15353),
    Int64($57dcae8ba572dcdc), Int64($2c0b582716530b0b), Int64($4e9d9cd327019d9d), Int64($ad6c47c1d82b6c6c),
    Int64($c43195f562a43131), Int64($cd7487b9e8f37474), Int64($fff6e309f115f6f6), Int64($05460a438c4c4646),
    Int64($8aac092645a5acac), Int64($1e893c970fb58989), Int64($5014a04428b41414), Int64($a3e15b42dfbae1e1),
    Int64($5816b04e2ca61616), Int64($e83acdd274f73a3a), Int64($b9696fd0d2066969), Int64($2409482d12410909),
    Int64($dd70a7ade0d77070), Int64($e2b6d954716fb6b6), Int64($67d0ceb7bd1ed0d0), Int64($93ed3b7ec7d6eded),
    Int64($17cc2edb85e2cccc), Int64($15422a5784684242), Int64($5a98b4c22d2c9898), Int64($aaa4490e55eda4a4),
    Int64($a0285d8850752828), Int64($6d5cda31b8865c5c), Int64($c7f8933fed6bf8f8), Int64($228644a411c28686)
   ) ;

  C7: array [0..255] of Int64 =  ( 
    Int64($186018c07830d818), Int64($238c2305af462623), Int64($c63fc67ef991b8c6), Int64($e887e8136fcdfbe8),
    Int64($8726874ca113cb87), Int64($b8dab8a9626d11b8), Int64($0104010805020901), Int64($4f214f426e9e0d4f),
    Int64($36d836adee6c9b36), Int64($a6a2a6590451ffa6), Int64($d26fd2debdb90cd2), Int64($f5f3f5fb06f70ef5),
    Int64($79f979ef80f29679), Int64($6fa16f5fcede306f), Int64($917e91fcef3f6d91), Int64($525552aa07a4f852),
    Int64($609d6027fdc04760), Int64($bccabc89766535bc), Int64($9b569baccd2b379b), Int64($8e028e048c018a8e),
    Int64($a3b6a371155bd2a3), Int64($0c300c603c186c0c), Int64($7bf17bff8af6847b), Int64($35d435b5e16a8035),
    Int64($1d741de8693af51d), Int64($e0a7e05347ddb3e0), Int64($d77bd7f6acb321d7), Int64($c22fc25eed999cc2),
    Int64($2eb82e6d965c432e), Int64($4b314b627a96294b), Int64($fedffea321e15dfe), Int64($5741578216aed557),
    Int64($155415a8412abd15), Int64($77c1779fb6eee877), Int64($37dc37a5eb6e9237), Int64($e5b3e57b56d79ee5),
    Int64($9f469f8cd923139f), Int64($f0e7f0d317fd23f0), Int64($4a354a6a7f94204a), Int64($da4fda9e95a944da),
    Int64($587d58fa25b0a258), Int64($c903c906ca8fcfc9), Int64($29a429558d527c29), Int64($0a280a5022145a0a),
    Int64($b1feb1e14f7f50b1), Int64($a0baa0691a5dc9a0), Int64($6bb16b7fdad6146b), Int64($852e855cab17d985),
    Int64($bdcebd8173673cbd), Int64($5d695dd234ba8f5d), Int64($1040108050209010), Int64($f4f7f4f303f507f4),
    Int64($cb0bcb16c08bddcb), Int64($3ef83eedc67cd33e), Int64($05140528110a2d05), Int64($6781671fe6ce7867),
    Int64($e4b7e47353d597e4), Int64($279c2725bb4e0227), Int64($4119413258827341), Int64($8b168b2c9d0ba78b),
    Int64($a7a6a7510153f6a7), Int64($7de97dcf94fab27d), Int64($956e95dcfb374995), Int64($d847d88e9fad56d8),
    Int64($fbcbfb8b30eb70fb), Int64($ee9fee2371c1cdee), Int64($7ced7cc791f8bb7c), Int64($66856617e3cc7166),
    Int64($dd53dda68ea77bdd), Int64($175c17b84b2eaf17), Int64($47014702468e4547), Int64($9e429e84dc211a9e),
    Int64($ca0fca1ec589d4ca), Int64($2db42d75995a582d), Int64($bfc6bf9179632ebf), Int64($071c07381b0e3f07),
    Int64($ad8ead012347acad), Int64($5a755aea2fb4b05a), Int64($8336836cb51bef83), Int64($33cc3385ff66b633),
    Int64($6391633ff2c65c63), Int64($020802100a041202), Int64($aa92aa39384993aa), Int64($71d971afa8e2de71),
    Int64($c807c80ecf8dc6c8), Int64($196419c87d32d119), Int64($4939497270923b49), Int64($d943d9869aaf5fd9),
    Int64($f2eff2c31df931f2), Int64($e3abe34b48dba8e3), Int64($5b715be22ab6b95b), Int64($881a8834920dbc88),
    Int64($9a529aa4c8293e9a), Int64($2698262dbe4c0b26), Int64($32c8328dfa64bf32), Int64($b0fab0e94a7d59b0),
    Int64($e983e91b6acff2e9), Int64($0f3c0f78331e770f), Int64($d573d5e6a6b733d5), Int64($803a8074ba1df480),
    Int64($bec2be997c6127be), Int64($cd13cd26de87ebcd), Int64($34d034bde4688934), Int64($483d487a75903248),
    Int64($ffdbffab24e354ff), Int64($7af57af78ff48d7a), Int64($907a90f4ea3d6490), Int64($5f615fc23ebe9d5f),
    Int64($2080201da0403d20), Int64($68bd6867d5d00f68), Int64($1a681ad07234ca1a), Int64($ae82ae192c41b7ae),
    Int64($b4eab4c95e757db4), Int64($544d549a19a8ce54), Int64($937693ece53b7f93), Int64($2288220daa442f22),
    Int64($648d6407e9c86364), Int64($f1e3f1db12ff2af1), Int64($73d173bfa2e6cc73), Int64($124812905a248212),
    Int64($401d403a5d807a40), Int64($0820084028104808), Int64($c32bc356e89b95c3), Int64($ec97ec337bc5dfec),
    Int64($db4bdb9690ab4ddb), Int64($a1bea1611f5fc0a1), Int64($8d0e8d1c8307918d), Int64($3df43df5c97ac83d),
    Int64($976697ccf1335b97), Int64($0000000000000000), Int64($cf1bcf36d483f9cf), Int64($2bac2b4587566e2b),
    Int64($76c57697b3ece176), Int64($82328264b019e682), Int64($d67fd6fea9b128d6), Int64($1b6c1bd87736c31b),
    Int64($b5eeb5c15b7774b5), Int64($af86af112943beaf), Int64($6ab56a77dfd41d6a), Int64($505d50ba0da0ea50),
    Int64($450945124c8a5745), Int64($f3ebf3cb18fb38f3), Int64($30c0309df060ad30), Int64($ef9bef2b74c3c4ef),
    Int64($3ffc3fe5c37eda3f), Int64($554955921caac755), Int64($a2b2a2791059dba2), Int64($ea8fea0365c9e9ea),
    Int64($6589650fecca6a65), Int64($bad2bab9686903ba), Int64($2fbc2f65935e4a2f), Int64($c027c04ee79d8ec0),
    Int64($de5fdebe81a160de), Int64($1c701ce06c38fc1c), Int64($fdd3fdbb2ee746fd), Int64($4d294d52649a1f4d),
    Int64($927292e4e0397692), Int64($75c9758fbceafa75), Int64($061806301e0c3606), Int64($8a128a249809ae8a),
    Int64($b2f2b2f940794bb2), Int64($e6bfe66359d185e6), Int64($0e380e70361c7e0e), Int64($1f7c1ff8633ee71f),
    Int64($62956237f7c45562), Int64($d477d4eea3b53ad4), Int64($a89aa829324d81a8), Int64($966296c4f4315296),
    Int64($f9c3f99b3aef62f9), Int64($c533c566f697a3c5), Int64($25942535b14a1025), Int64($597959f220b2ab59),
    Int64($842a8454ae15d084), Int64($72d572b7a7e4c572), Int64($39e439d5dd72ec39), Int64($4c2d4c5a6198164c),
    Int64($5e655eca3bbc945e), Int64($78fd78e785f09f78), Int64($38e038ddd870e538), Int64($8c0a8c148605988c),
    Int64($d163d1c6b2bf17d1), Int64($a5aea5410b57e4a5), Int64($e2afe2434dd9a1e2), Int64($6199612ff8c24e61),
    Int64($b3f6b3f1457b42b3), Int64($21842115a5423421), Int64($9c4a9c94d625089c), Int64($1e781ef0663cee1e),
    Int64($4311432252866143), Int64($c73bc776fc93b1c7), Int64($fcd7fcb32be54ffc), Int64($0410042014082404),
    Int64($515951b208a2e351), Int64($995e99bcc72f2599), Int64($6da96d4fc4da226d), Int64($0d340d68391a650d),
    Int64($facffa8335e979fa), Int64($df5bdfb684a369df), Int64($7ee57ed79bfca97e), Int64($2490243db4481924),
    Int64($3bec3bc5d776fe3b), Int64($ab96ab313d4b9aab), Int64($ce1fce3ed181f0ce), Int64($1144118855229911),
    Int64($8f068f0c8903838f), Int64($4e254e4a6b9c044e), Int64($b7e6b7d1517366b7), Int64($eb8beb0b60cbe0eb),
    Int64($3cf03cfdcc78c13c), Int64($813e817cbf1ffd81), Int64($946a94d4fe354094), Int64($f7fbf7eb0cf31cf7),
    Int64($b9deb9a1676f18b9), Int64($134c13985f268b13), Int64($2cb02c7d9c58512c), Int64($d36bd3d6b8bb05d3),
    Int64($e7bbe76b5cd38ce7), Int64($6ea56e57cbdc396e), Int64($c437c46ef395aac4), Int64($030c03180f061b03),
    Int64($5645568a13acdc56), Int64($440d441a49885e44), Int64($7fe17fdf9efea07f), Int64($a99ea921374f88a9),
    Int64($2aa82a4d8254672a), Int64($bbd6bbb16d6b0abb), Int64($c123c146e29f87c1), Int64($535153a202a6f153),
    Int64($dc57dcae8ba572dc), Int64($0b2c0b582716530b), Int64($9d4e9d9cd327019d), Int64($6cad6c47c1d82b6c),
    Int64($31c43195f562a431), Int64($74cd7487b9e8f374), Int64($f6fff6e309f115f6), Int64($4605460a438c4c46),
    Int64($ac8aac092645a5ac), Int64($891e893c970fb589), Int64($145014a04428b414), Int64($e1a3e15b42dfbae1),
    Int64($165816b04e2ca616), Int64($3ae83acdd274f73a), Int64($69b9696fd0d20669), Int64($092409482d124109),
    Int64($70dd70a7ade0d770), Int64($b6e2b6d954716fb6), Int64($d067d0ceb7bd1ed0), Int64($ed93ed3b7ec7d6ed),
    Int64($cc17cc2edb85e2cc), Int64($4215422a57846842), Int64($985a98b4c22d2c98), Int64($a4aaa4490e55eda4),
    Int64($28a0285d88507528), Int64($5c6d5cda31b8865c), Int64($f8c7f8933fed6bf8), Int64($86228644a411c286)
   ) ;

  RC: array [0..10] of Int64 =  ( 
    Int64($0000000000000000),
    Int64($1823c6e887b8014f),
    Int64($36a6d2f5796f9152),
    Int64($60bc9b8ea30c7b35),
    Int64($1de0d7c22e4bfe57),
    Int64($157737e59ff04ada),
    Int64($58c9290ab1a06b85),
    Int64($bd5d10f4cb3e0567),
    Int64($e427418ba77d95d8),
    Int64($fbee7c66dd17479e),
    Int64($ca2dbf07ad5a8333)
   ) ;

procedure InitializeWhirlpool(var Context: TWhirlpoolContext);
begin
  SetLength(Context.BitsHashed, 32);
  FillChar(Context.BitsHashed[0], 32, 0);

  SetLength(Context.Buffer, 64);
  FillChar(Context.Buffer[0], 64, 0);

  SetLength(Context.State, 8);
  FillChar(Context.State[0], SizeOf(Int64) shl 3, 0);

  Context.BufferSize := 0;
end;

procedure PrepareWhirlpoolBlock(const Buffer: ByteArray; Offset: Cardinal; var Block: Int64Array);  overload; 
const
  FF: Int64 = $FF;
var
  I: Integer;
begin
  for I := 0 to 7 do
  begin
    Block[I] := (Int64(Buffer[Offset    ]) shl 56) xor (Int64(Buffer[Offset + 1]) shl 48) xor
                (Int64(Buffer[Offset + 2]) shl 40) xor (Int64(Buffer[Offset + 3]) shl 32) xor
                (Int64(Buffer[Offset + 4]) shl 24) xor (Int64(Buffer[Offset + 5]) shl 16) xor
                (Int64(Buffer[Offset + 6]) shl  8) xor (Int64(Buffer[Offset + 7]));
    Inc(Offset, 8);
  end;
end;

procedure PrepareWhirlpoolBlock(Chunk: PByte; var Block: Int64Array); overload;
type
  ByteArr = array [0..7] of Byte;
  PByteArr = ^ByteArr;
var
  I: Integer;
  P: PByteArr;
begin
  for I := 0 to 7 do
  begin
    P := PByteArr(Chunk);
    Block[I] := (Int64(P[0]) shl 56) xor (Int64(P[1]) shl 48) xor
                (Int64(P[2]) shl 40) xor (Int64(P[3]) shl 32) xor
                (Int64(P[4]) shl 24) xor (Int64(P[5]) shl 16) xor
                (Int64(P[6]) shl  8) xor Int64(P[7]);
    Inc(Chunk, 8);
  end;
end;

procedure HashWhirlpoolBlock(const Block: Int64Array; var Hash: Int64Array);
var
  K, L, State: Int64Array;
  I: Integer;
begin
  Assert(Length(Block) = 8, 'Block must have exactly 8 elements');
  Assert(Length(Hash) = 8, 'State must have exactly 8 elements');

  SetLength(L, 8);
  SetLength(K, 8);
  K[0] := Hash[0];
  K[1] := Hash[1];
  K[2] := Hash[2];
  K[3] := Hash[3];
  K[4] := Hash[4];
  K[5] := Hash[5];
  K[6] := Hash[6];
  K[7] := Hash[7];

  SetLength(State, 8);
  State[0] := Block[0] xor K[0];
  State[1] := Block[1] xor K[1];
  State[2] := Block[2] xor K[2];
  State[3] := Block[3] xor K[3];
  State[4] := Block[4] xor K[4];
  State[5] := Block[5] xor K[5];
  State[6] := Block[6] xor K[6];
  State[7] := Block[7] xor K[7];

  for I := 1 to 10 do
  begin
    L[0] := C0[(K[0] shr 56)        ] xor C1[(K[7] shr 48) and $FF] xor
            C2[(K[6] shr 40) and $FF] xor C3[(K[5] shr 32) and $FF] xor
            C4[(K[4] shr 24) and $FF] xor C5[(K[3] shr 16) and $FF] xor
            C6[(K[2] shr  8) and $FF] xor C7[(K[1]       ) and $FF] xor RC[I];

    L[1] := C0[(K[1] shr 56)        ] xor C1[(K[0] shr 48) and $FF] xor
            C2[(K[7] shr 40) and $FF] xor C3[(K[6] shr 32) and $FF] xor
            C4[(K[5] shr 24) and $FF] xor C5[(K[4] shr 16) and $FF] xor
            C6[(K[3] shr  8) and $FF] xor C7[(K[2]       ) and $FF];

    L[2] := C0[(K[2] shr 56)        ] xor C1[(K[1] shr 48) and $FF] xor
            C2[(K[0] shr 40) and $FF] xor C3[(K[7] shr 32) and $FF] xor
            C4[(K[6] shr 24) and $FF] xor C5[(K[5] shr 16) and $FF] xor
            C6[(K[4] shr  8) and $FF] xor C7[(K[3]       ) and $FF];

    L[3] := C0[(K[3] shr 56)        ] xor C1[(K[2] shr 48) and $FF] xor
            C2[(K[1] shr 40) and $FF] xor C3[(K[0] shr 32) and $FF] xor
            C4[(K[7] shr 24) and $FF] xor C5[(K[6] shr 16) and $FF] xor
            C6[(K[5] shr  8) and $FF] xor C7[(K[4]       ) and $FF];

    L[4] := C0[(K[4] shr 56)        ] xor C1[(K[3] shr 48) and $FF] xor
            C2[(K[2] shr 40) and $FF] xor C3[(K[1] shr 32) and $FF] xor
            C4[(K[0] shr 24) and $FF] xor C5[(K[7] shr 16) and $FF] xor
            C6[(K[6] shr  8) and $FF] xor C7[(K[5]       ) and $FF];

    L[5] := C0[(K[5] shr 56)        ] xor C1[(K[4] shr 48) and $FF] xor
            C2[(K[3] shr 40) and $FF] xor C3[(K[2] shr 32) and $FF] xor
            C4[(K[1] shr 24) and $FF] xor C5[(K[0] shr 16) and $FF] xor
            C6[(K[7] shr  8) and $FF] xor C7[(K[6]       ) and $FF];

    L[6] := C0[(K[6] shr 56)        ] xor C1[(K[5] shr 48) and $FF] xor
            C2[(K[4] shr 40) and $FF] xor C3[(K[3] shr 32) and $FF] xor
            C4[(K[2] shr 24) and $FF] xor C5[(K[1] shr 16) and $FF] xor
            C6[(K[0] shr  8) and $FF] xor C7[(K[7]       ) and $FF];

    L[7] := C0[(K[7] shr 56)        ] xor C1[(K[6] shr 48) and $FF] xor
            C2[(K[5] shr 40) and $FF] xor C3[(K[4] shr 32) and $FF] xor
            C4[(K[3] shr 24) and $FF] xor C5[(K[2] shr 16) and $FF] xor
            C6[(K[1] shr  8) and $FF] xor C7[(K[0]       ) and $FF];

    K[0] := L[0];
    K[1] := L[1];
    K[2] := L[2];
    K[3] := L[3];
    K[4] := L[4];
    K[5] := L[5];
    K[6] := L[6];
    K[7] := L[7];

    L[0] := C0[(State[0] shr 56)        ] xor C1[(State[7] shr 48) and $FF] xor
            C2[(State[6] shr 40) and $FF] xor C3[(State[5] shr 32) and $FF] xor
            C4[(State[4] shr 24) and $FF] xor C5[(State[3] shr 16) and $FF] xor
            C6[(State[2] shr  8) and $FF] xor C7[(State[1]       ) and $FF] xor K[0];

    L[1] := C0[(State[1] shr 56)        ] xor C1[(State[0] shr 48) and $FF] xor
            C2[(State[7] shr 40) and $FF] xor C3[(State[6] shr 32) and $FF] xor
            C4[(State[5] shr 24) and $FF] xor C5[(State[4] shr 16) and $FF] xor
            C6[(State[3] shr  8) and $FF] xor C7[(State[2]       ) and $FF] xor K[1];

    L[2] := C0[(State[2] shr 56)        ] xor C1[(State[1] shr 48) and $FF] xor
            C2[(State[0] shr 40) and $FF] xor C3[(State[7] shr 32) and $FF] xor
            C4[(State[6] shr 24) and $FF] xor C5[(State[5] shr 16) and $FF] xor
            C6[(State[4] shr  8) and $FF] xor C7[(State[3]       ) and $FF] xor K[2];

    L[3] := C0[(State[3] shr 56)        ] xor C1[(State[2] shr 48) and $FF] xor
            C2[(State[1] shr 40) and $FF] xor C3[(State[0] shr 32) and $FF] xor
            C4[(State[7] shr 24) and $FF] xor C5[(State[6] shr 16) and $FF] xor
            C6[(State[5] shr  8) and $FF] xor C7[(State[4]       ) and $FF] xor K[3];

    L[4] := C0[(State[4] shr 56)        ] xor C1[(State[3] shr 48) and $FF] xor
            C2[(State[2] shr 40) and $FF] xor C3[(State[1] shr 32) and $FF] xor
            C4[(State[0] shr 24) and $FF] xor C5[(State[7] shr 16) and $FF] xor
            C6[(State[6] shr  8) and $FF] xor C7[(State[5]       ) and $FF] xor K[4];

    L[5] := C0[(State[5] shr 56)        ] xor C1[(State[4] shr 48) and $FF] xor
            C2[(State[3] shr 40) and $FF] xor C3[(State[2] shr 32) and $FF] xor
            C4[(State[1] shr 24) and $FF] xor C5[(State[0] shr 16) and $FF] xor
            C6[(State[7] shr  8) and $FF] xor C7[(State[6]       ) and $FF] xor K[5];

    L[6] := C0[(State[6] shr 56)        ] xor C1[(State[5] shr 48) and $FF] xor
            C2[(State[4] shr 40) and $FF] xor C3[(State[3] shr 32) and $FF] xor
            C4[(State[2] shr 24) and $FF] xor C5[(State[1] shr 16) and $FF] xor
            C6[(State[0] shr  8) and $FF] xor C7[(State[7]       ) and $FF] xor K[6];

    L[7] := C0[(State[7] shr 56)        ] xor C1[(State[6] shr 48) and $FF] xor
            C2[(State[5] shr 40) and $FF] xor C3[(State[4] shr 32) and $FF] xor
            C4[(State[3] shr 24) and $FF] xor C5[(State[2] shr 16) and $FF] xor
            C6[(State[1] shr  8) and $FF] xor C7[(State[0]       ) and $FF] xor K[7];

    State[0] := L[0];
    State[1] := L[1];
    State[2] := L[2];
    State[3] := L[3];
    State[4] := L[4];
    State[5] := L[5];
    State[6] := L[6];
    State[7] := L[7];
  end;

  Hash[0] := Hash[0] xor (State[0] xor Block[0]);
  Hash[1] := Hash[1] xor (State[1] xor Block[1]);
  Hash[2] := Hash[2] xor (State[2] xor Block[2]);
  Hash[3] := Hash[3] xor (State[3] xor Block[3]);
  Hash[4] := Hash[4] xor (State[4] xor Block[4]);
  Hash[5] := Hash[5] xor (State[5] xor Block[5]);
  Hash[6] := Hash[6] xor (State[6] xor Block[6]);
  Hash[7] := Hash[7] xor (State[7] xor Block[7]);
end;

procedure HashWhirlpool(var Context: TWhirlpoolContext; Chunk: Pointer; ChunkSize: LongWord);
var
  Block: Int64Array;
  Size: Cardinal;
  I, Carry: Integer;
  Hashed: Int64;
begin
  if (Chunk = nil) or (ChunkSize = 0) then
    Exit;

  Carry := 0;
  Hashed := ChunkSize shl 3;
  for I := 31 downto 0 do
  begin
    Carry := Carry + (Context.BitsHashed[I] and $FF) + Integer(Hashed and $FF);
    Context.BitsHashed[I] := Byte(Carry);
    Carry := Carry shr 8;
    Hashed := Hashed shr 8;
  end;

  if (Context.BufferSize + ChunkSize) < 64 then
  begin
    SBMove(PByte(Chunk)^, Context.Buffer[Context.BufferSize], ChunkSize);
    Inc(Context.BufferSize, ChunkSize);
    Exit;
  end;

  SetLength(Block, 8);

  if Context.BufferSize <> 0 then
  begin
    Size := Cardinal(Length(Context.Buffer)) - Context.BufferSize;
    SBMove(PByte(Chunk)^, Context.Buffer[Context.BufferSize], Size);
    Inc(PByte(Chunk), Size);
    Dec(ChunkSize, Size);

    PrepareWhirlpoolBlock(Context.Buffer, 0, Block);
    HashWhirlpoolBlock(Block, Context.State);

    Context.BufferSize := 0;
  end;

  while ChunkSize >= 64 do
  begin
    PrepareWhirlpoolBlock(PByte(Chunk), Block);
    HashWhirlpoolBlock(Block, Context.State);
    Inc(PByte(Chunk), 64);
    Dec(ChunkSize, 64);
  end;

  if ChunkSize <> 0 then
  begin
    SBMove(PByte(Chunk)^, Context.Buffer[0], ChunkSize);
    Context.BufferSize := ChunkSize;
  end;

  SetLength(Block, 0);
end;

procedure HashWhirlpool(var Context: TWhirlpoolContext; Chunk: ByteArray; ChunkOffset, ChunkSize: LongWord);
var
  Block: Int64Array;
  I, Carry: Integer;
  Hashed: Int64;
  Size: Cardinal;
begin
  if ChunkSize = 0 then
    Exit;

  Carry := 0;
  Hashed := ChunkSize shl 3;
  for I := 31 downto 0 do
  begin
    Carry := Carry + (Context.BitsHashed[I] and $FF) + Integer(Hashed and $FF);
    Context.BitsHashed[I] := Byte(Carry);
    Carry := Carry shr 8;
    Hashed := Hashed shr 8;
  end;

  if (Context.BufferSize + ChunkSize) < 64 then
  begin
    SBMove(Chunk[ChunkOffset], Context.Buffer[Context.BufferSize], ChunkSize);
    Inc(Context.BufferSize, ChunkSize);
    Exit;
  end;

  SetLength(Block, 8);

  if Context.BufferSize <> 0 then
  begin
    Size := Cardinal(Length(Context.Buffer)) - Context.BufferSize;
    SBMove(Chunk[ChunkOffset], Context.Buffer[Context.BufferSize], Size);
    Inc(ChunkOffset, Size);
    Dec(ChunkSize, Size);

    PrepareWhirlpoolBlock(Context.Buffer, 0, Block);
    HashWhirlpoolBlock(Block, Context.State);

    Context.BufferSize := 0;
  end;

  while ChunkSize >= 64 do
  begin
    PrepareWhirlpoolBlock(Chunk, ChunkOffset, Block);
    HashWhirlpoolBlock(Block, Context.State);
    Inc(ChunkOffset, 64);
    Dec(ChunkSize, 64);
  end;

  if ChunkSize <> 0 then
  begin
    SBMove(Chunk[ChunkOffset], Context.Buffer[0], ChunkSize);
    Context.BufferSize := ChunkSize;
  end;

  SetLength(Block, 0);
end;

function FinalizeWhirlpool(var Context: TWhirlpoolContext): TMessageDigest512;
var
  Block: Int64Array;
begin
  SetLength(Block, 8);

  Context.Buffer[Context.BufferSize] := $80;
  Inc(Context.BufferSize);

  if Context.BufferSize > 32 then
  begin
    while Context.BufferSize < 64 do
    begin
      Context.Buffer[Context.BufferSize] := 0;
      Inc(Context.BufferSize);
    end;

    PrepareWhirlpoolBlock(Context.Buffer, 0, Block);
    HashWhirlpoolBlock(Block, Context.State);

    Context.BufferSize := 0;
  end;

  while Context.BufferSize < 32 do
  begin
    Context.Buffer[Context.BufferSize] := 0;
    Inc(Context.BufferSize);
  end;

  SBMove(Context.BitsHashed[0], Context.Buffer[32], 32);

  PrepareWhirlpoolBlock(Context.Buffer, 0, Block);
  HashWhirlpoolBlock(Block, Context.State);

  Result.A1 := SwapInt64(Context.State[0]);
  Result.B1 := SwapInt64(Context.State[1]);
  Result.C1 := SwapInt64(Context.State[2]);
  Result.D1 := SwapInt64(Context.State[3]);
  Result.A2 := SwapInt64(Context.State[4]);
  Result.B2 := SwapInt64(Context.State[5]);
  Result.C2 := SwapInt64(Context.State[6]);
  Result.D2 := SwapInt64(Context.State[7]);

  ReleaseArray(Context.BitsHashed);
  ReleaseArray(Context.Buffer);
  SetLength(Context.State, 0);
  Context.BufferSize := 0;

  SetLength(Block, 0);
end;

end.
