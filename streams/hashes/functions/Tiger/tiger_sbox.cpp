//
// Created by Dusan Klinec on 23/03/2018.
//
/* tiger_sbox.c - S-Box for Tiger hash function
 *
 * Copyright: 2007-2012 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted,  free of charge,  to any person  obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction,  including without limitation
 * the rights to  use, copy, modify,  merge, publish, distribute, sublicense,
 * and/or sell copies  of  the Software,  and to permit  persons  to whom the
 * Software is furnished to do so.
 *
 * This program  is  distributed  in  the  hope  that it will be useful,  but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  Use this program  at  your own risk!
 */
#include "../Whirlpool/byte_order.h"

/* Four S-boxes used for table lookups by Tiger hash function. 8Kb in total. */
uint64_t rhash_tiger_sboxes[4][256] = {
    {
        I64(0x02AAB17CF7E90C5E),  I64(0xAC424B03E243A8EC),
        I64(0x72CD5BE30DD5FCD3),  I64(0x6D019B93F6F97F3A),
        I64(0xCD9978FFD21F9193),  I64(0x7573A1C9708029E2),
        I64(0xB164326B922A83C3),  I64(0x46883EEE04915870),
        I64(0xEAACE3057103ECE6),  I64(0xC54169B808A3535C),
        I64(0x4CE754918DDEC47C),  I64(0x0AA2F4DFDC0DF40C),
        I64(0x10B76F18A74DBEFA),  I64(0xC6CCB6235AD1AB6A),
        I64(0x13726121572FE2FF),  I64(0x1A488C6F199D921E),
        I64(0x4BC9F9F4DA0007CA),  I64(0x26F5E6F6E85241C7),
        I64(0x859079DBEA5947B6),  I64(0x4F1885C5C99E8C92),
        I64(0xD78E761EA96F864B),  I64(0x8E36428C52B5C17D),
        I64(0x69CF6827373063C1),  I64(0xB607C93D9BB4C56E),
        I64(0x7D820E760E76B5EA),  I64(0x645C9CC6F07FDC42),
        I64(0xBF38A078243342E0),  I64(0x5F6B343C9D2E7D04),
        I64(0xF2C28AEB600B0EC6),  I64(0x6C0ED85F7254BCAC),
        I64(0x71592281A4DB4FE5),  I64(0x1967FA69CE0FED9F),
        I64(0xFD5293F8B96545DB),  I64(0xC879E9D7F2A7600B),
        I64(0x860248920193194E),  I64(0xA4F9533B2D9CC0B3),
        I64(0x9053836C15957613),  I64(0xDB6DCF8AFC357BF1),
        I64(0x18BEEA7A7A370F57),  I64(0x037117CA50B99066),
        I64(0x6AB30A9774424A35),  I64(0xF4E92F02E325249B),
        I64(0x7739DB07061CCAE1),  I64(0xD8F3B49CECA42A05),
        I64(0xBD56BE3F51382F73),  I64(0x45FAED5843B0BB28),
        I64(0x1C813D5C11BF1F83),  I64(0x8AF0E4B6D75FA169),
        I64(0x33EE18A487AD9999),  I64(0x3C26E8EAB1C94410),
        I64(0xB510102BC0A822F9),  I64(0x141EEF310CE6123B),
        I64(0xFC65B90059DDB154),  I64(0xE0158640C5E0E607),
        I64(0x884E079826C3A3CF),  I64(0x930D0D9523C535FD),
        I64(0x35638D754E9A2B00),  I64(0x4085FCCF40469DD5),
        I64(0xC4B17AD28BE23A4C),  I64(0xCAB2F0FC6A3E6A2E),
        I64(0x2860971A6B943FCD),  I64(0x3DDE6EE212E30446),
        I64(0x6222F32AE01765AE),  I64(0x5D550BB5478308FE),
        I64(0xA9EFA98DA0EDA22A),  I64(0xC351A71686C40DA7),
        I64(0x1105586D9C867C84),  I64(0xDCFFEE85FDA22853),
        I64(0xCCFBD0262C5EEF76),  I64(0xBAF294CB8990D201),
        I64(0xE69464F52AFAD975),  I64(0x94B013AFDF133E14),
        I64(0x06A7D1A32823C958),  I64(0x6F95FE5130F61119),
        I64(0xD92AB34E462C06C0),  I64(0xED7BDE33887C71D2),
        I64(0x79746D6E6518393E),  I64(0x5BA419385D713329),
        I64(0x7C1BA6B948A97564),  I64(0x31987C197BFDAC67),
        I64(0xDE6C23C44B053D02),  I64(0x581C49FED002D64D),
        I64(0xDD474D6338261571),  I64(0xAA4546C3E473D062),
        I64(0x928FCE349455F860),  I64(0x48161BBACAAB94D9),
        I64(0x63912430770E6F68),  I64(0x6EC8A5E602C6641C),
        I64(0x87282515337DDD2B),  I64(0x2CDA6B42034B701B),
        I64(0xB03D37C181CB096D),  I64(0xE108438266C71C6F),
        I64(0x2B3180C7EB51B255),  I64(0xDF92B82F96C08BBC),
        I64(0x5C68C8C0A632F3BA),  I64(0x5504CC861C3D0556),
        I64(0xABBFA4E55FB26B8F),  I64(0x41848B0AB3BACEB4),
        I64(0xB334A273AA445D32),  I64(0xBCA696F0A85AD881),
        I64(0x24F6EC65B528D56C),  I64(0x0CE1512E90F4524A),
        I64(0x4E9DD79D5506D35A),  I64(0x258905FAC6CE9779),
        I64(0x2019295B3E109B33),  I64(0xF8A9478B73A054CC),
        I64(0x2924F2F934417EB0),  I64(0x3993357D536D1BC4),
        I64(0x38A81AC21DB6FF8B),  I64(0x47C4FBF17D6016BF),
        I64(0x1E0FAADD7667E3F5),  I64(0x7ABCFF62938BEB96),
        I64(0xA78DAD948FC179C9),  I64(0x8F1F98B72911E50D),
        I64(0x61E48EAE27121A91),  I64(0x4D62F7AD31859808),
        I64(0xECEBA345EF5CEAEB),  I64(0xF5CEB25EBC9684CE),
        I64(0xF633E20CB7F76221),  I64(0xA32CDF06AB8293E4),
        I64(0x985A202CA5EE2CA4),  I64(0xCF0B8447CC8A8FB1),
        I64(0x9F765244979859A3),  I64(0xA8D516B1A1240017),
        I64(0x0BD7BA3EBB5DC726),  I64(0xE54BCA55B86ADB39),
        I64(0x1D7A3AFD6C478063),  I64(0x519EC608E7669EDD),
        I64(0x0E5715A2D149AA23),  I64(0x177D4571848FF194),
        I64(0xEEB55F3241014C22),  I64(0x0F5E5CA13A6E2EC2),
        I64(0x8029927B75F5C361),  I64(0xAD139FABC3D6E436),
        I64(0x0D5DF1A94CCF402F),  I64(0x3E8BD948BEA5DFC8),
        I64(0xA5A0D357BD3FF77E),  I64(0xA2D12E251F74F645),
        I64(0x66FD9E525E81A082),  I64(0x2E0C90CE7F687A49),
        I64(0xC2E8BCBEBA973BC5),  I64(0x000001BCE509745F),
        I64(0x423777BBE6DAB3D6),  I64(0xD1661C7EAEF06EB5),
        I64(0xA1781F354DAACFD8),  I64(0x2D11284A2B16AFFC),
        I64(0xF1FC4F67FA891D1F),  I64(0x73ECC25DCB920ADA),
        I64(0xAE610C22C2A12651),  I64(0x96E0A810D356B78A),
        I64(0x5A9A381F2FE7870F),  I64(0xD5AD62EDE94E5530),
        I64(0xD225E5E8368D1427),  I64(0x65977B70C7AF4631),
        I64(0x99F889B2DE39D74F),  I64(0x233F30BF54E1D143),
        I64(0x9A9675D3D9A63C97),  I64(0x5470554FF334F9A8),
        I64(0x166ACB744A4F5688),  I64(0x70C74CAAB2E4AEAD),
        I64(0xF0D091646F294D12),  I64(0x57B82A89684031D1),
        I64(0xEFD95A5A61BE0B6B),  I64(0x2FBD12E969F2F29A),
        I64(0x9BD37013FEFF9FE8),  I64(0x3F9B0404D6085A06),
        I64(0x4940C1F3166CFE15),  I64(0x09542C4DCDF3DEFB),
        I64(0xB4C5218385CD5CE3),  I64(0xC935B7DC4462A641),
        I64(0x3417F8A68ED3B63F),  I64(0xB80959295B215B40),
        I64(0xF99CDAEF3B8C8572),  I64(0x018C0614F8FCB95D),
        I64(0x1B14ACCD1A3ACDF3),  I64(0x84D471F200BB732D),
        I64(0xC1A3110E95E8DA16),  I64(0x430A7220BF1A82B8),
        I64(0xB77E090D39DF210E),  I64(0x5EF4BD9F3CD05E9D),
        I64(0x9D4FF6DA7E57A444),  I64(0xDA1D60E183D4A5F8),
        I64(0xB287C38417998E47),  I64(0xFE3EDC121BB31886),
        I64(0xC7FE3CCC980CCBEF),  I64(0xE46FB590189BFD03),
        I64(0x3732FD469A4C57DC),  I64(0x7EF700A07CF1AD65),
        I64(0x59C64468A31D8859),  I64(0x762FB0B4D45B61F6),
        I64(0x155BAED099047718),  I64(0x68755E4C3D50BAA6),
        I64(0xE9214E7F22D8B4DF),  I64(0x2ADDBF532EAC95F4),
        I64(0x32AE3909B4BD0109),  I64(0x834DF537B08E3450),
        I64(0xFA209DA84220728D),  I64(0x9E691D9B9EFE23F7),
        I64(0x0446D288C4AE8D7F),  I64(0x7B4CC524E169785B),
        I64(0x21D87F0135CA1385),  I64(0xCEBB400F137B8AA5),
        I64(0x272E2B66580796BE),  I64(0x3612264125C2B0DE),
        I64(0x057702BDAD1EFBB2),  I64(0xD4BABB8EACF84BE9),
        I64(0x91583139641BC67B),  I64(0x8BDC2DE08036E024),
        I64(0x603C8156F49F68ED),  I64(0xF7D236F7DBEF5111),
        I64(0x9727C4598AD21E80),  I64(0xA08A0896670A5FD7),
        I64(0xCB4A8F4309EBA9CB),  I64(0x81AF564B0F7036A1),
        I64(0xC0B99AA778199ABD),  I64(0x959F1EC83FC8E952),
        I64(0x8C505077794A81B9),  I64(0x3ACAAF8F056338F0),
        I64(0x07B43F50627A6778),  I64(0x4A44AB49F5ECCC77),
        I64(0x3BC3D6E4B679EE98),  I64(0x9CC0D4D1CF14108C),
        I64(0x4406C00B206BC8A0),  I64(0x82A18854C8D72D89),
        I64(0x67E366B35C3C432C),  I64(0xB923DD61102B37F2),
        I64(0x56AB2779D884271D),  I64(0xBE83E1B0FF1525AF),
        I64(0xFB7C65D4217E49A9),  I64(0x6BDBE0E76D48E7D4),
        I64(0x08DF828745D9179E),  I64(0x22EA6A9ADD53BD34),
        I64(0xE36E141C5622200A),  I64(0x7F805D1B8CB750EE),
        I64(0xAFE5C7A59F58E837),  I64(0xE27F996A4FB1C23C),
        I64(0xD3867DFB0775F0D0),  I64(0xD0E673DE6E88891A),
        I64(0x123AEB9EAFB86C25),  I64(0x30F1D5D5C145B895),
        I64(0xBB434A2DEE7269E7),  I64(0x78CB67ECF931FA38),
        I64(0xF33B0372323BBF9C),  I64(0x52D66336FB279C74),
        I64(0x505F33AC0AFB4EAA),  I64(0xE8A5CD99A2CCE187),
        I64(0x534974801E2D30BB),  I64(0x8D2D5711D5876D90),
        I64(0x1F1A412891BC038E),  I64(0xD6E2E71D82E56648),
        I64(0x74036C3A497732B7),  I64(0x89B67ED96361F5AB),
        I64(0xFFED95D8F1EA02A2),  I64(0xE72B3BD61464D43D),
        I64(0xA6300F170BDC4820),  I64(0xEBC18760ED78A77A)
    }, {
        I64(0xE6A6BE5A05A12138),  I64(0xB5A122A5B4F87C98),
        I64(0x563C6089140B6990),  I64(0x4C46CB2E391F5DD5),
        I64(0xD932ADDBC9B79434),  I64(0x08EA70E42015AFF5),
        I64(0xD765A6673E478CF1),  I64(0xC4FB757EAB278D99),
        I64(0xDF11C6862D6E0692),  I64(0xDDEB84F10D7F3B16),
        I64(0x6F2EF604A665EA04),  I64(0x4A8E0F0FF0E0DFB3),
        I64(0xA5EDEEF83DBCBA51),  I64(0xFC4F0A2A0EA4371E),
        I64(0xE83E1DA85CB38429),  I64(0xDC8FF882BA1B1CE2),
        I64(0xCD45505E8353E80D),  I64(0x18D19A00D4DB0717),
        I64(0x34A0CFEDA5F38101),  I64(0x0BE77E518887CAF2),
        I64(0x1E341438B3C45136),  I64(0xE05797F49089CCF9),
        I64(0xFFD23F9DF2591D14),  I64(0x543DDA228595C5CD),
        I64(0x661F81FD99052A33),  I64(0x8736E641DB0F7B76),
        I64(0x15227725418E5307),  I64(0xE25F7F46162EB2FA),
        I64(0x48A8B2126C13D9FE),  I64(0xAFDC541792E76EEA),
        I64(0x03D912BFC6D1898F),  I64(0x31B1AAFA1B83F51B),
        I64(0xF1AC2796E42AB7D9),  I64(0x40A3A7D7FCD2EBAC),
        I64(0x1056136D0AFBBCC5),  I64(0x7889E1DD9A6D0C85),
        I64(0xD33525782A7974AA),  I64(0xA7E25D09078AC09B),
        I64(0xBD4138B3EAC6EDD0),  I64(0x920ABFBE71EB9E70),
        I64(0xA2A5D0F54FC2625C),  I64(0xC054E36B0B1290A3),
        I64(0xF6DD59FF62FE932B),  I64(0x3537354511A8AC7D),
        I64(0xCA845E9172FADCD4),  I64(0x84F82B60329D20DC),
        I64(0x79C62CE1CD672F18),  I64(0x8B09A2ADD124642C),
        I64(0xD0C1E96A19D9E726),  I64(0x5A786A9B4BA9500C),
        I64(0x0E020336634C43F3),  I64(0xC17B474AEB66D822),
        I64(0x6A731AE3EC9BAAC2),  I64(0x8226667AE0840258),
        I64(0x67D4567691CAECA5),  I64(0x1D94155C4875ADB5),
        I64(0x6D00FD985B813FDF),  I64(0x51286EFCB774CD06),
        I64(0x5E8834471FA744AF),  I64(0xF72CA0AEE761AE2E),
        I64(0xBE40E4CDAEE8E09A),  I64(0xE9970BBB5118F665),
        I64(0x726E4BEB33DF1964),  I64(0x703B000729199762),
        I64(0x4631D816F5EF30A7),  I64(0xB880B5B51504A6BE),
        I64(0x641793C37ED84B6C),  I64(0x7B21ED77F6E97D96),
        I64(0x776306312EF96B73),  I64(0xAE528948E86FF3F4),
        I64(0x53DBD7F286A3F8F8),  I64(0x16CADCE74CFC1063),
        I64(0x005C19BDFA52C6DD),  I64(0x68868F5D64D46AD3),
        I64(0x3A9D512CCF1E186A),  I64(0x367E62C2385660AE),
        I64(0xE359E7EA77DCB1D7),  I64(0x526C0773749ABE6E),
        I64(0x735AE5F9D09F734B),  I64(0x493FC7CC8A558BA8),
        I64(0xB0B9C1533041AB45),  I64(0x321958BA470A59BD),
        I64(0x852DB00B5F46C393),  I64(0x91209B2BD336B0E5),
        I64(0x6E604F7D659EF19F),  I64(0xB99A8AE2782CCB24),
        I64(0xCCF52AB6C814C4C7),  I64(0x4727D9AFBE11727B),
        I64(0x7E950D0C0121B34D),  I64(0x756F435670AD471F),
        I64(0xF5ADD442615A6849),  I64(0x4E87E09980B9957A),
        I64(0x2ACFA1DF50AEE355),  I64(0xD898263AFD2FD556),
        I64(0xC8F4924DD80C8FD6),  I64(0xCF99CA3D754A173A),
        I64(0xFE477BACAF91BF3C),  I64(0xED5371F6D690C12D),
        I64(0x831A5C285E687094),  I64(0xC5D3C90A3708A0A4),
        I64(0x0F7F903717D06580),  I64(0x19F9BB13B8FDF27F),
        I64(0xB1BD6F1B4D502843),  I64(0x1C761BA38FFF4012),
        I64(0x0D1530C4E2E21F3B),  I64(0x8943CE69A7372C8A),
        I64(0xE5184E11FEB5CE66),  I64(0x618BDB80BD736621),
        I64(0x7D29BAD68B574D0B),  I64(0x81BB613E25E6FE5B),
        I64(0x071C9C10BC07913F),  I64(0xC7BEEB7909AC2D97),
        I64(0xC3E58D353BC5D757),  I64(0xEB017892F38F61E8),
        I64(0xD4EFFB9C9B1CC21A),  I64(0x99727D26F494F7AB),
        I64(0xA3E063A2956B3E03),  I64(0x9D4A8B9A4AA09C30),
        I64(0x3F6AB7D500090FB4),  I64(0x9CC0F2A057268AC0),
        I64(0x3DEE9D2DEDBF42D1),  I64(0x330F49C87960A972),
        I64(0xC6B2720287421B41),  I64(0x0AC59EC07C00369C),
        I64(0xEF4EAC49CB353425),  I64(0xF450244EEF0129D8),
        I64(0x8ACC46E5CAF4DEB6),  I64(0x2FFEAB63989263F7),
        I64(0x8F7CB9FE5D7A4578),  I64(0x5BD8F7644E634635),
        I64(0x427A7315BF2DC900),  I64(0x17D0C4AA2125261C),
        I64(0x3992486C93518E50),  I64(0xB4CBFEE0A2D7D4C3),
        I64(0x7C75D6202C5DDD8D),  I64(0xDBC295D8E35B6C61),
        I64(0x60B369D302032B19),  I64(0xCE42685FDCE44132),
        I64(0x06F3DDB9DDF65610),  I64(0x8EA4D21DB5E148F0),
        I64(0x20B0FCE62FCD496F),  I64(0x2C1B912358B0EE31),
        I64(0xB28317B818F5A308),  I64(0xA89C1E189CA6D2CF),
        I64(0x0C6B18576AAADBC8),  I64(0xB65DEAA91299FAE3),
        I64(0xFB2B794B7F1027E7),  I64(0x04E4317F443B5BEB),
        I64(0x4B852D325939D0A6),  I64(0xD5AE6BEEFB207FFC),
        I64(0x309682B281C7D374),  I64(0xBAE309A194C3B475),
        I64(0x8CC3F97B13B49F05),  I64(0x98A9422FF8293967),
        I64(0x244B16B01076FF7C),  I64(0xF8BF571C663D67EE),
        I64(0x1F0D6758EEE30DA1),  I64(0xC9B611D97ADEB9B7),
        I64(0xB7AFD5887B6C57A2),  I64(0x6290AE846B984FE1),
        I64(0x94DF4CDEACC1A5FD),  I64(0x058A5BD1C5483AFF),
        I64(0x63166CC142BA3C37),  I64(0x8DB8526EB2F76F40),
        I64(0xE10880036F0D6D4E),  I64(0x9E0523C9971D311D),
        I64(0x45EC2824CC7CD691),  I64(0x575B8359E62382C9),
        I64(0xFA9E400DC4889995),  I64(0xD1823ECB45721568),
        I64(0xDAFD983B8206082F),  I64(0xAA7D29082386A8CB),
        I64(0x269FCD4403B87588),  I64(0x1B91F5F728BDD1E0),
        I64(0xE4669F39040201F6),  I64(0x7A1D7C218CF04ADE),
        I64(0x65623C29D79CE5CE),  I64(0x2368449096C00BB1),
        I64(0xAB9BF1879DA503BA),  I64(0xBC23ECB1A458058E),
        I64(0x9A58DF01BB401ECC),  I64(0xA070E868A85F143D),
        I64(0x4FF188307DF2239E),  I64(0x14D565B41A641183),
        I64(0xEE13337452701602),  I64(0x950E3DCF3F285E09),
        I64(0x59930254B9C80953),  I64(0x3BF299408930DA6D),
        I64(0xA955943F53691387),  I64(0xA15EDECAA9CB8784),
        I64(0x29142127352BE9A0),  I64(0x76F0371FFF4E7AFB),
        I64(0x0239F450274F2228),  I64(0xBB073AF01D5E868B),
        I64(0xBFC80571C10E96C1),  I64(0xD267088568222E23),
        I64(0x9671A3D48E80B5B0),  I64(0x55B5D38AE193BB81),
        I64(0x693AE2D0A18B04B8),  I64(0x5C48B4ECADD5335F),
        I64(0xFD743B194916A1CA),  I64(0x2577018134BE98C4),
        I64(0xE77987E83C54A4AD),  I64(0x28E11014DA33E1B9),
        I64(0x270CC59E226AA213),  I64(0x71495F756D1A5F60),
        I64(0x9BE853FB60AFEF77),  I64(0xADC786A7F7443DBF),
        I64(0x0904456173B29A82),  I64(0x58BC7A66C232BD5E),
        I64(0xF306558C673AC8B2),  I64(0x41F639C6B6C9772A),
        I64(0x216DEFE99FDA35DA),  I64(0x11640CC71C7BE615),
        I64(0x93C43694565C5527),  I64(0xEA038E6246777839),
        I64(0xF9ABF3CE5A3E2469),  I64(0x741E768D0FD312D2),
        I64(0x0144B883CED652C6),  I64(0xC20B5A5BA33F8552),
        I64(0x1AE69633C3435A9D),  I64(0x97A28CA4088CFDEC),
        I64(0x8824A43C1E96F420),  I64(0x37612FA66EEEA746),
        I64(0x6B4CB165F9CF0E5A),  I64(0x43AA1C06A0ABFB4A),
        I64(0x7F4DC26FF162796B),  I64(0x6CBACC8E54ED9B0F),
        I64(0xA6B7FFEFD2BB253E),  I64(0x2E25BC95B0A29D4F),
        I64(0x86D6A58BDEF1388C),  I64(0xDED74AC576B6F054),
        I64(0x8030BDBC2B45805D),  I64(0x3C81AF70E94D9289),
        I64(0x3EFF6DDA9E3100DB),  I64(0xB38DC39FDFCC8847),
        I64(0x123885528D17B87E),  I64(0xF2DA0ED240B1B642),
        I64(0x44CEFADCD54BF9A9),  I64(0x1312200E433C7EE6),
        I64(0x9FFCC84F3A78C748),  I64(0xF0CD1F72248576BB),
        I64(0xEC6974053638CFE4),  I64(0x2BA7B67C0CEC4E4C),
        I64(0xAC2F4DF3E5CE32ED),  I64(0xCB33D14326EA4C11),
        I64(0xA4E9044CC77E58BC),  I64(0x5F513293D934FCEF),
        I64(0x5DC9645506E55444),  I64(0x50DE418F317DE40A),
        I64(0x388CB31A69DDE259),  I64(0x2DB4A83455820A86),
        I64(0x9010A91E84711AE9),  I64(0x4DF7F0B7B1498371),
        I64(0xD62A2EABC0977179),  I64(0x22FAC097AA8D5C0E)
    }, {
        I64(0xF49FCC2FF1DAF39B),  I64(0x487FD5C66FF29281),
        I64(0xE8A30667FCDCA83F),  I64(0x2C9B4BE3D2FCCE63),
        I64(0xDA3FF74B93FBBBC2),  I64(0x2FA165D2FE70BA66),
        I64(0xA103E279970E93D4),  I64(0xBECDEC77B0E45E71),
        I64(0xCFB41E723985E497),  I64(0xB70AAA025EF75017),
        I64(0xD42309F03840B8E0),  I64(0x8EFC1AD035898579),
        I64(0x96C6920BE2B2ABC5),  I64(0x66AF4163375A9172),
        I64(0x2174ABDCCA7127FB),  I64(0xB33CCEA64A72FF41),
        I64(0xF04A4933083066A5),  I64(0x8D970ACDD7289AF5),
        I64(0x8F96E8E031C8C25E),  I64(0xF3FEC02276875D47),
        I64(0xEC7BF310056190DD),  I64(0xF5ADB0AEBB0F1491),
        I64(0x9B50F8850FD58892),  I64(0x4975488358B74DE8),
        I64(0xA3354FF691531C61),  I64(0x0702BBE481D2C6EE),
        I64(0x89FB24057DEDED98),  I64(0xAC3075138596E902),
        I64(0x1D2D3580172772ED),  I64(0xEB738FC28E6BC30D),
        I64(0x5854EF8F63044326),  I64(0x9E5C52325ADD3BBE),
        I64(0x90AA53CF325C4623),  I64(0xC1D24D51349DD067),
        I64(0x2051CFEEA69EA624),  I64(0x13220F0A862E7E4F),
        I64(0xCE39399404E04864),  I64(0xD9C42CA47086FCB7),
        I64(0x685AD2238A03E7CC),  I64(0x066484B2AB2FF1DB),
        I64(0xFE9D5D70EFBF79EC),  I64(0x5B13B9DD9C481854),
        I64(0x15F0D475ED1509AD),  I64(0x0BEBCD060EC79851),
        I64(0xD58C6791183AB7F8),  I64(0xD1187C5052F3EEE4),
        I64(0xC95D1192E54E82FF),  I64(0x86EEA14CB9AC6CA2),
        I64(0x3485BEB153677D5D),  I64(0xDD191D781F8C492A),
        I64(0xF60866BAA784EBF9),  I64(0x518F643BA2D08C74),
        I64(0x8852E956E1087C22),  I64(0xA768CB8DC410AE8D),
        I64(0x38047726BFEC8E1A),  I64(0xA67738B4CD3B45AA),
        I64(0xAD16691CEC0DDE19),  I64(0xC6D4319380462E07),
        I64(0xC5A5876D0BA61938),  I64(0x16B9FA1FA58FD840),
        I64(0x188AB1173CA74F18),  I64(0xABDA2F98C99C021F),
        I64(0x3E0580AB134AE816),  I64(0x5F3B05B773645ABB),
        I64(0x2501A2BE5575F2F6),  I64(0x1B2F74004E7E8BA9),
        I64(0x1CD7580371E8D953),  I64(0x7F6ED89562764E30),
        I64(0xB15926FF596F003D),  I64(0x9F65293DA8C5D6B9),
        I64(0x6ECEF04DD690F84C),  I64(0x4782275FFF33AF88),
        I64(0xE41433083F820801),  I64(0xFD0DFE409A1AF9B5),
        I64(0x4325A3342CDB396B),  I64(0x8AE77E62B301B252),
        I64(0xC36F9E9F6655615A),  I64(0x85455A2D92D32C09),
        I64(0xF2C7DEA949477485),  I64(0x63CFB4C133A39EBA),
        I64(0x83B040CC6EBC5462),  I64(0x3B9454C8FDB326B0),
        I64(0x56F56A9E87FFD78C),  I64(0x2DC2940D99F42BC6),
        I64(0x98F7DF096B096E2D),  I64(0x19A6E01E3AD852BF),
        I64(0x42A99CCBDBD4B40B),  I64(0xA59998AF45E9C559),
        I64(0x366295E807D93186),  I64(0x6B48181BFAA1F773),
        I64(0x1FEC57E2157A0A1D),  I64(0x4667446AF6201AD5),
        I64(0xE615EBCACFB0F075),  I64(0xB8F31F4F68290778),
        I64(0x22713ED6CE22D11E),  I64(0x3057C1A72EC3C93B),
        I64(0xCB46ACC37C3F1F2F),  I64(0xDBB893FD02AAF50E),
        I64(0x331FD92E600B9FCF),  I64(0xA498F96148EA3AD6),
        I64(0xA8D8426E8B6A83EA),  I64(0xA089B274B7735CDC),
        I64(0x87F6B3731E524A11),  I64(0x118808E5CBC96749),
        I64(0x9906E4C7B19BD394),  I64(0xAFED7F7E9B24A20C),
        I64(0x6509EADEEB3644A7),  I64(0x6C1EF1D3E8EF0EDE),
        I64(0xB9C97D43E9798FB4),  I64(0xA2F2D784740C28A3),
        I64(0x7B8496476197566F),  I64(0x7A5BE3E6B65F069D),
        I64(0xF96330ED78BE6F10),  I64(0xEEE60DE77A076A15),
        I64(0x2B4BEE4AA08B9BD0),  I64(0x6A56A63EC7B8894E),
        I64(0x02121359BA34FEF4),  I64(0x4CBF99F8283703FC),
        I64(0x398071350CAF30C8),  I64(0xD0A77A89F017687A),
        I64(0xF1C1A9EB9E423569),  I64(0x8C7976282DEE8199),
        I64(0x5D1737A5DD1F7ABD),  I64(0x4F53433C09A9FA80),
        I64(0xFA8B0C53DF7CA1D9),  I64(0x3FD9DCBC886CCB77),
        I64(0xC040917CA91B4720),  I64(0x7DD00142F9D1DCDF),
        I64(0x8476FC1D4F387B58),  I64(0x23F8E7C5F3316503),
        I64(0x032A2244E7E37339),  I64(0x5C87A5D750F5A74B),
        I64(0x082B4CC43698992E),  I64(0xDF917BECB858F63C),
        I64(0x3270B8FC5BF86DDA),  I64(0x10AE72BB29B5DD76),
        I64(0x576AC94E7700362B),  I64(0x1AD112DAC61EFB8F),
        I64(0x691BC30EC5FAA427),  I64(0xFF246311CC327143),
        I64(0x3142368E30E53206),  I64(0x71380E31E02CA396),
        I64(0x958D5C960AAD76F1),  I64(0xF8D6F430C16DA536),
        I64(0xC8FFD13F1BE7E1D2),  I64(0x7578AE66004DDBE1),
        I64(0x05833F01067BE646),  I64(0xBB34B5AD3BFE586D),
        I64(0x095F34C9A12B97F0),  I64(0x247AB64525D60CA8),
        I64(0xDCDBC6F3017477D1),  I64(0x4A2E14D4DECAD24D),
        I64(0xBDB5E6D9BE0A1EEB),  I64(0x2A7E70F7794301AB),
        I64(0xDEF42D8A270540FD),  I64(0x01078EC0A34C22C1),
        I64(0xE5DE511AF4C16387),  I64(0x7EBB3A52BD9A330A),
        I64(0x77697857AA7D6435),  I64(0x004E831603AE4C32),
        I64(0xE7A21020AD78E312),  I64(0x9D41A70C6AB420F2),
        I64(0x28E06C18EA1141E6),  I64(0xD2B28CBD984F6B28),
        I64(0x26B75F6C446E9D83),  I64(0xBA47568C4D418D7F),
        I64(0xD80BADBFE6183D8E),  I64(0x0E206D7F5F166044),
        I64(0xE258A43911CBCA3E),  I64(0x723A1746B21DC0BC),
        I64(0xC7CAA854F5D7CDD3),  I64(0x7CAC32883D261D9C),
        I64(0x7690C26423BA942C),  I64(0x17E55524478042B8),
        I64(0xE0BE477656A2389F),  I64(0x4D289B5E67AB2DA0),
        I64(0x44862B9C8FBBFD31),  I64(0xB47CC8049D141365),
        I64(0x822C1B362B91C793),  I64(0x4EB14655FB13DFD8),
        I64(0x1ECBBA0714E2A97B),  I64(0x6143459D5CDE5F14),
        I64(0x53A8FBF1D5F0AC89),  I64(0x97EA04D81C5E5B00),
        I64(0x622181A8D4FDB3F3),  I64(0xE9BCD341572A1208),
        I64(0x1411258643CCE58A),  I64(0x9144C5FEA4C6E0A4),
        I64(0x0D33D06565CF620F),  I64(0x54A48D489F219CA1),
        I64(0xC43E5EAC6D63C821),  I64(0xA9728B3A72770DAF),
        I64(0xD7934E7B20DF87EF),  I64(0xE35503B61A3E86E5),
        I64(0xCAE321FBC819D504),  I64(0x129A50B3AC60BFA6),
        I64(0xCD5E68EA7E9FB6C3),  I64(0xB01C90199483B1C7),
        I64(0x3DE93CD5C295376C),  I64(0xAED52EDF2AB9AD13),
        I64(0x2E60F512C0A07884),  I64(0xBC3D86A3E36210C9),
        I64(0x35269D9B163951CE),  I64(0x0C7D6E2AD0CDB5FA),
        I64(0x59E86297D87F5733),  I64(0x298EF221898DB0E7),
        I64(0x55000029D1A5AA7E),  I64(0x8BC08AE1B5061B45),
        I64(0xC2C31C2B6C92703A),  I64(0x94CC596BAF25EF42),
        I64(0x0A1D73DB22540456),  I64(0x04B6A0F9D9C4179A),
        I64(0xEFFDAFA2AE3D3C60),  I64(0xF7C8075BB49496C4),
        I64(0x9CC5C7141D1CD4E3),  I64(0x78BD1638218E5534),
        I64(0xB2F11568F850246A),  I64(0xEDFABCFA9502BC29),
        I64(0x796CE5F2DA23051B),  I64(0xAAE128B0DC93537C),
        I64(0x3A493DA0EE4B29AE),  I64(0xB5DF6B2C416895D7),
        I64(0xFCABBD25122D7F37),  I64(0x70810B58105DC4B1),
        I64(0xE10FDD37F7882A90),  I64(0x524DCAB5518A3F5C),
        I64(0x3C9E85878451255B),  I64(0x4029828119BD34E2),
        I64(0x74A05B6F5D3CECCB),  I64(0xB610021542E13ECA),
        I64(0x0FF979D12F59E2AC),  I64(0x6037DA27E4F9CC50),
        I64(0x5E92975A0DF1847D),  I64(0xD66DE190D3E623FE),
        I64(0x5032D6B87B568048),  I64(0x9A36B7CE8235216E),
        I64(0x80272A7A24F64B4A),  I64(0x93EFED8B8C6916F7),
        I64(0x37DDBFF44CCE1555),  I64(0x4B95DB5D4B99BD25),
        I64(0x92D3FDA169812FC0),  I64(0xFB1A4A9A90660BB6),
        I64(0x730C196946A4B9B2),  I64(0x81E289AA7F49DA68),
        I64(0x64669A0F83B1A05F),  I64(0x27B3FF7D9644F48B),
        I64(0xCC6B615C8DB675B3),  I64(0x674F20B9BCEBBE95),
        I64(0x6F31238275655982),  I64(0x5AE488713E45CF05),
        I64(0xBF619F9954C21157),  I64(0xEABAC46040A8EAE9),
        I64(0x454C6FE9F2C0C1CD),  I64(0x419CF6496412691C),
        I64(0xD3DC3BEF265B0F70),  I64(0x6D0E60F5C3578A9E)
    }, {
        I64(0x5B0E608526323C55),  I64(0x1A46C1A9FA1B59F5),
        I64(0xA9E245A17C4C8FFA),  I64(0x65CA5159DB2955D7),
        I64(0x05DB0A76CE35AFC2),  I64(0x81EAC77EA9113D45),
        I64(0x528EF88AB6AC0A0D),  I64(0xA09EA253597BE3FF),
        I64(0x430DDFB3AC48CD56),  I64(0xC4B3A67AF45CE46F),
        I64(0x4ECECFD8FBE2D05E),  I64(0x3EF56F10B39935F0),
        I64(0x0B22D6829CD619C6),  I64(0x17FD460A74DF2069),
        I64(0x6CF8CC8E8510ED40),  I64(0xD6C824BF3A6ECAA7),
        I64(0x61243D581A817049),  I64(0x048BACB6BBC163A2),
        I64(0xD9A38AC27D44CC32),  I64(0x7FDDFF5BAAF410AB),
        I64(0xAD6D495AA804824B),  I64(0xE1A6A74F2D8C9F94),
        I64(0xD4F7851235DEE8E3),  I64(0xFD4B7F886540D893),
        I64(0x247C20042AA4BFDA),  I64(0x096EA1C517D1327C),
        I64(0xD56966B4361A6685),  I64(0x277DA5C31221057D),
        I64(0x94D59893A43ACFF7),  I64(0x64F0C51CCDC02281),
        I64(0x3D33BCC4FF6189DB),  I64(0xE005CB184CE66AF1),
        I64(0xFF5CCD1D1DB99BEA),  I64(0xB0B854A7FE42980F),
        I64(0x7BD46A6A718D4B9F),  I64(0xD10FA8CC22A5FD8C),
        I64(0xD31484952BE4BD31),  I64(0xC7FA975FCB243847),
        I64(0x4886ED1E5846C407),  I64(0x28CDDB791EB70B04),
        I64(0xC2B00BE2F573417F),  I64(0x5C9590452180F877),
        I64(0x7A6BDDFFF370EB00),  I64(0xCE509E38D6D9D6A4),
        I64(0xEBEB0F00647FA702),  I64(0x1DCC06CF76606F06),
        I64(0xE4D9F28BA286FF0A),  I64(0xD85A305DC918C262),
        I64(0x475B1D8732225F54),  I64(0x2D4FB51668CCB5FE),
        I64(0xA679B9D9D72BBA20),  I64(0x53841C0D912D43A5),
        I64(0x3B7EAA48BF12A4E8),  I64(0x781E0E47F22F1DDF),
        I64(0xEFF20CE60AB50973),  I64(0x20D261D19DFFB742),
        I64(0x16A12B03062A2E39),  I64(0x1960EB2239650495),
        I64(0x251C16FED50EB8B8),  I64(0x9AC0C330F826016E),
        I64(0xED152665953E7671),  I64(0x02D63194A6369570),
        I64(0x5074F08394B1C987),  I64(0x70BA598C90B25CE1),
        I64(0x794A15810B9742F6),  I64(0x0D5925E9FCAF8C6C),
        I64(0x3067716CD868744E),  I64(0x910AB077E8D7731B),
        I64(0x6A61BBDB5AC42F61),  I64(0x93513EFBF0851567),
        I64(0xF494724B9E83E9D5),  I64(0xE887E1985C09648D),
        I64(0x34B1D3C675370CFD),  I64(0xDC35E433BC0D255D),
        I64(0xD0AAB84234131BE0),  I64(0x08042A50B48B7EAF),
        I64(0x9997C4EE44A3AB35),  I64(0x829A7B49201799D0),
        I64(0x263B8307B7C54441),  I64(0x752F95F4FD6A6CA6),
        I64(0x927217402C08C6E5),  I64(0x2A8AB754A795D9EE),
        I64(0xA442F7552F72943D),  I64(0x2C31334E19781208),
        I64(0x4FA98D7CEAEE6291),  I64(0x55C3862F665DB309),
        I64(0xBD0610175D53B1F3),  I64(0x46FE6CB840413F27),
        I64(0x3FE03792DF0CFA59),  I64(0xCFE700372EB85E8F),
        I64(0xA7BE29E7ADBCE118),  I64(0xE544EE5CDE8431DD),
        I64(0x8A781B1B41F1873E),  I64(0xA5C94C78A0D2F0E7),
        I64(0x39412E2877B60728),  I64(0xA1265EF3AFC9A62C),
        I64(0xBCC2770C6A2506C5),  I64(0x3AB66DD5DCE1CE12),
        I64(0xE65499D04A675B37),  I64(0x7D8F523481BFD216),
        I64(0x0F6F64FCEC15F389),  I64(0x74EFBE618B5B13C8),
        I64(0xACDC82B714273E1D),  I64(0xDD40BFE003199D17),
        I64(0x37E99257E7E061F8),  I64(0xFA52626904775AAA),
        I64(0x8BBBF63A463D56F9),  I64(0xF0013F1543A26E64),
        I64(0xA8307E9F879EC898),  I64(0xCC4C27A4150177CC),
        I64(0x1B432F2CCA1D3348),  I64(0xDE1D1F8F9F6FA013),
        I64(0x606602A047A7DDD6),  I64(0xD237AB64CC1CB2C7),
        I64(0x9B938E7225FCD1D3),  I64(0xEC4E03708E0FF476),
        I64(0xFEB2FBDA3D03C12D),  I64(0xAE0BCED2EE43889A),
        I64(0x22CB8923EBFB4F43),  I64(0x69360D013CF7396D),
        I64(0x855E3602D2D4E022),  I64(0x073805BAD01F784C),
        I64(0x33E17A133852F546),  I64(0xDF4874058AC7B638),
        I64(0xBA92B29C678AA14A),  I64(0x0CE89FC76CFAADCD),
        I64(0x5F9D4E0908339E34),  I64(0xF1AFE9291F5923B9),
        I64(0x6E3480F60F4A265F),  I64(0xEEBF3A2AB29B841C),
        I64(0xE21938A88F91B4AD),  I64(0x57DFEFF845C6D3C3),
        I64(0x2F006B0BF62CAAF2),  I64(0x62F479EF6F75EE78),
        I64(0x11A55AD41C8916A9),  I64(0xF229D29084FED453),
        I64(0x42F1C27B16B000E6),  I64(0x2B1F76749823C074),
        I64(0x4B76ECA3C2745360),  I64(0x8C98F463B91691BD),
        I64(0x14BCC93CF1ADE66A),  I64(0x8885213E6D458397),
        I64(0x8E177DF0274D4711),  I64(0xB49B73B5503F2951),
        I64(0x10168168C3F96B6B),  I64(0x0E3D963B63CAB0AE),
        I64(0x8DFC4B5655A1DB14),  I64(0xF789F1356E14DE5C),
        I64(0x683E68AF4E51DAC1),  I64(0xC9A84F9D8D4B0FD9),
        I64(0x3691E03F52A0F9D1),  I64(0x5ED86E46E1878E80),
        I64(0x3C711A0E99D07150),  I64(0x5A0865B20C4E9310),
        I64(0x56FBFC1FE4F0682E),  I64(0xEA8D5DE3105EDF9B),
        I64(0x71ABFDB12379187A),  I64(0x2EB99DE1BEE77B9C),
        I64(0x21ECC0EA33CF4523),  I64(0x59A4D7521805C7A1),
        I64(0x3896F5EB56AE7C72),  I64(0xAA638F3DB18F75DC),
        I64(0x9F39358DABE9808E),  I64(0xB7DEFA91C00B72AC),
        I64(0x6B5541FD62492D92),  I64(0x6DC6DEE8F92E4D5B),
        I64(0x353F57ABC4BEEA7E),  I64(0x735769D6DA5690CE),
        I64(0x0A234AA642391484),  I64(0xF6F9508028F80D9D),
        I64(0xB8E319A27AB3F215),  I64(0x31AD9C1151341A4D),
        I64(0x773C22A57BEF5805),  I64(0x45C7561A07968633),
        I64(0xF913DA9E249DBE36),  I64(0xDA652D9B78A64C68),
        I64(0x4C27A97F3BC334EF),  I64(0x76621220E66B17F4),
        I64(0x967743899ACD7D0B),  I64(0xF3EE5BCAE0ED6782),
        I64(0x409F753600C879FC),  I64(0x06D09A39B5926DB6),
        I64(0x6F83AEB0317AC588),  I64(0x01E6CA4A86381F21),
        I64(0x66FF3462D19F3025),  I64(0x72207C24DDFD3BFB),
        I64(0x4AF6B6D3E2ECE2EB),  I64(0x9C994DBEC7EA08DE),
        I64(0x49ACE597B09A8BC4),  I64(0xB38C4766CF0797BA),
        I64(0x131B9373C57C2A75),  I64(0xB1822CCE61931E58),
        I64(0x9D7555B909BA1C0C),  I64(0x127FAFDD937D11D2),
        I64(0x29DA3BADC66D92E4),  I64(0xA2C1D57154C2ECBC),
        I64(0x58C5134D82F6FE24),  I64(0x1C3AE3515B62274F),
        I64(0xE907C82E01CB8126),  I64(0xF8ED091913E37FCB),
        I64(0x3249D8F9C80046C9),  I64(0x80CF9BEDE388FB63),
        I64(0x1881539A116CF19E),  I64(0x5103F3F76BD52457),
        I64(0x15B7E6F5AE47F7A8),  I64(0xDBD7C6DED47E9CCF),
        I64(0x44E55C410228BB1A),  I64(0xB647D4255EDB4E99),
        I64(0x5D11882BB8AAFC30),  I64(0xF5098BBB29D3212A),
        I64(0x8FB5EA14E90296B3),  I64(0x677B942157DD025A),
        I64(0xFB58E7C0A390ACB5),  I64(0x89D3674C83BD4A01),
        I64(0x9E2DA4DF4BF3B93B),  I64(0xFCC41E328CAB4829),
        I64(0x03F38C96BA582C52),  I64(0xCAD1BDBD7FD85DB2),
        I64(0xBBB442C16082AE83),  I64(0xB95FE86BA5DA9AB0),
        I64(0xB22E04673771A93F),  I64(0x845358C9493152D8),
        I64(0xBE2A488697B4541E),  I64(0x95A2DC2DD38E6966),
        I64(0xC02C11AC923C852B),  I64(0x2388B1990DF2A87B),
        I64(0x7C8008FA1B4F37BE),  I64(0x1F70D0C84D54E503),
        I64(0x5490ADEC7ECE57D4),  I64(0x002B3C27D9063A3A),
        I64(0x7EAEA3848030A2BF),  I64(0xC602326DED2003C0),
        I64(0x83A7287D69A94086),  I64(0xC57A5FCB30F57A8A),
        I64(0xB56844E479EBE779),  I64(0xA373B40F05DCBCE9),
        I64(0xD71A786E88570EE2),  I64(0x879CBACDBDE8F6A0),
        I64(0x976AD1BCC164A32F),  I64(0xAB21E25E9666D78B),
        I64(0x901063AAE5E5C33C),  I64(0x9818B34448698D90),
        I64(0xE36487AE3E1E8ABB),  I64(0xAFBDF931893BDCB4),
        I64(0x6345A0DC5FBBD519),  I64(0x8628FE269B9465CA),
        I64(0x1E5D01603F9C51EC),  I64(0x4DE44006A15049B7),
        I64(0xBF6C70E5F776CBB1),  I64(0x411218F2EF552BED),
        I64(0xCB0C0708705A36A3),  I64(0xE74D14754F986044),
        I64(0xCD56D9430EA8280E),  I64(0xC12591D7535F5065),
        I64(0xC83223F1720AEF96),  I64(0xC3A0396F7363A51F)
    }
};

