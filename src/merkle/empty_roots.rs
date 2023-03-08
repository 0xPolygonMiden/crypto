use super::{Felt, RpoDigest, WORD_SIZE, ZERO};
use core::slice;

// EMPTY NODES SUBTREES
// ================================================================================================

/// Contains precomputed roots of empty subtrees in a Merkle rtee of depth 64.
pub struct EmptySubtreeRoots;

impl EmptySubtreeRoots {
    /// Returns a static slice with roots of empty subtrees of a Merkle tree starting at the
    /// specified depth.
    ///
    /// # Panics
    ///
    /// This function will panic if the provided `depth` is greater than `64`.
    pub const fn empty_hashes(depth: u8) -> &'static [RpoDigest] {
        assert!(depth < 65);
        let ptr = &EMPTY_SUBTREES_64[64 - depth as usize] as *const RpoDigest;
        // Safety: this is a static/constant array, so it will never be outlived. If we attempt to
        // use regular slices, this wouldn't be a `const` function, meaning we won't be able to use
        // the returned value for static/constant definitions.
        unsafe { slice::from_raw_parts(ptr, depth as usize + 1) }
    }
}

const EMPTY_SUBTREES_64: [RpoDigest; 65] = [
    RpoDigest::new([
        Felt::new(15321474589252129342),
        Felt::new(17373224439259377994),
        Felt::new(15071539326562317628),
        Felt::new(3312677166725950353),
    ]),
    RpoDigest::new([
        Felt::new(12146678323567200178),
        Felt::new(14288630174929498478),
        Felt::new(13374892366980833045),
        Felt::new(11840636859983936891),
    ]),
    RpoDigest::new([
        Felt::new(15220380953028059006),
        Felt::new(2981707349961006045),
        Felt::new(7409523958661360004),
        Felt::new(2816116826688969892),
    ]),
    RpoDigest::new([
        Felt::new(7829641133220670678),
        Felt::new(6170216088031698405),
        Felt::new(11814483661801576435),
        Felt::new(1762887097744793975),
    ]),
    RpoDigest::new([
        Felt::new(1299421782687082884),
        Felt::new(9938699043036414489),
        Felt::new(10193025806762503939),
        Felt::new(12073246492422971113),
    ]),
    RpoDigest::new([
        Felt::new(3774016405860870757),
        Felt::new(2584714598467121158),
        Felt::new(7418645462301488344),
        Felt::new(1016804897028793820),
    ]),
    RpoDigest::new([
        Felt::new(13238072489118494737),
        Felt::new(6917129315345826393),
        Felt::new(13736362398490889690),
        Felt::new(4929049375601714136),
    ]),
    RpoDigest::new([
        Felt::new(2433738165854950976),
        Felt::new(6710644905925382197),
        Felt::new(10571480102433401045),
        Felt::new(16853295309134271298),
    ]),
    RpoDigest::new([
        Felt::new(3162775558610426184),
        Felt::new(11944004899624546116),
        Felt::new(55767976185223284),
        Felt::new(5892480272697245897),
    ]),
    RpoDigest::new([
        Felt::new(12582634330812132159),
        Felt::new(6886254574119140332),
        Felt::new(4407453795368410417),
        Felt::new(6959805977831121004),
    ]),
    RpoDigest::new([
        Felt::new(16001070406220863863),
        Felt::new(4426773743735082930),
        Felt::new(6860108527212616559),
        Felt::new(3994703491288516722),
    ]),
    RpoDigest::new([
        Felt::new(9755907048710665826),
        Felt::new(13697078808748604851),
        Felt::new(17210321635283113095),
        Felt::new(1203394006092675979),
    ]),
    RpoDigest::new([
        Felt::new(3332855817731547893),
        Felt::new(1068928372599561798),
        Felt::new(17119375903210334455),
        Felt::new(8148601736624954416),
    ]),
    RpoDigest::new([
        Felt::new(17265634841675424144),
        Felt::new(18322832739735580203),
        Felt::new(17896992777163902308),
        Felt::new(6189383326950297131),
    ]),
    RpoDigest::new([
        Felt::new(9329637674239983584),
        Felt::new(2512861030579248721),
        Felt::new(10833150484884266896),
        Felt::new(7470498642428983444),
    ]),
    RpoDigest::new([
        Felt::new(3611140194800558886),
        Felt::new(17185933650781587767),
        Felt::new(7835232399818923215),
        Felt::new(7974155618002781326),
    ]),
    RpoDigest::new([
        Felt::new(17483286922353768131),
        Felt::new(353378057542380712),
        Felt::new(1935183237414585408),
        Felt::new(4820339620987989650),
    ]),
    RpoDigest::new([
        Felt::new(16172462385444809646),
        Felt::new(3268597753131435459),
        Felt::new(3481491333654579291),
        Felt::new(16487779176137683725),
    ]),
    RpoDigest::new([
        Felt::new(16595012576192613315),
        Felt::new(16028552537812484518),
        Felt::new(13016887826405546773),
        Felt::new(14649690775021494057),
    ]),
    RpoDigest::new([
        Felt::new(11300236651178143890),
        Felt::new(15307634289168527196),
        Felt::new(2834866419963148279),
        Felt::new(7512874625395280090),
    ]),
    RpoDigest::new([
        Felt::new(1148273481270068529),
        Felt::new(7411276436636897120),
        Felt::new(14325955409748352141),
        Felt::new(15577038614919538356),
    ]),
    RpoDigest::new([
        Felt::new(13911627859049081064),
        Felt::new(13298542751859672529),
        Felt::new(18341014824837028242),
        Felt::new(5587966507704160144),
    ]),
    RpoDigest::new([
        Felt::new(10957185917743597702),
        Felt::new(15815185767119166433),
        Felt::new(17883994521792846784),
        Felt::new(15958104556930886663),
    ]),
    RpoDigest::new([
        Felt::new(13148367538964199489),
        Felt::new(7372139436485928380),
        Felt::new(13408383191801051600),
        Felt::new(2114382634401123096),
    ]),
    RpoDigest::new([
        Felt::new(14448157482521530067),
        Felt::new(17865161921504959156),
        Felt::new(10319385198642448897),
        Felt::new(364163501511998552),
    ]),
    RpoDigest::new([
        Felt::new(9722640569118951143),
        Felt::new(16371655672847089887),
        Felt::new(12379452272155069993),
        Felt::new(11605969747977185617),
    ]),
    RpoDigest::new([
        Felt::new(2782512273606877924),
        Felt::new(3656296563981095117),
        Felt::new(5947388149010135441),
        Felt::new(1678144343036748885),
    ]),
    RpoDigest::new([
        Felt::new(10347491038074052866),
        Felt::new(11061756013655443653),
        Felt::new(8901792852813329415),
        Felt::new(10002477867799577447),
    ]),
    RpoDigest::new([
        Felt::new(16688151588649906570),
        Felt::new(12937054427339650762),
        Felt::new(2125115528195796454),
        Felt::new(4796610823085621719),
    ]),
    RpoDigest::new([
        Felt::new(3032620037225059051),
        Felt::new(13522881885116127385),
        Felt::new(6010511038055304264),
        Felt::new(8199256447383686121),
    ]),
    RpoDigest::new([
        Felt::new(11250302734399433639),
        Felt::new(4970037623163209776),
        Felt::new(15776613712371118341),
        Felt::new(5554382612311754837),
    ]),
    RpoDigest::new([
        Felt::new(5116523511540088640),
        Felt::new(12381059245485642368),
        Felt::new(2176361879916914688),
        Felt::new(11209293198464735683),
    ]),
    RpoDigest::new([
        Felt::new(11677748883385181208),
        Felt::new(15891398395707500576),
        Felt::new(3790704659934033620),
        Felt::new(2126099371106695189),
    ]),
    RpoDigest::new([
        Felt::new(13948603355603496603),
        Felt::new(15902438544472945077),
        Felt::new(1969361494026622497),
        Felt::new(17326911676634210553),
    ]),
    RpoDigest::new([
        Felt::new(16081431322775411514),
        Felt::new(13201312030265587002),
        Felt::new(18283434127959076535),
        Felt::new(9889802180847551599),
    ]),
    RpoDigest::new([
        Felt::new(8490051641633132830),
        Felt::new(11985660456681176415),
        Felt::new(12193381039977027251),
        Felt::new(17563185381678568385),
    ]),
    RpoDigest::new([
        Felt::new(3870617340693651786),
        Felt::new(2748490321246408799),
        Felt::new(8501743976565218963),
        Felt::new(1660720190266083389),
    ]),
    RpoDigest::new([
        Felt::new(2121119282758520982),
        Felt::new(9042267662074029772),
        Felt::new(15431993929052434204),
        Felt::new(10659345458998811701),
    ]),
    RpoDigest::new([
        Felt::new(15206763021853065070),
        Felt::new(15268692497656424421),
        Felt::new(13335448435922172445),
        Felt::new(3421340628484408379),
    ]),
    RpoDigest::new([
        Felt::new(5175159910654039438),
        Felt::new(10258564296733764665),
        Felt::new(235961379704359454),
        Felt::new(18007006485615491006),
    ]),
    RpoDigest::new([
        Felt::new(9455184082727641653),
        Felt::new(6634498452861935579),
        Felt::new(18189776179964984407),
        Felt::new(3546641211720870472),
    ]),
    RpoDigest::new([
        Felt::new(2566088177506289568),
        Felt::new(7785941571143323572),
        Felt::new(13948908169667863201),
        Felt::new(8557252288425473395),
    ]),
    RpoDigest::new([
        Felt::new(8801845050152766755),
        Felt::new(514652983374395586),
        Felt::new(13975919271481418443),
        Felt::new(17480955484347349170),
    ]),
    RpoDigest::new([
        Felt::new(7078477424334594989),
        Felt::new(9975053207879493059),
        Felt::new(5220656123503260168),
        Felt::new(13795787984352794188),
    ]),
    RpoDigest::new([
        Felt::new(1478357986561897612),
        Felt::new(3963701567400985039),
        Felt::new(10269836564499521403),
        Felt::new(11874873630603798755),
    ]),
    RpoDigest::new([
        Felt::new(936391814816943993),
        Felt::new(6085855616346025677),
        Felt::new(5782721339195502211),
        Felt::new(10409491632083436908),
    ]),
    RpoDigest::new([
        Felt::new(11138475264090866271),
        Felt::new(17799626597540451271),
        Felt::new(17968790388406362807),
        Felt::new(9539434947296310791),
    ]),
    RpoDigest::new([
        Felt::new(13051724588530357940),
        Felt::new(8058102530250142518),
        Felt::new(1861782711432586670),
        Felt::new(2928050228215055187),
    ]),
    RpoDigest::new([
        Felt::new(10650694022550988030),
        Felt::new(5634734408638476525),
        Felt::new(9233115969432897632),
        Felt::new(1437907447409278328),
    ]),
    RpoDigest::new([
        Felt::new(9720135276484706819),
        Felt::new(9350120041401976641),
        Felt::new(1348777594376050933),
        Felt::new(13138246165242825648),
    ]),
    RpoDigest::new([
        Felt::new(10866643979409126085),
        Felt::new(13790633638103642042),
        Felt::new(6374461622011119670),
        Felt::new(5702679962735491362),
    ]),
    RpoDigest::new([
        Felt::new(5257277882444261955),
        Felt::new(8511211402794551302),
        Felt::new(3294838877645533839),
        Felt::new(4084864647832858048),
    ]),
    RpoDigest::new([
        Felt::new(7948776578097466250),
        Felt::new(8630046431048474853),
        Felt::new(11549811661672434609),
        Felt::new(14329713552208961509),
    ]),
    RpoDigest::new([
        Felt::new(734617692582477804),
        Felt::new(11871516935077749937),
        Felt::new(12085935336918533812),
        Felt::new(11028098016323141988),
    ]),
    RpoDigest::new([
        Felt::new(10937083382606895486),
        Felt::new(12203867463821771187),
        Felt::new(13369919265612777227),
        Felt::new(2521482611471096233),
    ]),
    RpoDigest::new([
        Felt::new(1242037330294600071),
        Felt::new(8643213198640797337),
        Felt::new(14112360612081236212),
        Felt::new(11296904697431650998),
    ]),
    RpoDigest::new([
        Felt::new(11958494925108187724),
        Felt::new(6059642826232274823),
        Felt::new(1563918267677757605),
        Felt::new(266509853282035592),
    ]),
    RpoDigest::new([
        Felt::new(17288335252189973373),
        Felt::new(3243363076395469373),
        Felt::new(8880515798614590986),
        Felt::new(10260780639137628077),
    ]),
    RpoDigest::new([
        Felt::new(1839714959437284152),
        Felt::new(12088193186987715006),
        Felt::new(10200898335013164008),
        Felt::new(12768529781145127245),
    ]),
    RpoDigest::new([
        Felt::new(1537615626967151439),
        Felt::new(11731506816677487155),
        Felt::new(4748463589169553420),
        Felt::new(17495851576537541106),
    ]),
    RpoDigest::new([
        Felt::new(957733314860117562),
        Felt::new(15623410588944187169),
        Felt::new(4321611031548662227),
        Felt::new(12856104259650439278),
    ]),
    RpoDigest::new([
        Felt::new(14827447693720375746),
        Felt::new(17296925942589213350),
        Felt::new(13524332314559504765),
        Felt::new(15663886706087995199),
    ]),
    RpoDigest::new([
        Felt::new(18185978518863914335),
        Felt::new(936586966360019113),
        Felt::new(497299419609993926),
        Felt::new(1977881506773614749),
    ]),
    RpoDigest::new([
        Felt::new(8635338869442206704),
        Felt::new(11671305615285950885),
        Felt::new(15253023094703789604),
        Felt::new(7398108415970215319),
    ]),
    RpoDigest::new([ZERO; WORD_SIZE]),
];

#[test]
fn all_depths_opens_to_zero() {
    use super::Rpo256;

    for depth in 1..=64 {
        // fetch the subtrees and reverse it so the path is leaf -> root
        let mut subtree = EmptySubtreeRoots::empty_hashes(depth).to_vec();
        subtree.reverse();

        // the length of the subtrees set must be equal to depth + 1 as we also
        // include the root
        assert_eq!(depth as usize + 1, subtree.len());

        // assert the opening is zero
        let initial = RpoDigest::new([ZERO; WORD_SIZE]);
        assert_eq!(initial, subtree.remove(0));

        // compute every node of the path manually and compare with the output
        subtree
            .into_iter()
            .scan(initial, |state, x| {
                *state = Rpo256::merge(&[*state; 2]);
                Some((x, *state))
            })
            .for_each(|(x, computed)| assert_eq!(x, computed));
    }
}

#[test]
fn arbitrary_inputs_will_generate_sound_slices() {
    let min = &EMPTY_SUBTREES_64[0] as *const RpoDigest;
    let max = unsafe { min.add(64) };
    for depth in 0..=64 {
        let subtree = EmptySubtreeRoots::empty_hashes(depth);
        let first = &subtree[0] as *const RpoDigest;
        let last = &subtree[depth as usize] as *const RpoDigest;
        assert!(min <= first && first <= max);
        assert!(min <= last && last <= max);
    }
}
