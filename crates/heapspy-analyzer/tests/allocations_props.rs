//! Property test for the address join: random sample ranges and sorted
//! addresses, checked against a brute-force "latest covering range".

use heapspy_analyzer::allocations::{latest_covering, NO_LINK};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn latest_covering_matches_brute_force(
        mut addrs in prop::collection::vec(0u64..400, 0..60),
        ranges in prop::collection::vec((0u64..400, 0u64..120), 0..40),
    ) {
        addrs.sort_unstable();
        let ranges: Vec<(u64, u64)> = ranges.iter().map(|&(s, n)| (s, s + n)).collect();
        let got = latest_covering(addrs.iter().copied(), &ranges).unwrap();
        for (k, &a) in addrs.iter().enumerate() {
            let want = ranges
                .iter()
                .rposition(|&(s, e)| s <= a && a < e)
                .map_or(NO_LINK, |j| j as u32);
            prop_assert_eq!(got[k], want, "address {}", a);
        }
    }
}
