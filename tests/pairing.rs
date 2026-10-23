use rcu::pairing::{normalize, PairError, Pairing, CODE_TTL, MAX_FAILS};
use std::time::Instant;

#[test]
fn generated_code_is_8_crockford_chars() {
    let p = Pairing::new(Instant::now());
    let code = p.current_code().unwrap();
    assert_eq!(code.len(), 8);
    assert!(code
        .chars()
        .all(|c| "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c)));
}

#[test]
fn right_code_works_once() {
    let now = Instant::now();
    let mut p = Pairing::with_code("ABCD1234".into(), now);
    assert_eq!(p.attempt("abcd-1234", now), Ok(()));
    // 소모됨
    assert_eq!(p.attempt("ABCD1234", now), Err(PairError::Locked));
}

#[test]
fn confusable_letters_are_normalized() {
    assert_eq!(normalize("o1Il-5 z"), "01115Z");
}

#[test]
fn five_wrong_attempts_lock_and_discard_code() {
    let now = Instant::now();
    let mut p = Pairing::with_code("ABCD1234".into(), now);
    for _ in 0..MAX_FAILS - 1 {
        assert_eq!(p.attempt("WRONG000", now), Err(PairError::Wrong));
    }
    assert_eq!(p.attempt("WRONG000", now), Err(PairError::Locked));
    // 잠긴 뒤에는 맞는 코드도 안 된다.
    assert_eq!(p.attempt("ABCD1234", now), Err(PairError::Locked));
    assert!(p.current_code().is_none());
}

#[test]
fn expired_code_is_rejected() {
    let now = Instant::now();
    let mut p = Pairing::with_code("ABCD1234".into(), now);
    assert_eq!(
        p.attempt("ABCD1234", now + CODE_TTL),
        Err(PairError::Expired)
    );
}

#[test]
fn refresh_resets_lock() {
    let now = Instant::now();
    let mut p = Pairing::with_code("ABCD1234".into(), now);
    for _ in 0..MAX_FAILS {
        let _ = p.attempt("WRONG000", now);
    }
    let fresh = p.refresh(now);
    assert_eq!(p.attempt(&fresh, now), Ok(()));
}
