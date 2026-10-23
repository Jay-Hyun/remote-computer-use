//! 페어링 코드: 8자, 5분, 5번 틀리면 잠기고 코드를 버린다.

use rand::Rng;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

pub const MAX_FAILS: u32 = 5;
pub const CODE_TTL: Duration = Duration::from_secs(5 * 60);
/// Crockford base32 (I, L, O, U 제외)
const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairError {
    Wrong,
    Locked,
    Expired,
}

impl PairError {
    pub fn code(self) -> &'static str {
        match self {
            PairError::Wrong => "PAIR_WRONG",
            PairError::Locked => "PAIR_LOCKED",
            PairError::Expired => "PAIR_EXPIRED",
        }
    }
}

#[derive(Debug)]
pub struct Pairing {
    code: Option<String>,
    expires: Instant,
    fails: u32,
}

pub fn generate_code() -> String {
    let mut rng = rand::rngs::OsRng;
    (0..8)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

/// 사람이 입력한 코드를 정규화한다: 대문자, 하이픈·공백 제거, O→0, I/L→1.
pub fn normalize(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect()
}

impl Pairing {
    pub fn new(now: Instant) -> Pairing {
        Pairing::with_code(generate_code(), now)
    }

    pub fn with_code(code: String, now: Instant) -> Pairing {
        Pairing {
            code: Some(code),
            expires: now + CODE_TTL,
            fails: 0,
        }
    }

    /// 새 코드를 만든다. 실패 횟수도 초기화한다.
    pub fn refresh(&mut self, now: Instant) -> String {
        let code = generate_code();
        *self = Pairing::with_code(code.clone(), now);
        code
    }

    pub fn current_code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    /// 성공하면 코드를 소모한다(한 번만 쓸 수 있다).
    pub fn attempt(&mut self, input: &str, now: Instant) -> Result<(), PairError> {
        let Some(code) = self.code.as_ref() else {
            return Err(PairError::Locked);
        };
        if now >= self.expires {
            self.code = None;
            return Err(PairError::Expired);
        }
        let given = normalize(input);
        if bool::from(given.as_bytes().ct_eq(code.as_bytes())) {
            self.code = None;
            return Ok(());
        }
        self.fails += 1;
        if self.fails >= MAX_FAILS {
            self.code = None;
            return Err(PairError::Locked);
        }
        Err(PairError::Wrong)
    }
}
