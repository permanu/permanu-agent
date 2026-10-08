use super::*;
use std::cell::Cell;
use std::rc::Rc;
const FIXTURE: &[u8] =
    include_bytes!("../../tests/vectors/compose-release-v1/structural-only.fake.json");
fn now() -> i64 {
    serde_json::from_slice::<Value>(FIXTURE).unwrap()["attestation"]["issued_at"]
        .as_i64()
        .unwrap()
        + 1
}
struct Authority {
    revoked: Rc<Cell<bool>>,
    calls: Rc<Cell<u32>>,
}
impl AdmissionVerifier for Authority {
    fn verify(&self, envelope: &Value, _: i64) -> Result<(), Error> {
        self.calls.set(self.calls.get() + 1);
        let expected: Value = serde_json::from_slice(FIXTURE).unwrap();
        if self.revoked.get() || *envelope != expected {
            Err(Error::Authority)
        } else {
            Ok(())
        }
    }
}
struct Transport {
    calls: Rc<Cell<u32>>,
    wrong: bool,
}
impl FixtureTransport for Transport {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
        self.calls.set(self.calls.get() + 1);
        let v: Value = serde_json::from_slice(request).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["capability"], CAPABILITY);
        assert_eq!(v["op"], "compose.release.fixture");
        assert_eq!(v.as_object().unwrap().len(), 4);
        let e = &v["envelope"];
        Ok(serde_json::to_vec(&json!({"version":1,"capability":CAPABILITY,"state":if self.wrong{"deployed"}else{"fixture_validated"},"release_digest":schema::digest(b"permanu-compose-release-v1\n",&e["release"]).unwrap(),"application_id":e["release"]["application_id"],"release_id":e["release"]["release_id"]})).unwrap())
    }
}
fn bridge(
    wrong: bool,
) -> (
    Bridge<Authority, Transport>,
    Rc<Cell<bool>>,
    Rc<Cell<u32>>,
    Rc<Cell<u32>>,
) {
    let revoked = Rc::new(Cell::new(false));
    let verifies = Rc::new(Cell::new(0));
    let calls = Rc::new(Cell::new(0));
    let b = Boundary::default()
        .negotiate(Some(CAPABILITY), Some(CAPABILITY))
        .unwrap()
        .bind(
            Authority {
                revoked: revoked.clone(),
                calls: verifies.clone(),
            },
            Transport {
                calls: calls.clone(),
                wrong,
            },
        );
    (b, revoked, verifies, calls)
}
#[test]
fn default_and_mismatched_capability_rejected() {
    for (a, r) in [
        (None, None),
        (Some(CAPABILITY), None),
        (Some("deploy"), Some(CAPABILITY)),
    ] {
        assert!(Boundary::default().negotiate(a, r).is_err())
    }
    let b = Boundary::default().bind(
        Authority {
            revoked: Rc::new(Cell::new(false)),
            calls: Rc::new(Cell::new(0)),
        },
        Transport {
            calls: Rc::new(Cell::new(0)),
            wrong: false,
        },
    );
    assert!(matches!(b.prepare(FIXTURE, now()), Err(Error::Disabled)));
}
#[test]
fn fixture_round_trip_revalidates_same_authority() {
    let (b, _, verifies, calls) = bridge(false);
    let prepared = b.prepare(FIXTURE, now()).unwrap();
    let receipt = b.dispatch(&prepared, now()).unwrap();
    assert_eq!(receipt.state, "fixture_validated");
    assert_eq!(verifies.get(), 2);
    assert_eq!(calls.get(), 1);
}
#[test]
fn revocation_and_expiry_before_dispatch_stop_transport() {
    let (b, revoked, _, calls) = bridge(false);
    let prepared = b.prepare(FIXTURE, now()).unwrap();
    revoked.set(true);
    assert!(matches!(
        b.dispatch(&prepared, now()),
        Err(Error::Authority)
    ));
    assert_eq!(calls.get(), 0);
    revoked.set(false);
    assert!(b.dispatch(&prepared, i64::MAX).is_err());
    assert_eq!(calls.get(), 0);
}
#[test]
fn transport_cannot_claim_deployment() {
    let (b, _, _, _) = bridge(true);
    let prepared = b.prepare(FIXTURE, now()).unwrap();
    assert!(matches!(b.dispatch(&prepared, now()), Err(Error::Binding)));
}
#[test]
fn strict_shape_and_bindings_fail_before_authority() {
    let (b, _, verifies, calls) = bridge(false);
    let raw = std::str::from_utf8(FIXTURE).unwrap();
    for bad in [
        raw.replace("\"version\": 1", "\"Version\": 1"),
        raw.replace("\"version\": 1", "\"version\": 1,\"version\": 1"),
        format!("{raw}{{}}"),
        raw.replace("\"migrations\": \"none\"", "\"migrations\": \"run\""),
        raw.replace("\"action\": \"compose.release\"", "\"action\": \"deploy\""),
        raw.replace("\"root\": \"/srv/fake\"", "\"root\": \"/srv/../fake\""),
        String::from("{\"plan\":{},\"signatures\":[]}"),
        " ".repeat(65_537),
    ] {
        assert!(b.prepare(bad.as_bytes(), now()).is_err());
    }
    assert_eq!(verifies.get(), 0);
    assert_eq!(calls.get(), 0);
}
#[test]
fn fake_signatures_are_not_an_authority_bypass() {
    let (b, revoked, verifies, calls) = bridge(false);
    revoked.set(true);
    assert!(matches!(b.prepare(FIXTURE, now()), Err(Error::Authority)));
    assert_eq!(verifies.get(), 1);
    assert_eq!(calls.get(), 0);
}
