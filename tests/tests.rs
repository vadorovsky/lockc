#[test]
fn test_check_bpf_lsm_enabled() {}

#[test]
fn test_hash() {
    assert_eq!(lockc::hash("ayy").unwrap(), 339);
    assert_eq!(lockc::hash("lmao").unwrap(), 425);
}

#[test]
fn test_init_runtimes() {
    let mut skel = lockc::bpf_skel().expect("failed to get the BPF skeleton");

    lockc::init_runtimes(skel.maps_mut().runtimes()).expect("failed to initialize runtimes");
}
