use rcu::policy::windows_name_unsafe;

#[test]
fn dangerous_windows_names_are_flagged() {
    for bad in [
        "secret.txt:stream",
        "file.txt::$DATA",
        "name.",
        "name ",
        "CON",
        "con",
        "NUL.txt",
        "aux.tar.gz",
        "COM1",
        "lpt9.log",
        "CONIN$",
        "PROGRA~1",
        "x~2.txt",
        "a<b",
        "a|b",
        "what?",
        "star*",
        "tab\there",
    ] {
        assert!(windows_name_unsafe(bad), "{bad:?} should be unsafe");
    }
}

#[test]
fn ordinary_names_pass() {
    for ok in [
        "notes.txt",
        "README",
        "my file (1).md",
        "COM0", // COM0/LPT0 are not reserved devices
        "console.log",
        "connect.rs",
        "tilde~name.txt",
        "한글.txt",
        ".gitignore",
    ] {
        assert!(!windows_name_unsafe(ok), "{ok:?} should be fine");
    }
}
