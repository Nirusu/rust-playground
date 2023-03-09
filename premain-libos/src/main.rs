use rcgen::{Certificate, CertificateParams};
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

enum LibOS {
    Gramine,
    Occlum,
    Unknown,
}

fn main() {
    println!("[PreMain] Trying to detect libOS");
    let libos = detect_lib_os();
    match libos {
        LibOS::Gramine => {
            println!("[PreMain] Detected Gramine");
            premain_ex();
        }
        LibOS::Occlum => {
            println!("[PreMain] Detected Occlum");
            todo!("Occlum premain not implemented yet")
        }
        LibOS::Unknown => {
            println!("[PreMain] Unknown libOS");
            premain_ex();
        }
    }
}

fn detect_lib_os() -> LibOS {
    let utsname = nix::sys::utsname::uname().unwrap();

    let sysname = utsname.sysname();
    println!("utsname.sysname: {}", sysname.to_str().unwrap());
    let nodename = utsname.nodename();
    println!("utsname.nodename: {}", nodename.to_str().unwrap());
    let release = utsname.release();
    println!("utsname.release: {}", release.to_str().unwrap());
    let version = utsname.version();
    println!("utsname.version: {}", version.to_str().unwrap());
    let machine = utsname.machine();
    println!("utsname.machine: {}", machine.to_str().unwrap());

    if sysname == "Linux" && release == "3.10.0" && version == "1" && machine == "x86_64" {
        return LibOS::Gramine;
    }

    if sysname == "Occlum" {
        return LibOS::Occlum;
    }

    return LibOS::Unknown;
}

fn premain_ex() {
    println!("[PreMain] Running premain_ex");
    println!("[PreMain] Starting PreMain");
    let coordinator_addr = get_env_with_default("EDG_MARBLE_COORDINATOR_ADDR", "localhost:2001");
    println!("[PreMain] Coordinator address: {}", coordinator_addr);
    let marble_type = env::var("EDG_MARBLE_TYPE").expect("EDG_MARBLE_TYPE not set");
    println!("[PreMain] Marble type: {}", marble_type);
    let marble_dns_names_string = get_env_with_default("EDG_MARBLE_DNS_NAMES", "localhost");
    println!("[PreMain] Marble DNS names: {}", marble_dns_names_string);
    let uuid_file = get_env_with_default("EDG_MARBLE_UUID_FILE", "uuid");
    println!("[PreMain] UUID file: {}", uuid_file);

    let cert = generate_certificate(&marble_dns_names_string);
    println!("{}", cert.serialize_pem().unwrap());
    println!("{}", cert.serialize_private_key_pem());
}

fn get_env_with_default(name: &str, default: &str) -> String {
    return match env::var(name) {
        Ok(val) => val,
        Err(_e) => default.to_string(),
    };
}

fn generate_certificate(marble_dns_names_string: &str) -> Certificate {
    println!("[PreMain] Generating certificate");
    let mut params = CertificateParams::default();

    // Set the common name to "MarbleRun Marble"
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "MarbleRun Marble");
    params.not_before = time::OffsetDateTime::now_utc();
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyAgreement,
    ];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];

    let localhost_v4 = rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    let localhost_v6 = rcgen::SanType::IpAddress(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
    let marble_dns_names = marble_dns_names_string
        .split(",")
        .collect::<Vec<&str>>()
        .iter()
        .map(|s| rcgen::SanType::DnsName(s.to_string()))
        .collect::<Vec<rcgen::SanType>>();

    let mut san_types = vec![localhost_v4, localhost_v6];
    for san_type in marble_dns_names {
        san_types.push(san_type);
    }
    params.subject_alt_names = san_types;
    let cert = rcgen::Certificate::from_params(params).unwrap();

    return cert;
}
