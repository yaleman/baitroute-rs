#[test]
fn test_yaml_roundtrip() -> Result<(), usize> {
    if !std::path::Path::new("baitroute").exists() {
        println!(
            "baitroute directory not found, please clone github.com/utkusen/baitroute locally"
        );
        return Err(1);
    }

    let skippable: Vec<&str> = [
        "circleci-config.yaml",
        "github-workflows-disclosure.yaml",
        "couchbase-buckets-api.yaml",
        "CVE-2024-1210.yaml",
        "CVE-2024-1209.yaml",
        "CVE-2023-0678.yaml",
    ]
    .to_vec();

    for path in ["exposures", "info", "vulnerabilities"] {
        for file in std::fs::read_dir(format!("baitroute/rules/{}/", path)).unwrap() {
            let file = file.unwrap_or_else(|err| panic!("Failed to read {}: {:?}", path, err));
            // load the contents of the file

            if skippable
                .iter()
                .any(|skip| file.path().display().to_string().contains(skip))
            {
                println!("Skipping {}", file.path().display());
                continue;
            }
            println!("Testing {}", file.path().display());

            let contents = std::fs::read_to_string(file.path()).unwrap_or_else(|err| {
                panic!("Failed to read {}: {:?}", file.path().display(), err)
            });
            // parse the contents of the file
            let rules: baitroute_rs::Rules = serde_yml::from_str(&contents).unwrap_or_else(|err| {
                panic!("Failed to deserialize {}: {:?}", file.path().display(), err)
            });

            // serialise to yaml
            let yaml = serde_yml::to_string(&rules).unwrap_or_else(|err| {
                panic!("Failed to serialise {}: {:?}", file.path().display(), err)
            });
            println!("{}", yaml);
            // parse the serialised yaml
            let _rules2: baitroute_rs::Rules =
                std::panic::catch_unwind(|| serde_yml::from_str(&yaml).expect("failed to parse"))
                    .unwrap_or_else(|_| {
                        panic!("Panic occurred while parsing {}", file.path().display())
                    });
        }
    }
    Ok(())
}
