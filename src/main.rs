fn main() {
    // check if the local dir "baitroute" exists
    if !std::path::Path::new("baitroute").exists() {
        println!(
            "baitroute directory not found, please clone github.com/utkusen/baitroute locally"
        );
        return;
    }

    for path in ["exposures", "info", "vulnerabilities"] {
        for file in std::fs::read_dir(format!("baitroute/rules/{}/", path)).unwrap() {
            let file = file.unwrap_or_else(|err| panic!("Failed to read {}: {:?}", path, err));
            // load the contents of the file
            let contents = std::fs::read_to_string(file.path()).unwrap_or_else(|err| {
                panic!("Failed to read {}: {:?}", file.path().display(), err)
            });
            // parse the contents of the file
            let _rule: baitroute_rs::Rules = serde_yml::from_str(&contents).unwrap_or_else(|err| {
                panic!("Failed to deserialize {}: {:?}", file.path().display(), err)
            });

            println!("{} OK", file.path().display());
        }
    }
}
