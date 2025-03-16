use std::collections::BTreeSet;

use baitroute_rs::BASE_BAITROUTE_DIR;
use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
struct BeelzebubRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub regex: String,
    pub handler: String,
    // #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub headers: BTreeSet<String>,
    #[serde(rename = "statusCode", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
}

#[derive(Deserialize, Serialize)]
struct BeelzebubConfig {
    pub commands: Vec<BeelzebubRule>,
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub protocol: String,
    pub address: String,
    pub description: String,
}

impl Default for BeelzebubConfig {
    fn default() -> Self {
        Self {
            commands: Vec::new(),
            api_version: "v1".to_string(),
            protocol: "http".to_string(),
            address: ":8080".to_string(),
            description: "Baitroute rules".to_string(),
        }
    }
}

impl BeelzebubConfig {
    pub fn path_to_regex(&self, path: &str) -> String {
        format!("^{}$", path)
    }

    pub fn contains_path(&self, path: &str) -> bool {
        self.commands
            .iter()
            .any(|rule| rule.regex == self.path_to_regex(path))
    }
}

#[derive(Parser, Debug)]
/// Turns a baitroute rules directory into a Beelzebub configuration file
struct CliOpt {
    #[clap(help = "Path to the configuration file")]
    pub config: Option<String>,

    #[clap(short, long, help = "The output filepath")]
    pub output: Option<String>,

    #[clap(short, long, help = "Update the configuration file")]
    pub update: bool,
}

fn main() -> Result<(), usize> {
    let cli = CliOpt::parse();

    // due to some weird bug in the YAML crates, we need to skip these files
    let skippable = [
        "circleci-config.yaml",
        "github-workflows-disclosure.yaml",
        "couchbase-buckets-api.yaml",
        "CVE-2024-1210.yaml",
        "CVE-2024-1209.yaml",
        "CVE-2024-10914.yaml",
        "CVE-2023-0678.yaml",
    ];

    let mut config: BeelzebubConfig = match &cli.config {
        Some(config) => {
            let contents = match std::fs::read_to_string(config) {
                Err(err) => {
                    eprintln!("Failed to read config file {}: {:?}", config, err);
                    return Err(1);
                }
                Ok(val) => val,
            };
            eprintln!("Parsing {}", config);
            match serde_yml::from_str(&contents) {
                Ok(val) => {
                    eprintln!("Finished parsing {}", config);
                    val
                }
                Err(err) => {
                    eprintln!("Failed to deserialize config file {}: {:?}", config, err);
                    return Err(1);
                }
            }
        }
        None => BeelzebubConfig::default(),
    };

    // check if the local dir "baitroute" exists
    if !std::path::Path::new("baitroute").exists() {
        println!(
            "baitroute directory not found, please clone github.com/utkusen/baitroute locally"
        );
        return Err(1);
    }

    for path in ["exposures", "info", "vulnerabilities"] {
        for file in std::fs::read_dir(format!("{}{}", BASE_BAITROUTE_DIR, path)).unwrap() {
            let file = file.unwrap_or_else(|err| panic!("Failed to read {}: {:?}", path, err));
            // load the contents of the file
            if skippable
                .iter()
                .any(|skip| file.path().display().to_string().contains(skip))
            {
                println!("Skipping {}", file.path().display());
                continue;
            }

            let contents = std::fs::read_to_string(file.path()).unwrap_or_else(|err| {
                panic!("Failed to read {}: {:?}", file.path().display(), err)
            });
            // parse the contents of the file
            let rules: baitroute_rs::Rules = serde_yml::from_str(&contents).unwrap_or_else(|err| {
                panic!("Failed to deserialize {}: {:?}", file.path().display(), err)
            });

            for mut rule in rules.into_iter() {
                if rule.filename.is_none() {
                    rule.filename = Some(
                        file.path()
                            .display()
                            .to_string()
                            .replace(BASE_BAITROUTE_DIR, ""),
                    );
                }

                let regex = format!("^{}$", rule.path);

                let headers = match rule.headers.is_empty() {
                    true => BTreeSet::new(),
                    false => rule
                        .headers
                        .into_iter()
                        .map(|(k, v)| format!("{}: {}", k, v))
                        .collect(),
                };

                let beelrule = BeelzebubRule {
                    name: rule.filename,
                    regex,
                    handler: rule.body,
                    headers,
                    status_code: Some(rule.status.get()),
                };
                if config.contains_path(&rule.path) {
                    println!("Duplicate rule: {}", rule.path);
                } else {
                    config.commands.push(beelrule);
                }
            }
        }
    }

    let output = serde_yml::to_string(&config)
        .unwrap_or_else(|err| panic!("Failed to serialize: {:?}", err));

    let output_filename = match (cli.update, cli.output, &cli.config) {
        (true, Some(_), _) => {
            // they've asked for both, nope
            eprintln!("You can't update and output at the same time!");
            return Err(1);
        }
        (true, None, Some(config)) => {
            // they've asked for an update, but no output file
            Some(config.to_owned())
        }
        (true, None, None) => {
            // they've asked for an update, but no config file
            eprintln!("You need to specify a config file to update it!");
            return Err(1);
        }
        (false, Some(output), _) => {
            // they've asked for an output file
            Some(output.clone())
        }
        (false, None, None) => None,
        (false, None, Some(_)) => None,
    };

    let output = format!("---\n{}", output);

    match output_filename {
        Some(output_file) => {
            if let Err(err) = std::fs::write(&output_file, output) {
                {
                    eprintln!("Failed to write to output file {}: {:?}", output_file, err);
                    return Err(1);
                }
            }
        }
        None => {
            println!("{}", output);
        }
    }
    Ok(())
}
