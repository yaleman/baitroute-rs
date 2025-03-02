use std::{collections::BTreeMap, num::NonZero};

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct Rule {
    pub method: String,
    pub path: String,
    pub status: NonZero<u16>,
    pub content_type: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Rules(pub Vec<Rule>);

impl IntoIterator for Rules {
    type Item = Rule;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
