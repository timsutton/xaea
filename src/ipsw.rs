//! The disk images inside an IPSW, named by the role its
//! `BuildManifest.plist` gives each one.

use crate::zip::{self, Entry, ReadAt};
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;

/// One disk image member of an IPSW.
#[derive(Debug, Clone)]
pub struct Image {
    pub entry: Entry,
    /// Short role names (`os`, `system-cryptex`, …), from the manifest.
    pub roles: Vec<String>,
}

impl Image {
    /// Encrypted (an AEA), as opposed to a plain disk image.
    pub fn encrypted(&self) -> bool {
        self.entry.name.ends_with(".aea")
    }
}

pub struct Listing {
    pub product_version: Option<String>,
    pub build: Option<String>,
    pub devices: Vec<String>,
    pub images: Vec<Image>,
}

/// The role a manifest component gives a disk image, in a build identity
/// with this `Variant` and `RestoreBehavior`.
fn role(component: &str, variant: &str, behavior: &str) -> String {
    let update = behavior == "Update" || variant.contains("Upgrade") || variant.contains("Update");
    match component {
        "OS" if variant.contains("Recovery") => "recovery-os".into(),
        "OS" => "os".into(),
        "RestoreRamDisk" if update => "update-ramdisk".into(),
        "RestoreRamDisk" => "restore-ramdisk".into(),
        "Cryptex1,SystemOS" => "system-cryptex".into(),
        "Cryptex1,AppOS" => "app-cryptex".into(),
        "Ap,ExclaveOS" => "exclave-os".into(),
        other => {
            // e.g. `Cryptex1,Foo` → `cryptex1-foo`
            let mut s = String::new();
            for c in other.chars() {
                if c.is_ascii_alphanumeric() {
                    if c.is_ascii_uppercase()
                        && s.chars().last().is_some_and(|p| p.is_ascii_lowercase())
                    {
                        s.push('-');
                    }
                    s.push(c.to_ascii_lowercase());
                } else if !s.ends_with('-') {
                    s.push('-');
                }
            }
            s
        }
    }
}

fn is_disk_image(name: &str) -> bool {
    !name.contains('/') && (name.ends_with(".dmg") || name.ends_with(".dmg.aea"))
}

/// List `src`'s disk images; `entries` is its central directory.
pub fn list(src: &(impl ReadAt + ?Sized), entries: &[Entry]) -> Result<Listing> {
    let mut roles: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut listing = Listing {
        product_version: None,
        build: None,
        devices: Vec::new(),
        images: Vec::new(),
    };
    if let Some(bm) = entries.iter().find(|e| e.name == "BuildManifest.plist") {
        let bytes = zip::read(src, bm, 64 << 20)?;
        let plist = plist::Value::from_reader(std::io::Cursor::new(bytes))
            .context("BuildManifest.plist is not a plist")?;
        let d = plist
            .as_dictionary()
            .context("BuildManifest.plist is not a dictionary")?;
        let s = |k: &str| {
            d.get(k)
                .and_then(plist::Value::as_string)
                .map(str::to_owned)
        };
        listing.product_version = s("ProductVersion");
        listing.build = s("ProductBuildVersion");
        listing.devices = d
            .get("SupportedProductTypes")
            .and_then(plist::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_string().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        for id in d
            .get("BuildIdentities")
            .and_then(plist::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(plist::Value::as_dictionary)
        {
            let info = id.get("Info").and_then(plist::Value::as_dictionary);
            let info_s = |k: &str| {
                info.and_then(|i| i.get(k))
                    .and_then(plist::Value::as_string)
                    .unwrap_or_default()
            };
            let (variant, behavior) = (info_s("Variant"), info_s("RestoreBehavior"));
            let Some(manifest) = id.get("Manifest").and_then(plist::Value::as_dictionary) else {
                continue;
            };
            for (component, v) in manifest {
                let path = v
                    .as_dictionary()
                    .and_then(|c| c.get("Info"))
                    .and_then(plist::Value::as_dictionary)
                    .and_then(|i| i.get("Path"))
                    .and_then(plist::Value::as_string);
                if let Some(path) = path.filter(|p| is_disk_image(p)) {
                    let r = roles.entry(path.to_owned()).or_default();
                    let name = role(component, variant, behavior);
                    if !r.contains(&name) {
                        r.push(name);
                    }
                }
            }
        }
    }
    listing.images = entries
        .iter()
        .filter(|e| is_disk_image(&e.name))
        .map(|e| Image {
            roles: roles.get(&e.name).cloned().unwrap_or_default(),
            entry: e.clone(),
        })
        .collect();
    // The main OS first, then by role, then by name.
    listing.images.sort_by_key(|i| {
        let rank = [
            "os",
            "system-cryptex",
            "app-cryptex",
            "exclave-os",
            "recovery-os",
        ]
        .iter()
        .position(|r| i.roles.iter().any(|x| x == r))
        .unwrap_or(usize::MAX);
        (rank, i.roles.first().cloned(), i.entry.name.clone())
    });
    Ok(listing)
}

/// The image `want` names: a role, a member name, or a member name
/// without its `.dmg.aea` / `.aea` suffix.
pub fn select<'l>(listing: &'l Listing, want: &str) -> Result<&'l Image> {
    let by_name: Vec<_> = listing
        .images
        .iter()
        .filter(|i| {
            let n = &i.entry.name;
            n == want
                || n.strip_suffix(".aea") == Some(want)
                || n.strip_suffix(".dmg.aea") == Some(want)
        })
        .collect();
    if let [one] = by_name[..] {
        return Ok(one);
    }
    let by_role: Vec<_> = listing
        .images
        .iter()
        .filter(|i| i.roles.iter().any(|r| r.eq_ignore_ascii_case(want)))
        .collect();
    match by_role[..] {
        [one] => Ok(one),
        [] => bail!("no disk image in this IPSW is named or has the role `{want}`"),
        _ => bail!(
            "role `{want}` matches several disk images ({}); name one",
            by_role
                .iter()
                .map(|i| i.entry.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::role;

    #[test]
    fn roles_from_manifest_components() {
        let erase = ("Customer Erase Install (IPSW)", "Erase");
        let upgrade = ("Customer Upgrade Install (IPSW)", "Update");
        let recovery = ("Recovery Customer Install", "Erase");
        assert_eq!(role("OS", erase.0, erase.1), "os");
        assert_eq!(role("OS", recovery.0, recovery.1), "recovery-os");
        assert_eq!(role("RestoreRamDisk", erase.0, erase.1), "restore-ramdisk");
        assert_eq!(
            role("RestoreRamDisk", upgrade.0, upgrade.1),
            "update-ramdisk"
        );
        assert_eq!(
            role("Cryptex1,SystemOS", erase.0, erase.1),
            "system-cryptex"
        );
        assert_eq!(role("Ap,ExclaveOS", erase.0, erase.1), "exclave-os");
        assert_eq!(
            role("Cryptex1,FooBar", erase.0, erase.1),
            "cryptex1-foo-bar"
        );
    }
}
