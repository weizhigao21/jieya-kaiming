use std::path::Path;

use jieya_core::detect::{volume_group_total, volume_info};
use jieya_core::output::{archive_dir_name, sanitize_component, unique_path};

#[test]
fn dir_name_strips_archive_and_volume_suffixes() {
    assert_eq!(archive_dir_name(Path::new("pack.zip")), "pack");
    assert_eq!(archive_dir_name(Path::new("pack.tar.gz")), "pack");
    assert_eq!(archive_dir_name(Path::new("pack.7z.001")), "pack");
    assert_eq!(archive_dir_name(Path::new("pack.part01.rar")), "pack");
    assert_eq!(archive_dir_name(Path::new("pack.zip.002")), "pack");
}

#[test]
fn dir_name_strips_fake_extension() {
    // 伪装成 .dat 的包：目录名不能把假后缀带进去
    assert_eq!(archive_dir_name(Path::new("伪装包.dat")), "伪装包");
    assert_eq!(archive_dir_name(Path::new("RJ01116988")), "RJ01116988");
}

#[test]
fn dir_name_never_escapes_with_dotdot() {
    // "...zip" 的 stem 正好是 ".."，绝不能拼成源目录本身
    assert_eq!(archive_dir_name(Path::new("...zip")), "output");
}

#[test]
fn sanitize_rejects_reserved_and_drive() {
    assert_eq!(sanitize_component(".."), "output");
    assert_eq!(sanitize_component("con"), "output");
    assert_eq!(sanitize_component("C:"), "output");
    assert_eq!(sanitize_component("a:b*c?"), "a_b_c_");
}

#[test]
fn volume_patterns() {
    assert_eq!(
        volume_info(Path::new("a.part02.rar")),
        Some(("a.rar".to_string(), 2))
    );
    assert_eq!(
        volume_info(Path::new("a.7z.003")),
        Some(("a.7z".to_string(), 3))
    );
    assert_eq!(volume_info(Path::new("a.zip")), None);
    assert_eq!(volume_info(Path::new("a.partx.rar")), None);
}

#[test]
fn volume_group_total_counts_siblings() {
    let dir = std::env::temp_dir().join(format!("jk_vol_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("v.part01.rar"), b"0123456789").unwrap();
    std::fs::write(dir.join("v.part02.rar"), b"01234").unwrap();
    let (total, count) = volume_group_total(&dir.join("v.part01.rar"));
    assert_eq!(count, 2);
    assert_eq!(total, 15);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unique_path_inserts_counter_before_extension() {
    let dir = std::env::temp_dir().join(format!("jk_unique_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("data.txt"), b"x").unwrap();
    let cand = unique_path(&dir.join("data.txt"));
    assert_eq!(cand.file_name().unwrap(), "data~2.txt");
    let _ = std::fs::remove_dir_all(&dir);
}
