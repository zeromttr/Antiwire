use std::io::Read;
use std::path::Path;

use flate2::read::MultiGzDecoder;

use crate::error::DownloadError;

/// Decompresses a gzip file at `src_path` into `dest_path`, aborting once the
/// decompressed output exceeds `max_bytes`. This cap is independent of any
/// cap applied to the compressed download and exists specifically to bound
/// decompression-bomb style inputs, which a compressed-size limit alone
/// cannot catch.
///
/// Writes are committed atomically via [`atomic_write_file::AtomicWriteFile`].
/// Synchronous — call from a blocking context (e.g. `spawn_blocking`).
///
/// # Errors
///
/// Returns [`DownloadError::Io`] if `src_path` cannot be read or is not valid
/// gzip data, and [`DownloadError::SizeLimitExceeded`] if the decompressed
/// output exceeds `max_bytes`.
pub fn gunzip_file(src_path: &Path, dest_path: &Path, max_bytes: u64) -> Result<(), DownloadError> {
    let source = std::fs::File::open(src_path)?;
    let mut decoder = MultiGzDecoder::new(source);
    let mut writer = atomic_write_file::AtomicWriteFile::open(dest_path)?;

    // Bound decompression bombs: copy at most max_bytes+1 decompressed bytes
    // and fail if the limit is exceeded. This avoids a manual read loop
    // and centralises the size check.
    let limit = max_bytes.saturating_add(1);
    let mut limited = (&mut decoder).take(limit);
    let copied = std::io::copy(&mut limited, &mut writer)?;
    if copied > max_bytes {
        return Err(DownloadError::SizeLimitExceeded(max_bytes));
    }

    writer.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::gunzip_file;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn write_gz(dir: &std::path::Path, name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        let file = std::fs::File::create(&path).expect("create gz");
        let mut encoder = GzEncoder::new(file, Compression::default());
        encoder.write_all(contents).expect("write gz contents");
        encoder.finish().expect("finish gz");
        path
    }

    #[test]
    fn gunzip_file_decompresses_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let contents = b"hello geoip world".repeat(100);
        let src = write_gz(dir.path(), "in.gz", &contents);
        let dest = dir.path().join("out.bin");

        gunzip_file(&src, &dest, contents.len() as u64).expect("gunzip");

        let decompressed = std::fs::read(&dest).expect("read output");
        assert_eq!(decompressed, contents);
    }

    #[test]
    fn gunzip_file_aborts_when_decompressed_size_exceeds_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let contents = vec![b'x'; 10_000];
        let src = write_gz(dir.path(), "big.gz", &contents);
        let dest = dir.path().join("out.bin");

        let error = gunzip_file(&src, &dest, 100).expect_err("size limit");
        assert!(matches!(
            error,
            crate::DownloadError::SizeLimitExceeded(100)
        ));
        assert!(
            !dest.exists(),
            "destination file must not exist when gunzip aborts"
        );
    }
}
